import angr
import sys
from log import *
from io import StringIO
import re
import pyvex.stmt as ps
import pyvex.expr as pe
import stmt
from env import Environment, Arg2RegNum
from inspect_info import InspectInfo, Effect
from diff_parser import Patterns
from symbol_value import WildCardSymbol
import time
import lief # type: ignore
from settings import *
from refinement import refine_sig, rebuild_effects, effect_to_node, single_refine
from copy import deepcopy
import dominator_builder


class FunctionNotFound(Exception):
    pass


logger = get_logger(__name__)
logger.setLevel(INFO)
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)
ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

sys.setrecursionlimit(10000)


def hexl(l):
    return [hex(x) for x in l]


class State:
    def __init__(self, node: angr.knowledge_plugins.cfg.cfg_node.CFGNode, env: Environment) -> None:
        self.node = node
        self.env = env
        self.addrs = []  # addrs that travel
        self.inspect = {}
        self.inspect_patterns = {}

    def fork(self) -> "State":
        state = State(self.node, self.env.fork())
        state.addrs = self.addrs.copy()
        state.inspect = self.inspect.copy()
        state.inspect_patterns = self.inspect_patterns
        return state

    def __str__(self) -> str:
        return f"State({hex(self.node.addr)})"

    def __repr__(self) -> str:
        return self.__str__()


class Simulator:
    def __init__(self, proj: angr.Project) -> None:
        self.proj = proj
        self.from_to = []

    def _init_function(self, funcname: str):
        symbol = self.proj.loader.find_symbol(funcname)

        if symbol is None:
            raise FunctionNotFound(
                f"symbol {funcname} not found in binary {self.proj}")
        self.funcname = funcname
        cfg = self.proj.analyses.CFGFast(
            regions=[(symbol.rebased_addr, symbol.rebased_addr + symbol.size)], normalize=True)
        function = None
        for func in cfg.functions:
            if cfg.functions[func].name == funcname:
                function = cfg.functions[func]
                break
        assert function is not None
        self.graph = cfg.graph
        self.cfg = cfg
        self.dom_tree, self.super_node = dominator_builder.build_dominator_tree(cfg, funcname)
        # print(f"self.parent_info: {self.parent_info}")
        dominator_builder.print_dom_tree(self.dom_tree, symbol.rebased_addr, labels=None)
        self.function = function
        self._init_map()
    # def _init_function(self, funcname: str):
    #     symbol = self.proj.loader.find_symbol(funcname)
    #     if symbol is None:
    #         if self.symbol is not None:
    #             symbol = self.symbol
    #         else: 
    #             raise FunctionNotFound(
    #                 f"symbol {funcname} not found in binary {self.proj}")
    #     self.funcname = funcname
    #     # print(f"symbol.size: {symbol.size}")
        
    #     cfg = self.proj.analyses.CFGFast(
    #         regions=[(symbol.rebased_addr, symbol.rebased_addr + symbol.size)],
    #         normalize=True,
    #         force_complete_scan=True,
    #         force_smart_scan=False
    #     )
        
    #     function = None

    #     for func in cfg.functions:
    #         if cfg.functions[func].name == 'sub_400000':
    #             cfg.functions[func].name = funcname
    #             function = cfg.functions[func]
    #             break
    #         if cfg.functions[func].name == funcname:
    #             function = cfg.functions[func]
    #             break
    #     # print(f"function: {function}")
    #     # assert function is not None
    #     if function is None:
    #         logger.error(f"function {funcname} not found in binary {self.proj}")
    #         raise FunctionNotFound(
    #             f"function {funcname} not found in binary {self.proj}")
        
    #     self.graph = cfg.graph

    #     self.cfg = cfg
    #     self.function = function
    #     self._init_map()

    def _init_map(self):
        # print("in _init_map")
        self.node2IR: dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode,
                           list[stmt.Statement]] = {}
        self.addr2IR = {}
        addr = None
        for block in self.function.blocks:
            # logger.info(f"block.vex: {block.vex}")
            for statement in block.vex.statements:
                # print(f"statement: {statement}")
                # exit(0)
                if isinstance(statement, ps.IMark):
                    addr = statement.addr
                stmtwrapper = stmt.Statement.construct(statement)
                if addr not in self.addr2IR:
                    self.addr2IR[addr] = []
                self.addr2IR[addr].append(stmtwrapper)

        for node in self.graph.nodes:
            self.node2IR[node] = []
            addrs = node.instruction_addrs
            for addr in addrs:
                if addr not in self.addr2IR:
                    continue
                    assert False, f"addr {hex(addr)} not in addr2IR"
                self.node2IR[node].extend(self.addr2IR[addr])

        self.IR2addr = {}
        for addr in self.addr2IR.keys():
            IRs = self.addr2IR[addr]
            for IR in IRs:
                self.IR2addr[IR] = addr

        self.addr2Node = {}
        for node in self.cfg.nodes():
            self.addr2Node[node.addr] = node
    # def _init_map(self):
    #     # print("in _init_map")
    #     self.node2IR: dict[angr.knowledge_plugins.cfg.cfg_node.CFGNode,
    #                        list[stmt.Statement]] = {}
    #     self.addr2IR = {}
    #     addr = None
    #     for block in self.function.blocks:
    #         # logger.info(f"block.vex: {block.vex}")
    #         for statement in block.vex.statements:
    #             # print(f"statement: {statement}")
    #             # exit(0)
    #             if isinstance(statement, ps.IMark):
    #                 addr = statement.addr
    #             stmtwrapper = stmt.Statement.construct(statement)
    #             if addr not in self.addr2IR:
    #                 self.addr2IR[addr] = []
    #             self.addr2IR[addr].append(stmtwrapper)

    #     for node in self.graph.nodes:
    #         self.node2IR[node] = []
    #         addrs = node.instruction_addrs
    #         for addr in addrs:
    #             if addr not in self.addr2IR:
    #                 continue
    #                 assert False, f"addr {hex(addr)} not in addr2IR"
    #             self.node2IR[node].extend(self.addr2IR[addr])

        self.IR2addr = {}
        for addr in self.addr2IR.keys():
            IRs = self.addr2IR[addr]
            for IR in IRs:
                self.IR2addr[IR] = addr

        self.addr2Node = {}
        for node in self.cfg.nodes():
            self.addr2Node[node.addr] = node

    def _reachable_set(self, addrs: set[int]) -> set:
        endnodes = []
        for addr in addrs:
            if addr not in self.addr2Node:
                continue
            endnodes.append(self.addr2Node[addr])

        predecessors = {}
        for node in self.cfg.nodes():
            predecessors[node] = []

        for node in self.cfg.nodes():
            for succ, _ in node.successors_and_jumpkinds(False):
                predecessors[succ].append(node)

        queue = list(endnodes)
        visit = set()
        while len(queue) > 0:
            node = queue.pop()
            if node.addr in visit:
                continue
            visit.add(node.addr)
            queue.extend(predecessors[node])
        # print(visit)
        return visit

    # def _reduce_addresses_by_basicblock(self, address: dict|list) -> tuple[set[int], list[dict]]:
    #     # print("in _reduce_addresses_by_basicblock")
    #     l = list(self.function.blocks)
    #     result = set()
    #     basic = []
    #     if isinstance(address, list):
    #         # address는 list일 수 있음
    #         for addr in address:
    #             for block in l:
    #                 if addr in block.instruction_addrs:
    #                     result.add(block.addr)
    #                     basic.append({"parent": addr, "children": [], "parent_addrs": {block.addr}, "children_addrs": set()})
    #                     break
    #         return result, basic
    #     else:
    #         for parent, children in address.items():
    #             # parent가 tuple일 수 있음
    #             one_item = {"parent": parent, "children": children, "parent_addrs": set(), "children_addrs": set()}           
    #             if isinstance(parent, tuple):
    #                 bb_parent = set(addr for addr in parent)
    #             else:
    #                 bb_parent = {parent}
    #             for addr in bb_parent:
    #                 for block in l:
    #                     if addr in block.instruction_addrs:
    #                         result.add(block.addr)
    #                         one_item["parent_addrs"].add(block.addr)
    #                         break
                
    #             for addr in children:
    #                 for block in l:
    #                     if addr in block.instruction_addrs:
    #                         result.add(block.addr)
    #                         one_item["children_addrs"].add(block.addr)
    #                         break
    #             basic.append(one_item)
    #         # for addr in address:
    #         #     for block in l:
    #         #         if addr in block.instruction_addrs:
    #         #             result.add(block.addr)
    #         #             break
    #         return result, basic

    def _reduce_addresses_by_basicblock(self, address: list[int]) -> set[int]:
        l = list(self.function.blocks)
        result = set()
        for addr in address:
            for block in l:
                if addr in block.instruction_addrs:
                    result.add(block.addr)
                    break
        return result

    # def generate_forall_bb(self, funcname: str, dic) -> dict:
    #     # print("in generate_forall_bb")
    #     try: 
    #         self._init_function(funcname)
    #     except FunctionNotFound:
    #         raise FunctionNotFound(f"function {funcname} not found in binary {self.proj}")
    #     all_addrs = []
    #     collect = {}
    #     for block in self.function.blocks:
    #         all_addrs.extend(block.instruction_addrs)
    #     # all_addrs는 int 리스트이므로 별도 처리 불필요
    #     self.inspect_addrs = all_addrs
    #     start_node = self.cfg.get_any_node(self.function.addr)
    #     init_state = State(start_node, Environment())
    #     reduce, info = self._reduce_addresses_by_basicblock(all_addrs)
    #     reduce_addr = set(reduce)
    #     # based on basic block inspect
    #     init_state.inspect = {addr: {} for addr in reduce_addr}
    #     init_state.inspect_patterns = dic
    #     queue = [init_state]
    #     visit = set()
    #     while len(queue) > 0:  # DFS
    #         state = queue.pop()
    #         if state.node.addr in visit:
    #             continue
    #         result = self._simulateBB(state)
    #         if isinstance(result, list):  # fork
    #             visit.update(result[0].addrs)
    #             queue.extend(result[1:])
    #         else:  # state run to the end
    #             visit.update(result.addrs)
    #             collect.update(result.inspect)
    #     return collect

    def generate_forall_bb(self, funcname: str, dic) -> dict:
        self._init_function(funcname)

        all_addrs = []
        collect = {}
        for block in self.function.blocks:
            all_addrs.extend(block.instruction_addrs)
        self.supernode_parent_map = self.get_parent_supernode_addr_for_addresses(all_addrs)
        self.address_parent = self.get_parent_supernode_nodeobj_for_addresses(all_addrs)
        self.inspect_addrs = all_addrs
        start_node = self.cfg.get_any_node(self.function.addr)
        init_state = State(start_node, Environment())
        reduce_addr = set(self._reduce_addresses_by_basicblock(all_addrs))
        # based on basic block inspect
        init_state.inspect = {addr: {} for addr in reduce_addr}
        init_state.inspect_patterns = dic
        queue = [init_state]
        visit = set()
        while len(queue) > 0:  # DFS
            state = queue.pop()
            if state.node.addr in visit:
                continue
            result = self._simulateBB(state)
            if isinstance(result, list):  # fork
                visit.update(result[0].addrs)
                queue.extend(result[1:])
            else:  # state run to the end
                visit.update(result.addrs)
                collect.update(result.inspect)
        # print(f"collect: {collect}")
        
        for parent, child in self.dom_tree.edges():
            # print(f"parent: {parent}, child: {child}")
            # print(f"from_to: {self.from_to}")
            is_true_branch = (parent, child) in self.from_to
            self.dom_tree[parent][child]['true_branch'] = is_true_branch

        for parent, child in self.dom_tree.edges():
            is_true_branch = self.dom_tree[parent][child].get('true_branch', False)
            # print(f"0x{parent:x} -> 0x{child:x}, true_branch: {is_true_branch}")
        # print(f"collect: {collect}")
        new_collect = {}
        for k in collect.keys():
            if k in self.supernode_parent_map:
                parent = self.supernode_parent_map[k]
                k_top = self.supernode_map[k]
                if parent is None:
                    key = ("None", False)
                    new_collect[key] = []
                    for _, item in collect[k].items():
                        new_collect[key].extend(item)
                    # i = clean(new_collect[(t, False)])
                    # i = new_collect[key]
                    # new_collect[key] = i
                else:
                    is_true_branch = self.dom_tree[parent][k_top].get('true_branch', False)
                    # trace[parent]를 순회해서 Condition 만 가져오기 (Condition, true_branch 여부)
                    for _, traces in collect[parent].items():
                        for t in traces:
                            if isinstance(t, InspectInfo) and isinstance(t.ins, Effect.Condition):
                                key = (t, is_true_branch)
                                
                                # parent_cond = t
                                # key = (t, is_true_branch)
                                if key not in list(new_collect.keys()):
                                    new_collect[key] = []
                                for _, item in collect[k].items():
                                    if key not in list(new_collect.keys()):
                                        new_collect[key] = []
                                    
                                    new_collect[key].extend(item)
                                    
                                # i = clean(new_collect[key])
                                # i = new_collect[key]
                                # new_collect[key] = i
        return new_collect

    # def generate(self, funcname: str, addresses: dict, patterns) -> tuple[dict, list[dict]]:
    #     # print("in Simulator generate")
        
    #     self._init_function(funcname)
    #     trace = {}
    #     reduce, info = self._reduce_addresses_by_basicblock(addresses)
    #     reduce_addr = set(reduce)
    #     reachable = self._reachable_set(reduce_addr)
    #     start_node = self.cfg.get_any_node(self.function.addr)
    #     flatten_list = []
    #     for parent, children in addresses.items():
    #         # parent가 tuple일 수 있음
    #         if isinstance(parent, tuple):
    #             flatten_list.extend(list(parent))
    #         else:
    #             flatten_list.append(parent)
    #         flatten_list.extend(children)

    #     # self.inspect_addrs = addresses
    #     self.inspect_addrs = flatten_list
    #     init_state = State(start_node, Environment())
    #     # based on basic block inspect
    #     init_state.inspect = {addr: {} for addr in reduce_addr}
    #     init_state.inspect_patterns = patterns
    #     queue = [init_state]
    #     visit = set()
    #     while len(queue) > 0:  # DFS
    #         state = queue.pop()
    #         if state.node.addr not in reachable:
    #             continue
    #         if state.node.addr in visit:
    #             continue
    #         result = self._simulateBB(state, step_one=True)
            
    #         if isinstance(result, list):  # fork
    #             visit.update(result[0].addrs)
    #             trace.update(result[0].inspect)
    #             queue.extend(result)
    #         # else: # state run to the end
    #         #     if result.node.addr in reduce_addr:
    #         #         breakpoint()
    #         #     visit.update(result.addrs)
    #         #     trace.update(result.inspect)
    #         #     queue.append(result)
    #     return trace, info
    def get_supernode_for_addresses(self, addresses: list[int]) -> dict[int, int]:
        """
        각 address가 속한 super node(대표 주소)를 반환합니다.
        :param addresses: 확인할 address 리스트
        :return: {address: supernode_addr} 딕셔너리
        """
        # 1. 각 address가 속한 블록의 head address를 찾는다.
        addr_to_head = {}
        for addr in addresses:
            head_addr = None
            for block in self.function.blocks:
                if addr in block.instruction_addrs:
                    head_addr = block.addr
                    break
            addr_to_head[addr] = head_addr

        # 2. head address로 super_node에서 슈퍼노드 대표 주소를 찾는다.
        return {addr: self.super_node.get(head_addr, None) for addr, head_addr in addr_to_head.items()}
    def get_parent_supernode_addr_for_addresses(self, addresses: list[int]) -> dict[int, int | None]:
        """
        각 address의 super node의 dominator tree상 parent(super node) block의 node head address를 반환합니다.
        :param addresses: 확인할 address 리스트
        :return: {address: parent_supernode_addr or None} 딕셔너리
        """
        # supernode_map: address -> supernode_addr
        # dom_tree: supernode_addr(parent) -> supernode_addr(child)
        result = {}
        self.supernode_map = self.get_supernode_for_addresses(addresses)
        for addr in addresses:
            supernode = self.supernode_map.get(addr)
            if supernode is None:
                result[addr] = None
                continue
            # dom_tree에서 supernode의 parent 찾기 (parent -> supernode edge)
            parent = None
            for p, c in self.dom_tree.edges():
                if c == supernode:
                    parent = p
                    break
            result[addr] = parent
        return result
    
    def get_parent_supernode_nodeobj_for_addresses(self, addresses: list[int]) -> dict[int, angr.knowledge_plugins.cfg.cfg_node.CFGNode | None]:
        """
        각 address의 super node의 dominator tree상 parent(super node) block의 node 객체를 반환합니다.
        :param addresses: 확인할 address 리스트
        :return: {address: parent_supernode_node or None} 딕셔너리
        """
        # 1. 각 address가 속한 블록의 head address를 찾는다.
        addr_to_head = {}
        for addr in addresses:
            head_addr = None
            for block in self.function.blocks:
                if addr in block.instruction_addrs:
                    head_addr = block.addr
                    break
            addr_to_head[addr] = head_addr

        # 2. head address로 super_node에서 슈퍼노드 대표 주소를 찾는다.
        addr_to_supernode = {addr: self.super_node.get(head_addr, None) for addr, head_addr in addr_to_head.items()}

        # 3. 도미네이터 트리에서 parent supernode 주소 찾기
        result = {}
        for addr, supernode in addr_to_supernode.items():
            if supernode is None:
                result[addr] = None
                continue
            parent = None
            for p, c in self.dom_tree.edges():
                if c == supernode:
                    parent = p
                    break
            if parent is None:
                result[addr] = None
                continue
            # 4. parent(supernode) 주소에 해당하는 node 객체 찾기
            parent_node = self.addr2Node.get(parent, None)
            parent_addr = set()
            for stmt in self.node2IR[parent_node]:
                machine_addr = self.IR2addr[stmt]
                parent_addr.add(machine_addr)
                # print(f"machine_addr: {hex(machine_addr)}")
                # print(f"stmt: {stmt}")
            result[addr] = parent_addr
        return result

    def generate(self, funcname: str, addresses: list[int], patterns) -> dict:
        # print("in Simulator generate")
        if addresses[0] < self.proj.loader.main_object.min_addr:
            addresses = [(addr + self.proj.loader.main_object.min_addr)
                         for addr in addresses]
        self._init_function(funcname)
        self.supernode_parent_map = self.get_parent_supernode_addr_for_addresses(addresses)
        self.address_parent = self.get_parent_supernode_nodeobj_for_addresses(addresses)

        trace = {}
        reduce_addr = set(self._reduce_addresses_by_basicblock(addresses))
        reachable = self._reachable_set(reduce_addr)
        start_node = self.cfg.get_any_node(self.function.addr)
        self.inspect_addrs = deepcopy(addresses)
        init_state = State(start_node, Environment())
        # based on basic block inspect
        init_state.inspect = {addr: {} for addr in reduce_addr}
        init_state.inspect_patterns = patterns
        # print(f"self.supernode_parent_map: {self.supernode_parent_map}")

        for addr in addresses:
            parent_addr = self.supernode_parent_map[addr]
            if parent_addr not in init_state.inspect:
                init_state.inspect[parent_addr] = {}
            for parent_addr in self.address_parent[addr]:
                    if parent_addr not in self.inspect_addrs:
                        self.inspect_addrs.append(parent_addr)
                
        queue = [init_state]
        visit = set()
        while len(queue) > 0:  # DFS
            state = queue.pop()
            if state.node.addr not in reachable:
                continue
            if state.node.addr in visit:
                continue
            # logger.debug(f"Now begin {hex(state.node.addr)}")
            result = self._simulateBB(state, step_one=True)
            # print(f"result: {result}")
            
            if isinstance(result, list):  # fork
                visit.update(result[0].addrs)
                trace.update(result[0].inspect)
                queue.extend(result)

            # else: # state run to the end
            #     if result.node.addr in reduce_addr:
            #         breakpoint()
            #     visit.update(result.addrs)
            #     trace.update(result.inspect)
            #     queue.append(result)
            # print(f"trace: {trace}")
        # trace를 parent-child 관계로 변환
        for parent, child in self.dom_tree.edges():
            # print(f"parent: {parent}, child: {child}")
            # print(f"from_to: {self.from_to}")
            is_true_branch = (parent, child) in self.from_to
            self.dom_tree[parent][child]['true_branch'] = is_true_branch

        for parent, child in self.dom_tree.edges():
            is_true_branch = self.dom_tree[parent][child].get('true_branch', False)
            # print(f"0x{parent:x} -> 0x{child:x}, true_branch: {is_true_branch}")
        new_trace = {}
        for k in trace.keys():
            if k in self.supernode_parent_map:
                parent = self.supernode_parent_map[k]
                k_top = self.supernode_map[k]
                if parent is None:
                    key = ("None", False)
                    new_trace[key] = []
                    for _, item in trace[k].items():
                        new_trace[key].extend(item)
                    i = clean(new_trace[key])
                    new_trace[key] = i
                else:
                    is_true_branch = self.dom_tree[parent][k_top].get('true_branch', False)
                    # trace[parent]를 순회해서 Condition 만 가져오기 (Condition, true_branch 여부)
                    for _, traces in trace[parent].items():
                        for t in traces:
                            if isinstance(t, InspectInfo) and isinstance(t.ins, Effect.Condition):
                                # print(f"Condition: {t.effect.condition}, true_branch: {is_true_branch}")
                                # parent_cond = t
                                new_trace[(t, is_true_branch)] = []
                                for _, item in trace[k].items():
                                    new_trace[(t, is_true_branch)].extend(item)
                                i = clean(new_trace[(t, is_true_branch)])
                                new_trace[(t, is_true_branch)] = i
                # print(f"0x{k:x} -> 0x{parent:x}, true_branch: {is_true_branch}")
            # else:
            #     print(f"Warning: {k} not in supernode_parent_map")
        # print(f"new_trace: {new_trace}")
        return new_trace
    

    def _simulateBB(self, state: State, step_one=False) -> list[State] | State:
        while 1:
            state.addrs.append(state.node.addr)
            for statement in self.node2IR[state.node]:
                machine_addr = self.IR2addr[statement]
                if machine_addr in self.inspect_addrs:
                    # print(f"machine_addr: {hex(machine_addr)}")
                    # print(f"statement: {statement}") 
                    if isinstance(statement, stmt.Exit):
                        dst = statement.stmt.dst.value
                        self.from_to.append((state.node.addr, dst))
                        # print(f"Exit statement found: {hex(state.node.addr)} -> {hex(dst)} in {statement}")
                    cond = statement.simulate(state.env, True)
                    basicblock_addr = state.node.addr
                    # logger.info(f"basicblock_addr: {hex(basicblock_addr)}")
                    assert basicblock_addr in state.inspect
                    block = state.inspect[basicblock_addr]
                    # logger.info(f"block: {block}")
                    if machine_addr not in block:
                        # logger.info(f"machine_addr not in block")
                        block[machine_addr] = []
                    if isinstance(cond, InspectInfo):
                        # logger.info(f"cond is InspectInfo")
                        block[machine_addr].append(cond)
                    elif isinstance(cond, pe.IRExpr):  # guard it
                        block[machine_addr].append(
                            # InspectInfo(("Condition", cond)) 
                            InspectInfo(Effect.Condition(cond))
                        )
                    # logger.info(f"block2: {block}")                   
                else:
                    cond = statement.simulate(state.env)
            length = len(state.node.successors_and_jumpkinds(False))
            if length == 0:
                return state
            if length == 1:
                succ, jump = state.node.successors_and_jumpkinds(False)[0]
                if jump == "Ijk_Boring":
                    state.node = succ  # maybe exist condition even length == 1
                # elif jump == "Ijk_Call":
                #     output_stream = StringIO()
                #     sys.stdout = output_stream
                #     state.node.block.pp()
                #     output =  output_stream.getvalue()
                #     sys.stdout = sys.__stdout__
                #     breakpoint()
                #     state.node = succ
                #     state.env.set_ret()
                #     state.node = succ
                #     state.env.set_ret()
                elif jump == "Ijk_FakeRet":
                    output_stream = StringIO()
                    sys.stdout = output_stream
                    state.node.block.pp()
                    output = output_stream.getvalue()
                    sys.stdout = sys.__stdout__
                    # print(output)
                    # breakpoint()
                    if "call" in output:
                        call_name = output.split(
                            "\n")[-2].split("\t")[-1].split(" ")[-1]
                        # remove color in call_name
                        call_name = re.sub(r"\x1b\[[0-9;]*m", "", call_name)
                        if not call_name.startswith("0x"):
                            if call_name in state.inspect_patterns:  # collect all call
                                basicblock_addr = state.node.addr
                                if basicblock_addr in state.inspect:
                                    args = []
                                    # args number
                                    argnum = state.inspect_patterns[call_name][0]
                                    wild = state.inspect_patterns[call_name][1]
                                    for i in range(argnum):
                                        if wild[i]:
                                            args.append(WildCardSymbol())
                                        else:
                                            args.append(
                                                state.env.get_reg(Arg2RegNum[i]))
                                    info = InspectInfo(
                                        # ("Call", call_name, args)
                                        Effect.Call(call_name, args)
                                    )
                                    block = state.inspect[basicblock_addr]
                                    if machine_addr not in block:
                                        block[machine_addr] = []
                                    block[machine_addr].append(info)
                            state.env.set_ret(call_name)
                            state.node = succ
                        else:
                            state.env.set_ret()
                            state.node = succ
                    else:
                        state.env.set_ret()
                        state.node = succ
                else:
                    logger.critical(f"NotImplementedError {jump}")
                    state.node = succ
                if step_one:
                    return [state]
            else:  # length > 1, fork
                states = [state]
                try:
                    condition = state.node.block.vex.next.constants[0].value
                except:
                    condition = None
                for succ, jump in state.node.successors_and_jumpkinds(False):
                    # print(f"{succ} {jump}")
                    if jump == "Ijk_Boring":
                        # assert cond is not None
                        newstate = state.fork()
                        newstate.node = succ
                        states.append(newstate)
                    elif jump == "Ijk_Call":
                        # for succ, jump in state.node.successors_and_jumpkinds(False):
                        #     print(f"555 {succ} {jump}")
                        newstate = state.fork()
                        newstate.env.set_ret()
                        newstate.node = succ
                        states.append(newstate)
                    elif jump == "Ijk_FakeRet":
                        # state.node.block.pp()
                        # state.node.block.vex.pp()
                        # print(succ, jump)
                        # input()
                        newstate = state.fork()
                        newstate.env.set_ret()
                        newstate.node = succ
                        states.append(newstate)
                    else:
                        logger.critical(f"NotImplementedError {jump}")
                        continue
                return states

class Signature:
    def __init__(self, collect: dict, funcname: str, state: str, patterns) -> None:
        # print("in Signature")
        self.collect = collect
        self.funcname = funcname
        self.state = state
        self.patterns = patterns
        self.sig_dict = {"add": [], "remove": []}

    @classmethod
    def from_add(cls, collect: dict, funcname: str, state: str, patterns) -> "Signature":
        return cls(collect, funcname, state, patterns)

    @classmethod
    def from_remove(cls, collect: dict, funcname: str, state: str, patterns) -> "Signature":
        return cls(collect, funcname, state, patterns)

    @classmethod
    def from_modify(cls, collect_vuln: dict, collect_patch: dict, funcname: str, add_pattern, remove_pattern) -> "Signature":
        return cls([collect_vuln, collect_patch], funcname, "modify", [remove_pattern, add_pattern])

    def _clean(self, collect):
        # print("in _clean")
        collect_copy = collect.copy()
        for site in collect_copy:
            string = str(site)
            if string.find("FakeRet") == -1 and string.find("Mem") == -1 and string.find("SR") == -1:
                collect.remove(site)
        collect_copy = collect.copy()
        conds = []
        others = []
        for site in reversed(collect_copy):
            # if site.ins[0] == "Condition":
            if isinstance(site, Effect.Condition):
                # string = str(site.ins[1])
                string = str(site.expr)
                conds.append(string)
            # elif site.ins[0] == "Store":
            elif isinstance(site, Effect.Store):
                # string = str(site.ins[2])
                string = str(site.expr)
                if string in others:
                    collect.remove(site)
                    continue
                for cond in conds:
                    if string in cond:
                        collect.remove(site)
                        break
                others.append(string)
            # elif site.ins[0] == "Call":
            elif isinstance(site, Effect.Call):
                # for arg in site.ins[2]:
                for arg in site.args:
                    others.append(str(arg))
            # elif site.ins[0] == "Put":
            elif isinstance(site, Effect.Put):
                # string = str(site.ins[2])
                string = str(site.expr)
                # FakeRet with name, we cannot remove it
                if "FakeRet" in string and len(string) > len("FakeRet()"):
                    continue
                if string in others:
                    collect.remove(site)
                    continue
                for cond in conds:
                    if string in cond:
                        collect.remove(site)
                        break
                others.append(string)
        return collect

    def serial(self) -> list | tuple[list, list]:
        if self.state == "modify":
            return (self._serial(self.collect[0]), self._serial(self.collect[1]))
        else:
            return self._serial(self.collect)

    def _serial(self, collect) -> tuple[list, list]:
        # print("in _serial")
        l = []
        for bb in collect.keys():
            for addr_or_cons in collect[bb].keys():
                if addr_or_cons == "Constraints":
                    pass
                else:
                    for single_site in collect[bb][addr_or_cons]:
                        l.append(single_site)
        return self._clean(l), []

    def __str__(self) -> str:
        return f"{self.funcname} {self.state} {self.collect}"

    def show(self) -> None:
        if self.state == "modify":
            self._show(self.collect[0], "vuln")
            self._show(self.collect[1], "patch")
        else:
            self._show(self.collect, self.state)

    def _show(self, collect, type="") -> None:
        # print("=========================================", type)
        logger.info(f"========================================= {type} signature")
        # ser = self._serial(collect)
        # print(f"ser: {ser}")
        # for single_site in ser[0]:
        #     # print(single_site)
        #     logger.info(single_site)
        for key, value in collect.items():
            logger.info(f"Key: {key}")
            logger.info("------------------------------------------")
            for v in value:
                logger.info(v)
        # print("=========================================")
        logger.info("=========================================")


def valid_sig(sigs: list[Signature]):
    exists_modify = False
    # print("in valid_sig")
    for sig in sigs:
        # print(f"sig.state: {sig.state}")
        if sig.state == "modify":
            exists_modify = True
            break
    if exists_modify:
        new_sigs = []
        i = 0
        for sig in sigs:
            # print(f"i: {i}")
            i += 1
            if sig.state == "modify":
                add, remove = sig.serial()
                add = set(add[0])
                remove = set(remove[0])
                # breakpoint()
                # print(f"add: {add}")
                # print(f"remove: {remove}")
                if add.issuperset(remove) or remove.issuperset(add):
                    # print("add.issuperset(remove) or remove.issuperset(add)")
                    continue
                new_sigs.append(sig)
        return new_sigs
    return sigs


def handle_pattern(patterns: Patterns | list[Patterns]) -> dict:
    # print("in handle_pattern")
    def _handle_pattern(patterns: Patterns) -> dict:
        # print("in _handle_pattern")
        dic = {}
        for pattern in patterns.patterns:
            if pattern.pattern == "If":
                pass
            if pattern.pattern == "Call":
                dic[pattern.name] = [pattern.number, pattern.wildcard]
        return dic
    if isinstance(patterns, Patterns):
        return _handle_pattern(patterns)
    else:
        dic = {}
        for pa in patterns:
            dic.update(_handle_pattern(pa))
        return dic


class Generator:

    def __init__(self, vuln_proj: angr.Project, patch_proj: angr.Project) -> None:
        # print("in Generator")
        self.vuln_proj = Simulator(vuln_proj)
        self.patch_proj = Simulator(patch_proj)

    @classmethod
    def from_binary(cls, vuln_path: str, patch_path: str):
        # print("in from_binary")
        proj1 = angr.Project(vuln_path, load_options={'auto_load_libs': False})
        proj2 = angr.Project(patch_path, load_options={
                             'auto_load_libs': False})
        assert proj1.loader.main_object.min_addr == proj2.loader.main_object.min_addr
        return Generator(proj1, proj2)

    # def generate(self, funcname: str, addresses: dict, state: str, patterns: Patterns) -> dict:
    #     patterns_ = handle_pattern(patterns)
    #     new_addresses = {}
    #     try:
    #         if state == "vuln":
    #             base_addr = self.vuln_proj.proj.loader.main_object.min_addr
                
    #         elif state == "patch":
    #             base_addr = self.patch_proj.proj.loader.main_object.min_addr
    #         else:
    #             raise NotImplementedError(f"{state} is not considered.")
            
            
    #         for key in addresses.keys():
    #             if key != "None":
    #                 temp = addresses[key]
    #                 temp = [addr + base_addr for addr in temp]
    #                 new_key = tuple(x + base_addr for x in key)
    #                 new_addresses[new_key] = temp
    #             else:
    #                 temp = addresses[key]
    #                 temp = [addr + base_addr for addr in temp]
    #                 new_addresses[key] = temp

                    
    #         # if isinstance(addresses[0], tuple):
    #         #     addresses = [(parent + base_addr, binary + base_addr) for parent, binary in addresses]
    #         # else:
    #         #     addresses = [
    #         #             addr + base_addr for addr in addresses]
    #         if state == "vuln":
    #             collect, info = self.vuln_proj.generate(
    #                 funcname, new_addresses, patterns_)
    #         elif state == "patch":
    #             collect, info = self.patch_proj.generate(
    #                 funcname, new_addresses, patterns_)
    #         else:
    #             raise NotImplementedError(f"{state} is not considered.")
    #         # collect = self.vuln_proj.generate_parent_child(
    #         #     funcname, new_addresses, patterns_)
    #     except FunctionNotFound:
    #         return None
    #     print(f"new_addresses: {new_addresses}")
    #     print(f"collect: {collect}")
    #     print(f"info: {info}")
    #     new_collect = extract_collect(new_addresses, collect, info)
    #     print(f"new_collect: {new_collect}")
    #     for bb in new_collect.keys():
            # clean_collect = clean(new_collect[bb])
    #         new_collect[bb] = clean_collect
        
    #     print(f"signature: {new_collect}")
    #     return collect

    def generate(self, funcname: str, addresses: list[int], state: str, patterns: Patterns) -> dict:
        # print("in Generator generate")
        patterns_ = handle_pattern(patterns)
        try:
            if state == "vuln":
                addresses = [
                    addr + self.vuln_proj.proj.loader.main_object.min_addr for addr in addresses]
                collect = self.vuln_proj.generate(
                    funcname, addresses, patterns_)
            elif state == "patch":
                addresses = [
                    addr + self.patch_proj.proj.loader.main_object.min_addr for addr in addresses]
                collect = self.patch_proj.generate(
                    funcname, addresses, patterns_)
            else:
                raise NotImplementedError(f"{state} is not considered.")
        except FunctionNotFound:
            return None
        return collect

def extract_collect(addresses: dict, collect:dict, info:list) -> dict:
    new_collect = {}
    for parent, children in addresses.items():
        p_con = None
        for i in info:
            if parent == "None":
                new_collect["None"] = []
                child_addrs = i["children_addrs"]
                for c_addr in child_addrs:
                    for c in children:
                        child_collect = collect[c_addr][c]
                        new_collect["None"].extend(child_collect)
            else:
                if i["parent"] == parent:
                    parent_addrs = i["parent_addrs"]
                    for p_addr in parent_addrs:
                        for p in parent:
                            parent_collect = collect[p_addr][p]
                            for col in parent_collect:
                                temp_col = col
                                if  isinstance(col.ins, Effect.Condition):
                                    if p_con is None:
                                        new_collect[col] = []
                                        p_con = col
                                    else:
                                        print(f"two conditions for p_addr: {p_addr}, p: {p}, col: {col}, p_con: {p_con}")
                                        exit(0)
                    child_addrs = i["children_addrs"]
                    for c_addr in child_addrs:
                        for c in children:
                            child_collect = collect[c_addr][c]
                            new_collect[p_con].extend(child_collect)
                new_collect[p_con]= list(set(new_collect[p_con]))
    return new_collect
                                
def clean(collect):
    # print("in _clean")
    collect_copy = collect.copy()
    for site in collect_copy:
        string = str(site)
        if string.find("FakeRet") == -1 and string.find("Mem") == -1 and string.find("SR") == -1:
            collect.remove(site)
    collect_copy = collect.copy()
    conds = []
    others = []
    for site in sorted(collect_copy, key=lambda x: str(x)):
        effect = site.ins
        # if site.ins[0] == "Condition":
        if isinstance(effect, Effect.Condition):
            # string = str(site.ins[1])
            string = str(site).split("Condition: ")[-1].strip()
            conds.append(string)
        # elif site.ins[0] == "Store":
        elif isinstance(effect, Effect.Store):
            # string = str(site.ins[2])
            string = str(site).split("Store: ")[-1].split("= ")[-1].strip()
            if string in others:
                collect.remove(site)
                continue
            for cond in conds:
                if string in cond:
                    collect.remove(site)
                    break
            others.append(string)
        # elif site.ins[0] == "Call":
        elif isinstance(effect, Effect.Call):
            # for arg in site.ins[2]:
            args = str(site).split(effect.name + "(")[-1].replace("))", ")")
            others.append(args)
            
        # elif site.ins[0] == "Put":
        elif isinstance(effect, Effect.Put):
            # string = str(site.ins[2])
            string = str(site).split("Put: ")[-1].split("= ")[-1].strip()
            # FakeRet with name, we cannot remove it
            if "FakeRet" in string and len(string) > len("FakeRet()"):
                continue
            if string in others:
                collect.remove(site)
                continue
            for cond in conds:
                if string in cond:
                    collect.remove(site)
                    break
            others.append(string)
    return collect


def getbbs(collect) -> list:
    bbs = []
    for bb in collect.keys():
        constraints = []
        effect = []
        for addr_or_constraint in collect[bb]:
            if addr_or_constraint == "Constraints":
                pass
            else:
                for single_site in collect[bb][addr_or_constraint]:
                    effect.append(single_site)
        bbs.append((bb, constraints, effect))
    return bbs


def extrace_effect(collect) -> list:
    # logger.info(f"collect: {collect}")
    effect = []
    for bb in collect.keys():
        for addr_or_constraint in collect[bb]:
            if addr_or_constraint == "Constraints":
                continue
            for single_site in collect[bb][addr_or_constraint]:
                # logger.info(f"single_site: {single_site}")
                effect.append(single_site)
    # logger.info(f"effect: {effect}")
    return effect

class Symbol:
    """
    Represents a symbol with the necessary attributes for CFG analysis.
    """
    def __init__(self, name: str, rebased_addr: int, size: int, is_function: bool = True):
        """
        Initializes the Symbol object.

        :param name: The name of the symbol.
        :param rebased_addr: The rebased address of the symbol.
        :param size: The size of the symbol in bytes.
        :param is_function: Whether the symbol represents a function.
        """
        self.name = name
        self.rebased_addr = rebased_addr
        self.size = size
        self.is_function = is_function

    def __repr__(self):
        return (f"Symbol(name={self.name}, rebased_addr={hex(self.rebased_addr)}, "
                f"size={self.size}, is_function={self.is_function})")

class Test:
    def __init__(self, sigs: dict[str, list[Signature]]) -> None:
        self.sigs = sigs

    def test_path(self, binary_path: str) -> str:
        try:
            project = angr.Project(binary_path)
            simulator = Simulator(project)
            
        except Exception as e:
            print(f"Error testing path: {e}")

        
        return self.test_project(simulator)


    def test_project(self, simulator: Simulator) -> str:
        # if one think it's vuln, then it is vuln
        exist_patch = False
        results = []
        funcnames = self.sigs.keys()

        # check at least one function is in the binary, else return None
        # for funcname in funcnames:
        #     func_addr = self.find_custom_symbol(funcname)
        #     if func_addr is not None:
        #         # simulator.symbol = funcname

        #         break
        # else:
        #     logger.critical(f"no function {funcnames} in the signature")
        #     # exit(0)
        #     assert False
        for funcname in self.sigs.keys():
            sigs = self.sigs[funcname]
            # funcname = "ssl3_get_record"
            # simulator = Simulator(simulator.proj)
            # sigs = [<simulator.Signature object at 0x7fafd1f517e0>]
            result = self.test_func(funcname, simulator, sigs)
            # print(f"result: {result}")
            # time.sleep(10)
            if result == "vuln":
                return "vuln"
            results.append(result)
        # print(f"results: {results}")
        # time.sleep(10)
        for result in results:
            if result == "vuln":
                return "vuln"
            if result == "patch":
                exist_patch = True
        if exist_patch:
            return "patch"
        return "vuln"
        # return "patch"

    def use_pattern(self, patterns: Patterns) -> str:
        for pattern in patterns.patterns:
            if pattern.pattern == "If":
                return "If"
        for pattern in patterns.patterns:
            if pattern.pattern == "Call":
                return "Call"
        return None

    # def _match2len(self, match: list) -> int:
    #     l = 0
    #     for m in match:
    #         if m.ins[0] == "Put":
    #             l += 1
    #         elif m.ins[0] == "Store":
    #             l += 1.5
    #         elif m.ins[0] == "Condition" or m.ins[0] == "Call":
    #             l += 2
    #         else:
    #             raise NotImplementedError(f"{m.ins[0]} is not considered.")
    #     return l

    def _match2len(self, match: list[InspectInfo]) -> int:
        l = 0
        for m in match:
            ins = m.ins
            if isinstance(ins, Effect.Put):
                l += 1
            elif isinstance(ins, Effect.Store):
                l += 1.5
            elif isinstance(ins, (Effect.Condition, Effect.Call)):
                l += 2
            else:
                raise NotImplementedError(f"{type(ins)} is not considered.")
        return l

    def test_func(self, funcname: str, simulator: Simulator, sigs: list[Signature]) -> str:
        dic = {}
        
        for sig in sigs:
            dic.update(handle_pattern(sig.patterns))
            # print(f'{sig.funcname} {sig.state} {sig.patterns}') # ssl3_get_record modify [Patterns(patterns=[]), Patterns(patterns=[])]
            # time.sleep(10)
        try:
            traces: dict = simulator.generate_forall_bb(funcname, dic)
            # print(f"traces: {traces}")
            # exit(0)
            # time.sleep(10)
        except FunctionNotFound:
            print(f"FunctionNotFound: {funcname}")
            return None
        result = []
        # test one hunk's signature
        for sig in sigs:
            refined = False
            if sig.state == "vuln":
                # vuln_effect, _ = sig.serial()
                vuln_effect = sig.collect
                patch_effect = {}
                vuln_effect = single_refine(vuln_effect)
                # assert vuln_effect == sig.collect, f"vuln_effect {vuln_effect} != sig.collect {sig.collect}"
                print(f"refined vuln_effect: {vuln_effect}")
                vuln_pattern, patch_pattern = sig.patterns, Patterns([])
            elif sig.state == "patch":
                vuln_effect = {}
                # patch_effect, _ = sig.serial()
                patch_effect = sig.collect
                patch_effect = single_refine(patch_effect)
                # assert patch_effect == sig.collect, f"patch_effect {patch_effect} != sig.collect {sig.collect}"
                print(f"refined patch_effect: {patch_effect}")
                vuln_pattern, patch_pattern = Patterns([]), sig.patterns

            elif sig.state == "modify":
                if sig.sig_dict["add"] == [] and sig.sig_dict["remove"] == []:
                    # vuln_info, patch_info = sig.serial()
                    # vuln_effect, _ = vuln_info
                    # patch_effect, _ = patch_info
                    # vuln_effect, patch_effect = sig.sig_dict["remove"], sig.sig_dict["add"]
                    vuln_effect, patch_effect = sig.collect[0], sig.collect[1] # vuln_effect, patch_effect는 dict 형태

                    for vuln_key, vuln_value in list(vuln_effect.items()):
                        for patch_key, patch_value in list(patch_effect.items()):
                            # print(f"vuln_key: {vuln_key}, vuln_value: {vuln_value}")
                            # print(f"patch_key: {patch_key}, patch_value: {patch_value}")
                            old_vuln_key, old_patch_key = deepcopy(vuln_key[0]), deepcopy(patch_key[0])
                            new_vuln_key, new_patch_key =  rebuild_effects(vuln_key[0]), rebuild_effects(patch_key[0])
                            assert new_vuln_key == old_vuln_key, f"new_vuln_key {new_vuln_key} != old_vuln_key {old_vuln_key}"
                            assert new_patch_key == old_patch_key, f"new_patch_key {new_patch_key} != old_patch_key {old_patch_key}"
                            vuln_key, patch_key = (new_vuln_key, vuln_key[1]) , (new_patch_key, patch_key[1])
                            if vuln_key == patch_key:
                                # print(f"vuln_value: {vuln_value}, patch_value: {patch_value}")
                                v, p = list(set(vuln_value) - set(patch_value)), list(set(patch_value) - set(vuln_value))
                                if not v and not p:
                                    # 두 리스트가 모두 비어 있으면 key 삭제
                                    del vuln_effect[vuln_key]
                                    del patch_effect[patch_key]
                                else:
                                    # refinement
                                    refined_v, refined_p = refine_sig(v, p)
                                    vuln_effect[vuln_key] = refined_v
                                    patch_effect[patch_key] = refined_p
                    
                    # vuln_effect = set(vuln_effect)
                    # patch_effect = set(patch_effect)
                    
                    # vuln_effect, patch_effect = vuln_effect-patch_effect, patch_effect-vuln_effect
                    # vuln_effect = list(vuln_effect)
                    # patch_effect = list(patch_effect)
                    
                    # if vuln_effect != [] and patch_effect != []:    
                    #     vuln_effect, patch_effect = refine_sig(vuln_effect, patch_effect)
                    #     refined = True
                    sig.sig_dict["add"] = patch_effect
                    sig.sig_dict["remove"] = vuln_effect
                else:
                    vuln_effect, patch_effect = sig.sig_dict["remove"], sig.sig_dict["add"]

                vuln_pattern, patch_pattern = sig.patterns[0], sig.patterns[1]
            else:
                raise NotImplementedError(f"{sig.state} is not considered.")
            
            vuln_use_pattern, patch_use_pattern = self.use_pattern(
                vuln_pattern), self.use_pattern(patch_pattern)
            # vuln_effect = set(vuln_effect)
            # patch_effect = set(patch_effect)
            
            # vuln_effect, patch_effect = vuln_effect-patch_effect, patch_effect-vuln_effect
            
            if len(vuln_effect) == 0 and len(patch_effect) == 0:
                continue
            # logger.info(f"vuln_effect: {vuln_effect}")
            # logger.info(f"patch_effect: {patch_effect}")
            vuln_match, patch_match = [], []
            # all_effects = extrace_effect(traces)
            all_effects = traces
            old_effects = deepcopy(all_effects)
            # all_effects = list(set(all_effects))
            # print(f"before rebuild all_effects: {all_effects}")
            for k, v in list(all_effects.items()):
                new_key = rebuild_effects(k[0])
                try:
                    assert new_key == k[0], f"new_key {new_key} != old_key {k[0]}"
                except AssertionError:
                    print(f"new_key {new_key.ins.expr}, type: {type(new_key.ins.expr)}")
                    print(f"old_key {k[0].ins.expr}, type: {type(k[0].ins.expr)}")
                    exit(0)
                k = (new_key, k[1])

                old_v = deepcopy(v)
                new_v = []
                for effect in v:
                    new_v.append(rebuild_effects(effect))
                assert new_v == old_v, f"new_v {new_v} != old_v {old_v}"
                all_effects[k] = new_v
                # temp = []
                # for i in all_effects:
                #     print(f"refined i: {i}")
                #     a = rebuild_effects(i)
                #     print(f"refined a: {a}")
                #     temp.append(a)
                # all_effects = temp
                # all_effects = [rebuild_effects(e) for e in all_effects]
            
            assert all_effects == old_effects, f"all_effects {all_effects}, len(all_effects) {len(all_effects)} \n!= \nold_effects {old_effects}, len(old_effects) {len(old_effects)}"
            
                # print(f"refined all_effects: {all_effects}")
            # logger.info(f"all_effects: {all_effects}") 
            # logger.info(f"all_effects: {sorted(str(InspectInfo(i)) for i in all_effects)}")
            logger.info(f"after rebuild all_effects: {all_effects}")
            # for effect in all_effects:
            #     logger.info(f"effect: {effect}")
            
            
            test = False
            # essential a add patch
            if len(vuln_effect) == 0:
                # logger.info("pure addition")
                # temp = len(patch_effect)
                # for i in range(temp):
                #     patch_effect = list(patch_effect)  # 리스트로 변환
                #     patch = patch_effect[temp-i-1]
                for patch_key, patch_value in patch_effect.items():
                    # for patch in patch_effect:
                    #     if (patch.ins[0] == "Condition" or patch.ins[0] == "Call") and patch not in all_effects:
                    for pv in patch_value:
                        # print(f"patch_value: {pv} and patch_key: {patch_key}")
                        if isinstance(pv.ins, (Effect.Condition, Effect.Call)):
                            if patch_key not in all_effects:
                                logger.info(f"patch {patch_key} is not in all_effects; {all_effects.keys()}")
                                test = True
                                result.append("vuln")
                                break
                            else:
                                if pv not in all_effects[patch_key]:
                                    test = True
                                    logger.info(f"all_effects[{patch_key}] does not contain {pv}; {all_effects[patch_key]}")
                                    result.append("vuln")
                                    break
                        # if isinstance(pv.ins, (Effect.Condition, Effect.Call)) and patch_key in all_effects and pv not in all_effects[patch_key]:
                        #     test = True
                        #     # logger.info(f"patch {pv} is not in all_effects")
                        #     print(f"patch {patch_key}: {pv} is not in all_effects")
                        #     result.append("vuln")
                        #     break
                # for patch in patch_effect:
                #     # if (patch.ins[0] == "Condition" or patch.ins[0] == "Call") and patch not in all_effects:
                #     if isinstance(patch.ins, (Effect.Condition, Effect.Call)) and patch not in all_effects:
                #         test = True
                #         result.append("vuln")
                #         break
            # essential a vuln patch
            if len(patch_effect) == 0:
                # logger.info("pure deletion")
                for vuln_key, vuln_value in vuln_effect.items():
                    for vv in vuln_value:
                        # for vuln in vuln_effect:
                        #     if (vuln.ins[0] == "Condition" or vuln.ins[0] == "Call") and vuln not in all_effects:
                        if isinstance(vv.ins, (Effect.Condition, Effect.Call)):
                            if vuln_key not in all_effects:
                                logger.info(f"vuln {vuln_key} is not in all_effects; {all_effects.keys()}")
                                test = True
                                result.append("patch")
                                break
                            else:
                                if vv not in all_effects[vuln_key]:
                                    test = True
                                    logger.info(f"all_effects[{vuln_key}] does not contain {vv}; {all_effects[vuln_key]}")
                                    result.append("patch")
                                    break
                # for vuln in vuln_effect:
                #     # if (vuln.ins[0] == "Condition" or vuln.ins[0] == "Call") and vuln not in all_effects:
                #     if isinstance(vuln.ins, (Effect.Condition, Effect.Call)) and vuln not in all_effects:
                #         test = True
                #         # logger.info(f"vuln {vuln} is not in all_effects")
                #         result.append("patch")
                #         break
            # else:
            #     logger.info("modify")
            if test:
                continue
            # for ae in all_effects:
            #     if ae in vuln_effect:
            #         # logger.info(f"vuln {ae} is in vuln_effect")
            #         vuln_match.append(ae)
            #     if ae in patch_effect:
            #         # logger.info(f"patch {ae} is in patch_effect")
            #         patch_match.append(ae)

            # TODO: 테스트 할 방법 찾기
            # for vuln in vuln_effect:
            #     if vuln in all_effects:
            #         vuln_match.append(vuln)
            for vuln_key, vuln_value in vuln_effect.items():
                if vuln_key in all_effects:
                    for vv in vuln_value:
                        if vv in all_effects[vuln_key]:
                            vuln_match.append(vv)
            # for patch in patch_effect:                
            #     if patch in all_effects:
            #         patch_match.append(patch)
            for patch_key, patch_value in patch_effect.items():
                if patch_key in all_effects:
                    for pv in patch_value:
                        if pv in all_effects[patch_key]:
                            patch_match.append(pv)
            logger.info(f"vuln match {vuln_match}, patch match {patch_match}")
            # exit(0)
            # If the pattern is If, then we should check there at least one condition in matched effect
            if patch_use_pattern == "If":
                # patch_match = [
                #     i for i in patch_match if i.ins[0] == "Condition"]
                patch_match = [i for i in patch_match if isinstance(i.ins, Effect.Condition)]
                if len(patch_match) == 0:
                    result.append("vuln")
                    continue
            if vuln_use_pattern == "If":
                # vuln_match = [i for i in vuln_match if i.ins[0] == "Condition"]
                vuln_match = [i for i in vuln_match if isinstance(i.ins, Effect.Condition)]
                if len(vuln_match) == 0:
                    result.append("patch")
                    continue
            vuln_num = self._match2len(vuln_match)
            patch_num = self._match2len(patch_match)
            # print(vuln_num, patch_num, funcname)
            if vuln_num == 0 and patch_num == 0:
                continue
            if patch_num == vuln_num:
                continue
            if vuln_num >= patch_num:
                return "vuln"
            result.append("patch" if patch_num > vuln_num else "vuln")
        if len(result) == 0:
            print("result: None")
            return None
        # if one think it's vuln, then it is vuln
        if "vuln" in result:
            return "vuln"
        if "patch" in result:
            return "patch"
        # if no vuln and patch, then it's vuln
        return "vuln"
        # return "patch"
