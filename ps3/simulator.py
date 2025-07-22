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
from key_equal import key_checker


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

def _update_new_trace(trace, temp_supernode, supernode_parent_map, supernode_map, dom_tree):
    """
    trace, temp_supernode, supernode_parent_map, supernode_map, dom_tree를 받아
    new_trace를 업데이트하는 공통 로직을 함수로 분리
    """
    new_trace = {}
    for k in trace.keys():
        if k in supernode_parent_map:
            parent = supernode_parent_map[k]
            k_top = supernode_map[k]
            if parent is None:
                key = ("None", False)
                new_trace[key] = []
                for _, item in trace[k].items():
                    new_trace[key].extend(item)
                i = clean(new_trace[key])
                new_trace[key] = i
            else:
                is_true_branch = dom_tree[parent][k_top].get('true_branch', False)
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
        else:
            if k in temp_supernode:
                for real_key in temp_supernode[k]:
                    parent = supernode_parent_map[real_key]
                    k_top = supernode_map[real_key]
                    if parent is None:
                        key = ("None", False)
                        new_trace[key] = []
                        for _, item in trace[k].items():
                            new_trace[key].extend(item)
                        i = clean(new_trace[key])
                        new_trace[key] = i
                    else:
                        is_true_branch = dom_tree[parent][k_top].get('true_branch', False)
                        # trace[parent]를 순회해서 Condition 만 가져오기 (Condition, true_branch 여부)
                        for _, traces in trace[parent].items():
                            for t in traces:
                                if isinstance(t, InspectInfo) and isinstance(t.ins, Effect.Condition):
                                    # print(f"Condition: {t.effect.condition}, true_branch: {is_true_branch}")
                                    new_trace[(t, is_true_branch)] = []
                                    for _, item in trace[k].items():
                                        new_trace[(t, is_true_branch)].extend(item)
                                    i = clean(new_trace[(t, is_true_branch)])
                                    new_trace[(t, is_true_branch)] = i
    return new_trace


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
        # dominator_builder.print_dom_tree(self.dom_tree, symbol.rebased_addr, labels=None)
        self.function = function
        self._init_map()

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

    def _reduce_addresses_by_basicblock(self, address: list[int]) -> set[int]:
        l = list(self.function.blocks)
        result = set()
        for addr in address:
            for block in l:
                if addr in block.instruction_addrs:
                    result.add(block.addr)
                    break
        return result

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
                                
                                new_collect.setdefault(key, [])
                                # if key not in list(new_collect.keys()):
                                #     new_collect[key] = []
                                for _, item in collect.get(k, {}).items():
                                    # print(f"Trying to access key: {key}")
                                    # print(f"Current keys: {list(new_collect.keys())}")
                                    if isinstance(item, list):
                                        try:
                                            new_collect[key].extend(item)
                                        except Exception as e:
                                            print(f"Trying to access key: {key}")
                                            print(f"Current keys: {list(new_collect.keys())}")
                                            exit(0)
                                    else:
                                        new_collect[key].append(item)
                            #    for _, item in collect[k].items():
                            #        if key not in new_collect:
                            #            new_collect[key] = []
                                    # item이 리스트가 아닐 수도 있으니 리스트로 변환
                            #        if isinstance(item, list):
                            #            new_collect[key].extend(item)
                            #        else:
                            #            new_collect[key].append(item)
                                # print(f"new_collect: {new_collect}"
                                    
                                # i = clean(new_collect[key])
                                # i = new_collect[key]
                                # new_collect[key] = i
        return new_collect

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
            # print(f"addr {hex(addr)} -> supernode {hex(supernode)}, parent {hex(parent) if parent is not None else 'None'}")
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
            # parent_addr = self.supernode_parent_map[addr].keys()
            if parent_addr not in init_state.inspect:
                init_state.inspect[parent_addr] = {}
            if self.address_parent[addr] is not None:
                for parent_addr in self.address_parent[addr]:
                        if parent_addr not in self.inspect_addrs:
                            self.inspect_addrs.append(parent_addr)
        # print(f"self.inspect_addrs: {hexl(self.inspect_addrs)}")
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
                # print(f"trace: {trace}")

            # else: # state run to the end
            #     if result.node.addr in reduce_addr:
            #         breakpoint()
            #     visit.update(result.addrs)
            #     trace.update(result.inspect)
            #     queue.append(result)
        # trace를 parent-child 관계로 변환
        for parent, child in self.dom_tree.edges():
            # print(f"parent: {hex(parent)}, child: {hex(child)}")
            # print(f"from_to: {self.from_to}")
            is_true_branch = (parent, child) in self.from_to
            self.dom_tree[parent][child]['true_branch'] = is_true_branch
            # print(f"0x{parent:x} -> 0x{child:x}, true_branch: {is_true_branch}")

        for parent, child in self.dom_tree.edges():
            is_true_branch = self.dom_tree[parent][child].get('true_branch', False)
            # print(f"0x{parent:x} -> 0x{child:x}, true_branch: {is_true_branch}")
        new_trace = {}
        # print(f"self.supernode_parent_map: {self.supernode_parent_map}")
        # print("self.supernode_map: ")
        # for k, v in self.supernode_map.items():
        #     print(f"0x{k:x} -> 0x{v:x}")
        # print("self.supernode_parent_map: ")
        # for k, v in self.supernode_parent_map.items():
        #     if v is None:
        #         print(f"0x{k:x} -> None")
        #     else:
        #         print(f"0x{k:x} -> 0x{v:x}")
        # for key in trace.keys():
        #     print(f"key: {hex(key)}, in self.supernode_parent_map: {key in self.supernode_parent_map}")

        # for k, v in trace.items():
        #     print(f"key: {hex(k)}, value: {v}")
        #     if isinstance(v, dict):
        #         for k2, v2 in v.items():
        #             print(f"  key2: {hex(k2)}, value2: {v2}")
        temp_supernode = {}
        for k, v in self.supernode_map.items():
            if v is not None:
                if v not in temp_supernode:
                    temp_supernode[v] = []
                temp_supernode[v].append(k)
        
        # 기존 중복 코드 대신 함수 호출로 대체
        new_trace = _update_new_trace(trace, temp_supernode, self.supernode_parent_map, self.supernode_map, self.dom_tree)
        keys_to_delete = [k for k, v in new_trace.items() if v == []]
        for k in keys_to_delete:
            del new_trace[k]
        
        return new_trace
    

    def _simulateBB(self, state: State, step_one=False) -> list[State] | State:
        while 1:
            state.addrs.append(state.node.addr)
            for statement in self.node2IR[state.node]:
                machine_addr = self.IR2addr[statement]
                # print(f"statement: {statement}, type: {type(statement)}, in self.inspect_addrs: {machine_addr in self.inspect_addrs}")
                if machine_addr in self.inspect_addrs:
                    # print(f"machine_addr: {hex(machine_addr)}")
                    if isinstance(statement, stmt.Exit):
                        dst = statement.stmt.dst.value
                        self.from_to.append((state.node.addr, dst))
                    cond = statement.simulate(state.env, True)
                    basicblock_addr = state.node.addr
                    assert basicblock_addr in state.inspect
                    block = state.inspect[basicblock_addr]
                    # logger.info(f"block: {block}")
                    if machine_addr not in block:
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
        self.refined_patch = None
        self.refined_vuln = None

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
            logger.info("------------------------------------------")
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
                remove, add = sig.collect[0], sig.collect[1]
                for _, rv in remove.items():
                    rv = set(rv)
                    for _, av in add.items():
                        av = set(av)
                        if rv.issubset(av) or av.issubset(rv):
                            # print(f"rv: {rv}, av: {av}")
                            # print("rv.issubset(av) or av.issubset(rv)")
                            break
                    else:
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
                patch_effect = {}
                # vuln_effect, _ = sig.serial()
                if sig.refined_vuln is None:
                    vuln_effect = sig.collect
                    vuln_effect = single_refine(vuln_effect)
                    sig.refined_vuln = vuln_effect
                    logger.info(f"refined vuln_effect: {vuln_effect}")
                else:
                    vuln_effect = sig.refined_vuln
                
                # assert vuln_effect == sig.collect, f"vuln_effect {vuln_effect} != sig.collect {sig.collect}"
                # print(f"refined vuln_effect: {vuln_effect}")
                vuln_pattern, patch_pattern = sig.patterns, Patterns([])
            elif sig.state == "patch":
                vuln_effect = {}
                # patch_effect, _ = sig.serial()
                if sig.refined_patch is None:
                    patch_effect = sig.collect
                    patch_effect = single_refine(patch_effect)
                    sig.refined_patch = patch_effect
                    logger.info(f"refined patch_effect: {patch_effect}")
                else:
                    patch_effect = sig.refined_patch
                # print(f"refined patch_effect: {patch_effect}")
                vuln_pattern, patch_pattern = Patterns([]), sig.patterns
                # exit(0)
            
            elif sig.state == "modify":
                if sig.sig_dict["add"] == [] and sig.sig_dict["remove"] == []:
                    # vuln_info, patch_info = sig.serial()
                    # vuln_effect, _ = vuln_info
                    # patch_effect, _ = patch_info
                    # vuln_effect, patch_effect = sig.sig_dict["remove"], sig.sig_dict["add"]
                    vuln_effect, patch_effect = sig.collect[0], sig.collect[1] # vuln_effect, patch_effect는 dict 형태
                    vuln_effect = single_refine(vuln_effect)
                    patch_effect = single_refine(patch_effect)
                    logger.info(f"refined vuln_effect: {vuln_effect}")
                    logger.info(f"refined patch_effect: {patch_effect}")
                    # for vuln_key, vuln_value in list(vuln_effect.items()):
                        # for patch_key, patch_value in list(patch_effect.items()):
                        #     # print(f"vuln_key: {vuln_key}, vuln_value: {vuln_value}")
                        #     # print(f"patch_key: {patch_key}, patch_value: {patch_value}")
                        #     old_vuln_key, old_patch_key = deepcopy(vuln_key[0]), deepcopy(patch_key[0])
                        #     new_vuln_key, new_patch_key =  rebuild_effects(vuln_key[0]), rebuild_effects(patch_key[0])
                        #     assert new_vuln_key == old_vuln_key, f"new_vuln_key {new_vuln_key} != old_vuln_key {old_vuln_key}"
                        #     assert new_patch_key == old_patch_key, f"new_patch_key {new_patch_key} != old_patch_key {old_patch_key}"
                        #     vuln_key, patch_key = (new_vuln_key, vuln_key[1]) , (new_patch_key, patch_key[1])
                        #     if vuln_key == patch_key:
                        #         # print(f"vuln_value: {vuln_value}, patch_value: {patch_value}")
                        #         v, p = list(set(vuln_value) - set(patch_value)), list(set(patch_value) - set(vuln_value))
                        #         # refinement
                        #         if v and p:
                        #             # both have values, refine them
                        #                 refined_v, refined_p = refine_sig(v, p)
                        #                 vuln_effect[vuln_key] = refined_v
                        #                 patch_effect[patch_key] = refined_p
                        #         elif v:
                        #             # only vuln has values, refine vuln
                        #             refined_v = single_refine(v)
                        #             vuln_effect[vuln_key] = refined_v
                        #             if patch_key in patch_effect:
                        #                 del patch_effect[patch_key]
                                    
                        #         elif p:
                        #             # only patch has values, refine patch
                        #             refined_p = single_refine(p)
                        #             patch_effect[patch_key] = refined_p
                        #             if vuln_key in vuln_effect:
                        #                 del vuln_effect[vuln_key]
                        #         else:
                        #             del vuln_effect[vuln_key]
                        #             del patch_effect[patch_key]

                    sig.sig_dict["add"] = patch_effect
                    sig.sig_dict["remove"] = vuln_effect
                    sig.refined_patch = patch_effect
                    sig.refined_vuln = vuln_effect
                else:
                    vuln_effect, patch_effect = sig.sig_dict["remove"], sig.sig_dict["add"]

                vuln_pattern, patch_pattern = sig.patterns[0], sig.patterns[1]
            else:
                raise NotImplementedError(f"{sig.state} is not considered.")
            
            vuln_use_pattern, patch_use_pattern = self.use_pattern(
                vuln_pattern), self.use_pattern(patch_pattern)
            
            if len(vuln_effect) == 0 and len(patch_effect) == 0:
                continue
            vuln_match, patch_match = [], []
            # all_effects = extrace_effect(traces)
            all_effects = traces
            
            old_effects = deepcopy(all_effects)
            # all_effects = list(set(all_effects))
            # logger.info(f"before rebuild all_effects: {all_effects}")
            new_effects = {}
            for k, v in all_effects.items():
                new_key = rebuild_effects(k[0])
                # try:
                #     assert new_key == k[0], f"new_key {new_key} != old_key {k[0]}"
                # except AssertionError:
                #     print(f"new_key {new_key.ins.expr}, type: {type(new_key.ins.expr)}")
                #     print(f"old_key {k[0].ins.expr}, type: {type(k[0].ins.expr)}")
                #     exit(0)
                k = (new_key, k[1])

                old_v = deepcopy(v)
                new_v = []
                for effect in v:
                    new_v.append(rebuild_effects(effect))
                # assert new_v == old_v or str(new_v) == str(old_v), f"new_v {new_v} != old_v {old_v}"
                # if new_v != old_v:
                                # logger.info(f"str(new_v) == str(old_v): {str(nv) == str(ov)}")
                                # logger.info(f"new_v type: {type(nv)}, old_v type: {type(ov)}")
                                # logger.info(f"new_v ins: {nv.ins}, old_v ins: {ov.ins}")
                                # logger.info(f"new_v expr: {nv.expr}, old_v expr: {ov.expr}")
                    # raise AssertionError(f"new_v != old_v, {str(new_v) == str(ov)}")
                new_effects[k] = new_v

            all_effects = new_effects
            logger.info(f"after rebuild all_effects: {all_effects}")
            
            
            test = False
            # essential a add patch
            if len(vuln_effect) == 0:
                for patch_key, patch_value in patch_effect.items():
                    for pv in patch_value:
                        if isinstance(pv.ins, Effect.Call):
                            if patch_key not in all_effects:
                            # if same_key is None:
                                logger.info(f"KEY MATCHING FALIED: {patch_key} is not in all_effects; {all_effects.keys()}")
                                test = True
                                result.append("vuln")
                                break
                            else:
                                # if pv not in all_effects[patch_key]:
                                if pv not in all_effects[patch_key]:
                                    test = True
                                    logger.info(f"VALUE MATCHING FAILED: all_effects[{patch_key}] does not contain {pv}; {all_effects[patch_key]}")
                                    result.append("vuln")
                                    break
                        if isinstance(pv.ins, Effect.Condition):
                            in_true_branch = True
                            in_false_branch = True
                            if patch_key not in all_effects: # patch_key is a Condition, so we check if it is in all_effects
                                if (pv, True) not in all_effects :
                                    # test = True
                                    # result.append("vuln")
                                    # logger.info(f"KEY MATCHING FALIED: {patch_key} and {pv} is not in all_effects; {all_effects.keys()}")
                                    # break
                                    # key 없음
                                    in_true_branch = False
                                # else:
                                #     if (pv, True) in patch_effect and patch_effect[(pv, True)] != all_effects[(pv, True)]:
                                #         # test = True
                                #         # result.append("vuln")
                                #         # logger.info(f"VALUE MATCHING FAILED: all_effects[{pv}] are different from {patch_effect[pv]}; {all_effects[pv]}")
                                #         # break
                                #         # value 다름
                                #         in_true_branch = False
                                
                                # if not in_true_branch: # True branch에 없으면 False branch에 있는지 확인
                                    if (pv, False) not in all_effects:
                                        in_false_branch = False
                                    # else:
                                    #     if (pv, False) in patch_effect and patch_effect[(pv, False)] != all_effects[(pv, False)]:
                                    #         in_false_branch = False

                                if not in_true_branch and not in_false_branch:
                                    logger.info(f"KEY MATCHING FALIED: {patch_key} and {pv}'s True and False are not in all_effects; {all_effects.keys()}")
                                    test = True
                                    result.append("vuln")
                                    break
                            else:
                                if pv not in all_effects[patch_key]:
                                    logger.info(f"VALUE MATCHING FAILED: all_effects[{patch_key}] does not contain {pv}; {all_effects[patch_key]}")
                                    test = True
                                    result.append("vuln")
                                    break
                            
            
                            # if pv not in all_effects: # pv is a Condition, so we check if it is in all_effects
                            #     
                            #     test = True
                            #     result.append("vuln")
                            #     break
            # essential a vuln patch
            if len(patch_effect) == 0:
                
                for vuln_key, vuln_value in vuln_effect.items():
                    for vv in vuln_value:
                        if isinstance(vv.ins, Effect.Call):
                            # same_key = key_checker(vuln_key, list(all_effects.keys()))
                            # if same_key is None:
                            if vuln_key not in all_effects:
                                logger.info(f"KEY MATCHING FALIED: {vuln_key} is not in all_effects; {all_effects.keys()}")
                                test = True
                                result.append("patch")
                                break
                            else:
                                # if vv not in all_effects[vuln_key]:
                                if vv not in all_effects[vuln_key]:
                                    test = True
                                    logger.info(f"VALUE MATCHING FAILED: all_effects[{vuln_key}] does not contain {vv}; {all_effects[vuln_key]}")
                                    result.append("patch")
                                    break
                        if isinstance(vv.ins, Effect.Condition):
                            if vuln_key not in all_effects: # vuln_key is a Condition, so we check if it is in all_effects
                                in_true_branch = True
                                in_false_branch = True
                                if (vv, True) not in all_effects:
                                    # test = True
                                    # result.append("patch")
                                    # logger.info(f"KEY MATCHING FALIED: {vuln_key} and {vv} is not in all_effects; {all_effects.keys()}")
                                    # break
                                    # key 없음
                                    in_true_branch = False
                                else:
                                    if (vv, True) in vuln_effect and vuln_effect[(vv, True)] != all_effects[(vv, True)]:
                                        # test = True
                                        # result.append("patch")
                                        # logger.info(f"VALUE MATCHING FAILED: all_effects[{vv}] are different from {vuln_effect[vv]}; {all_effects[vv]}")
                                        # break
                                        # value 다름
                                        in_true_branch = False

                                if not in_true_branch: # True branch에 없으면 False branch에 있는지 확인
                                    if (vv, False) not in all_effects:
                                        in_false_branch = False
                                    else:
                                        if (vv, False) in vuln_effect and vuln_effect[(vv, False)] != all_effects[(vv, False)]:
                                            in_false_branch = False
                                if not in_true_branch and not in_false_branch:
                                    logger.info(f"KEY MATCHING FALIED: {vuln_key} and {vv}'s True and False are not in all_effects; {all_effects.keys()}")
                                    test = True
                                    result.append("patch")
                                    break
                            else:
                                if vv not in all_effects[vuln_key]:
                                    logger.info(f"VALUE MATCHING FAILED: all_effects[{vuln_key}] does not contain {vv}; {all_effects[vuln_key]}")
                                    test = True
                                    result.append("patch")
                                    break
                            # if vv not in all_effects: # vv is a Condition, so we check if it is in all_effects
                            #     logger.info(f"KEY MATCHING FALIED: {vuln_key} is not in all_effects; {all_effects.keys()}")
                            #     test = True
                            #     result.append("patch")
                            #     break
            if test:
                continue
        
            # TODO: 테스트 할 방법 찾기
            # for vuln in vuln_effect:
            #     if vuln in all_effects:
            #         vuln_match.append(vuln)
            for vuln_key, vuln_value in vuln_effect.items():
                # vuln_same_key = key_checker(vuln_key, list(all_effects.keys()))
                # if vuln_same_key is not None:
                if vuln_key in all_effects:
                    for vv in vuln_value:
                        # if vv in all_effects[vuln_key]:
                        if vv in all_effects[vuln_key]:
                            vuln_match.append(vv)
            # for patch in patch_effect:                
            #     if patch in all_effects:
            #         patch_match.append(patch)
            for patch_key, patch_value in patch_effect.items():
                # patch_same_key = key_checker(patch_key, list(all_effects.keys()))
                # if patch_same_key is not None:
                if patch_key in all_effects:
                    for pv in patch_value:
                        if pv in all_effects[patch_key]:
                            patch_match.append(pv)
            logger.info(f"vuln match {vuln_match}, patch match {patch_match}")
            # # If the pattern is If, then we should check there at least one condition in matched effect
            # if patch_use_pattern == "If":
            #     # patch_match = [
            #     #     i for i in patch_match if i.ins[0] == "Condition"]
            #     patch_match = [i for i in patch_match if isinstance(i.ins, Effect.Condition)]
            #     if len(patch_match) == 0:
            #         result.append("vuln")
            #         continue
            # if vuln_use_pattern == "If":
            #     # vuln_match = [i for i in vuln_match if i.ins[0] == "Condition"]
            #     vuln_match = [i for i in vuln_match if isinstance(i.ins, Effect.Condition)]
            #     if len(vuln_match) == 0:
            #         result.append("patch")
            #         continue
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