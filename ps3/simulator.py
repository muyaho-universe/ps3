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
import lief
from settings import *
from refinement import refine_sig


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
    def __init__(self, proj: angr.Project, symbol=None) -> None:
        self.proj = proj
        self.symbol = symbol

    def _init_function(self, funcname: str):
        symbol = self.proj.loader.find_symbol(funcname)
        if symbol is None:
            if self.symbol is not None:
                symbol = self.symbol
            else: 
                raise FunctionNotFound(
                    f"symbol {funcname} not found in binary {self.proj}")
        self.funcname = funcname
        # print(f"symbol.size: {symbol.size}")
        
        cfg = self.proj.analyses.CFGFast(
            regions=[(symbol.rebased_addr, symbol.rebased_addr + symbol.size)],
            normalize=True,
            force_complete_scan=True,
            force_smart_scan=False
        )
        
        function = None

        for func in cfg.functions:
            if cfg.functions[func].name == 'sub_400000':
                cfg.functions[func].name = funcname
                function = cfg.functions[func]
                break
            if cfg.functions[func].name == funcname:
                function = cfg.functions[func]
                break
        # print(f"function: {function}")
        # assert function is not None
        if function is None:
            logger.error(f"function {funcname} not found in binary {self.proj}")
            raise FunctionNotFound(
                f"function {funcname} not found in binary {self.proj}")
        
        self.graph = cfg.graph

        self.cfg = cfg
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

    def _reachable_set(self, addrs: set[int]) -> set:
        # print("in _reachable_set")
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
        # print("in _reduce_addresses_by_basicblock")
        l = list(self.function.blocks)
        result = set()
        for addr in address:
            for block in l:
                if addr in block.instruction_addrs:
                    result.add(block.addr)
                    break
        return result

    def generate_forall_bb(self, funcname: str, dic) -> dict:
        # print("in generate_forall_bb")
        try: 
            self._init_function(funcname)
        except FunctionNotFound:
            raise FunctionNotFound(f"function {funcname} not found in binary {self.proj}")
        all_addrs = []
        collect = {}
        for block in self.function.blocks:
            all_addrs.extend(block.instruction_addrs)
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
        return collect

    def generate(self, funcname: str, addresses: list[int], patterns) -> dict:
        # print("in Simulator generate")
        if addresses[0] < self.proj.loader.main_object.min_addr:
            addresses = [(addr + self.proj.loader.main_object.min_addr)
                         for addr in addresses]
        self._init_function(funcname)
        trace = {}
        reduce_addr = set(self._reduce_addresses_by_basicblock(addresses))
        reachable = self._reachable_set(reduce_addr)
        start_node = self.cfg.get_any_node(self.function.addr)
        self.inspect_addrs = addresses
        init_state = State(start_node, Environment())
        # based on basic block inspect
        init_state.inspect = {addr: {} for addr in reduce_addr}
        init_state.inspect_patterns = patterns
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
        return trace

    def _simulateBB(self, state: State, step_one=False) -> list[State] | State:
        # print("in _simulateBB")
        # print(f"state.env: {state.env.show()}")
        while 1:
            state.addrs.append(state.node.addr)
            # print("=========================================")
            # logger.info("=========================================")
            # state.env.show_regs()
            # logger.info("=========================================")
            # state.env.show_mems()
            # logger.info("=========================================\n")
            # print("=========================================")
            # state.env.show_regs()
            # print("=========================================")
            # a = state.node.block.vex._pp_str()
            # print("a:",a)
            # for stmt in self.node2IR[state.node]:
            #     logger.info(f"stmt: {stmt}")
            # time.sleep(10)
            
            # input()
            for stmt in self.node2IR[state.node]:
                machine_addr = self.IR2addr[stmt]                
                if machine_addr in self.inspect_addrs:
                    # logger.info(f"machine_addr is in inspect_addrs: {hex(machine_addr)}")
                    
                    # when Exit stmt, return guard, else return tuple) else return None
                    cond = stmt.simulate(state.env, True)
                    # if cond is not None:
                       
                    #     print(f"cond: {cond}")
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
                    cond = stmt.simulate(state.env)
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
        ser = self._serial(collect)
        # print(f"ser: {ser}")
        for single_site in ser[0]:
            # print(single_site)
            logger.info(single_site)
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
            # time.sleep(10)
        except FunctionNotFound:
            print(f"FunctionNotFound: {funcname}")
            return None
        result = []
        # test one hunk's signature
        for sig in sigs:
            if sig.state == "vuln":
                vuln_effect, _ = sig.serial()
                patch_effect = []
                vuln_pattern, patch_pattern = sig.patterns, Patterns([])
            elif sig.state == "patch":
                vuln_effect = []
                patch_effect, _ = sig.serial()
                vuln_pattern, patch_pattern = Patterns([]), sig.patterns
            elif sig.state == "modify":
                if sig.sig_dict["add"] == [] and sig.sig_dict["remove"] == []:
                    vuln_info, patch_info = sig.serial()
                    vuln_effect, _ = vuln_info
                    patch_effect, _ = patch_info
                    
                    vuln_effect = set(vuln_effect)
                    patch_effect = set(patch_effect)
                    
                    vuln_effect, patch_effect = vuln_effect-patch_effect, patch_effect-vuln_effect
                    vuln_effect = list(vuln_effect)
                    patch_effect = list(patch_effect)

                    # TODO: 여기서 refinement
                    if vuln_effect != [] and patch_effect != []:    
                        vuln_effect, patch_effect = refine_sig(vuln_effect, patch_effect)
                    sig.sig_dict["add"] = patch_effect
                    sig.sig_dict["remove"] = vuln_effect
                else:
                    vuln_effect, patch_effect = sig.sig_dict["remove"], sig.sig_dict["add"]

                vuln_pattern, patch_pattern = sig.patterns[0], sig.patterns[1]
            else:
                raise NotImplementedError(f"{sig.state} is not considered.")
            vuln_use_pattern, patch_use_pattern = self.use_pattern(
                vuln_pattern), self.use_pattern(patch_pattern)
            vuln_effect = set(vuln_effect)
            patch_effect = set(patch_effect)
            
            vuln_effect, patch_effect = vuln_effect-patch_effect, patch_effect-vuln_effect
            
            if len(vuln_effect) == 0 and len(patch_effect) == 0:
                continue
            # logger.info(f"vuln_effect: {vuln_effect}")
            # logger.info(f"patch_effect: {patch_effect}")
            vuln_match, patch_match = [], []
            all_effects = extrace_effect(traces)
            # logger.info(f"all_effects: {set(all_effects)}")
            # logger.info(f"all_effects: {sorted(str(InspectInfo(i)) for i in all_effects)}")
            # exit(0)
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
                for patch in patch_effect:
                    # if (patch.ins[0] == "Condition" or patch.ins[0] == "Call") and patch not in all_effects:
                    if isinstance(patch.ins, (Effect.Condition, Effect.Call)) and patch not in all_effects:
                        test = True
                        result.append("vuln")
                        break
            # essential a vuln patch
            if len(patch_effect) == 0:
                # logger.info("pure deletion")
                for vuln in vuln_effect:
                    # if (vuln.ins[0] == "Condition" or vuln.ins[0] == "Call") and vuln not in all_effects:
                    if isinstance(vuln.ins, (Effect.Condition, Effect.Call)) and vuln not in all_effects:
                        test = True
                        # logger.info(f"vuln {vuln} is not in all_effects")
                        result.append("patch")
                        break
            # else:
            #     logger.info("modify")
            if test:
                continue
            for vuln in vuln_effect:
                if vuln in all_effects:
                    vuln_match.append(vuln)
            for patch in patch_effect:
                # print(f"patch: {InspectInfo(patch)}, is in all_effects: {patch in all_effects}")
                # print(f"type(patch): {type(patch)}, type(all_effects[0]): {type(all_effects[0])}")
                if patch in all_effects:
                    # for i in all_effects:
                    #     if i == patch:
                    #         logger.info(f"patch {i} is in all_effects")
                    #         i.show_eq(patch)
                    patch_match.append(patch)
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
