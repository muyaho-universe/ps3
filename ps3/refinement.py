from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
from inspect_info import InspectInfo
from copy import deepcopy

def similarity(vuln: Effect, patch: Effect, type) -> int:
    if type == "call":
        score = 0
        for a, b in zip(vuln.args, patch.args):
            score += similarity_expr(a, b)
        return score
    elif type == "condition":
        return similarity_expr(vuln.expr, patch.expr)
    elif type == "return":
        return similarity_expr(vuln.expr, patch.expr)
    elif type == "put":
        return similarity_expr(vuln.reg, patch.reg) + similarity_expr(vuln.expr, patch.expr)
    elif type == "store":
        return similarity_expr(vuln.addr, patch.addr) + similarity_expr(vuln.expr, patch.expr)
    else:
        print(f"Unknown effect type: {type}")
        return 0

def similarity_expr(a, b) -> int:

    if type(a) != type(b):
        return 0

    # Constants
    elif isinstance(a, Const) and isinstance(b, Const):
        
        return similarity_expr(a.con, b.con)

    # Symbolic registers
    elif isinstance(a, RegSymbol) and isinstance(b, RegSymbol):
        # print(f"RegSymbol: {a}, {b}")
        return 1

    # Binary operations
    elif isinstance(a, Binop) and isinstance(b, Binop):
        # print(f"Binop: {a}, {b}")
        if a.op != b.op:
            return 0
        return 1 + similarity_expr(a.args[0], b.args[0]) + similarity_expr(a.args[1], b.args[1])

    # Memory load
    elif isinstance(a, Load) and isinstance(b, Load):
        # print(f"Load: {a}, {b}")
        return 1 + similarity_expr(a.addr, b.addr)

    # Unary operations
    elif isinstance(a, Unop) and isinstance(b, Unop):
        # print(f"Unop: {a}, {b}")
        if a.op != b.op:
            return 0
        return 1 + similarity_expr(a.args[0], b.args[0])
    
    # Memory symbols
    elif isinstance(a, MemSymbol) and isinstance(b, MemSymbol):
        # print(f"MemSymbol: {a}, {b}")
        return 1 + similarity_expr(a.address, b.address)
    
    # IRConst symbols
    elif isinstance(a, IRConst) and isinstance(b, IRConst):
        # print(f"IRConst: {a}, {b}")
        return 1

    elif isinstance(a, int) and isinstance(b, int):
        # print(f"Int: {a}, {b}")
        return 1 if a == b else 0
    elif isinstance(a, str) and isinstance(b, str):
        # print(f"Str: {a}, {b}")
        return 1 if a == b else 0

    else:
        print(f"Unknown expression type: {type(a)}")
        print(f"Unknown expression type: {type(b)}")
        print(f"Unknown expression: {a}")
        print(f"Unknown expression: {b}")
        exit(1)
    return 0


def possible_subs(expr, results=[]):
    one_level_results = []

    if isinstance(expr, IRExpr):
        print(f"In possible_subs, IRExpr: {expr}")
        if isinstance(expr, Binop):
            print("Binop")
            # self.op_int = op_int
            # self.args = args
            for arg in expr.args:
                possible_subs(arg, one_level_results)
            
        elif isinstance(expr, Unop):
            print("Unop")
            # self.op = op
            # self.args = args
            for arg in expr.args:
                possible_subs(arg, one_level_results)
        elif isinstance(expr, Load):
            print(f"Load: type(end): {type(expr.end)}, type(expr.ty): {type(expr.ty)}, type(addr): {type(expr.addr)}")
            # self.end = end
            # self.ty = ty
            # self.addr = addr
            possible_subs(expr.addr, one_level_results)

        elif isinstance(expr, ITE):
            print("ITE")
            # self.cond = cond
            # self.iffalse = iffalse
            # self.iftrue = iftrue
            possible_subs(expr.cond, one_level_results)
        elif isinstance(expr, CCall):
            print(f"CCall, type(expr.retty): {type(expr.retty)}, type(expr.cee): {type(expr.cee)}")
            # self.retty = retty
            # self.cee = cee
            # self.args = tuple(args)

            for arg in expr.args:
                possible_subs(arg, one_level_results)
            
        elif isinstance(expr, RdTmp):
            print("RdTmp")
        elif isinstance(expr, Get):
            print("Get")
            # self.offset = offset
            # if ty_int is None:
            #     self.ty_int = get_int_from_enum(ty)
            # else:
            #     self.ty_int = ty_int
            possible_subs(expr.offset, one_level_results)
        elif isinstance(expr, Const):
            print("Const")
            possible_subs(expr.con)

        
        else:
            print(f"Unknown expression type: {type(expr)}")
            exit(1)
            return results
    
    elif isinstance(expr, IRConst):
        print("IRConst")
        # self._value = value
        possible_subs(expr.value)
    
    elif isinstance(expr, SymbolicValue):
        print(f"In possible_subs, SymbolicValue: {expr}")
        if isinstance(expr, AnySymbol):
            print("AnySymbol")
        elif isinstance(expr, RegSymbol):
            print("RegSymbol")
            # self.offset = offset
            possible_subs(expr.offset)
        elif isinstance(expr, ReturnSymbol):
            print("ReturnSymbol")
            # self.name = name
            # self.order = ReturnSymbol.order    
            possible_subs(expr.name)
        elif isinstance(expr, MemSymbol):
            print("MemSymbol")
            # self.address = address
            possible_subs(expr.address)
        else:
            print(f"Unknown expression type: {type(expr)}")
            exit(1)
            return results
        
    elif isinstance(expr, int):
        print(f"In possible_subs, int: {expr}")
        results.append(expr)
        return results
    elif isinstance(expr, str):
        print(f"In possible_subs, str: {expr}")
        results.append(expr)
        return results
    else:
        print(f"In possible_subs, unknown type: {type(expr)}")
        exit(1)
        # return results

def refine_pair(vuln: Effect, patch: Effect) -> tuple[InspectInfo, InspectInfo]:

    if isinstance(vuln, Effect.Call):
        # self.name = name -> str
        # self.args = args -> list[IRExpr]
        # print(f"vuln's effect: {vuln} is a call")
        for arg in vuln.args:
            possible_subs(arg)
    elif isinstance(vuln, Effect.Condition):
        # self.expr = expr -> pyvex.expr
        # print(f"vuln's effect: {vuln} is a condition")
        possible_subs(vuln.expr)
        
    elif isinstance(vuln, Effect.Put):
        # self.reg = reg -> int
        # self.expr = expr -> pyvex.expr
        # print(f"vuln's effect: {vuln} is a put")
        possible_subs(vuln.expr)
    elif isinstance(vuln, Effect.Store):
        # self.addr = addr -> pyvex.expr
        # self.expr = expr -> pyvex.expr
        # print(f"vuln's effect: {vuln} is a store")
        possible_subs(vuln.addr)
        possible_subs(vuln.expr)
    elif isinstance(vuln, Effect.Return):
        # self.expr = expr
        # print(f"vuln's effect: {vuln} is a return")
        possible_subs(vuln.expr)
    else:
        print(f"Unknown effect type: {type(vuln)}")
        exit(1)
        return (InspectInfo(vuln), InspectInfo(patch))

    # print(f"possible_subs: {expr}, type: {type(expr)}")
    # vuln_lattice = possible_subs(expr)
    # for i in vuln_lattice:
    #     print(f"vuln_lattice: {i}, type: {type(i)}")

    # exit(1)
    return (InspectInfo(vuln), InspectInfo(patch))

def refine_sig(vuln_effect: list[InspectInfo], patch_effect: list[InspectInfo]) -> tuple[list[InspectInfo], list[InspectInfo]]:
    refined_vuln = []
    refined_patch = []
    info_type = ["call", "condition", "return", "put", "store"]
    mode = ["add", "remove"]

    pair_dict = {"call": {"add": [], "remove":[]}, "condition": {"add": [], "remove":[]}, "return": {"add": [], "remove":[]}, "put": {"add": [], "remove":[]}, "store": {"add": [], "remove":[]}}

    for i in vuln_effect:
        if isinstance(i.ins, Effect.Call):
            pair_dict["call"]["remove"].append(i.ins)
        elif isinstance(i.ins, Effect.Condition):
            pair_dict["condition"]["remove"].append(i.ins)
        elif isinstance(i.ins, Effect.Return):
            pair_dict["return"]["remove"].append(i.ins)
        elif isinstance(i.ins, Effect.Put):
            pair_dict["put"]["remove"].append(i.ins)
        elif isinstance(i.ins, Effect.Store):
            pair_dict["store"]["remove"].append(i.ins)
        else:
            print(f"Unknown effect type: {type(i.ins)}")

    for i in patch_effect:
        if isinstance(i.ins, Effect.Call):
            pair_dict["call"]["add"].append(i.ins)
        elif isinstance(i.ins, Effect.Condition):
            pair_dict["condition"]["add"].append(i.ins)
        elif isinstance(i.ins, Effect.Return):
            pair_dict["return"]["add"].append(i.ins)
        elif isinstance(i.ins, Effect.Put):
            pair_dict["put"]["add"].append(i.ins)
        elif isinstance(i.ins, Effect.Store):
            pair_dict["store"]["add"].append(i.ins)
        else:
            print(f"Unknown effect type: {type(i.ins)}")

    # print(f"pair_dict: {pair_dict}")

    # 1. calculate the similarity of each effect
    
    similarity_dict = {}
    for type in info_type:
        if len(pair_dict[type]["add"]) == 0 or len(pair_dict[type]["remove"]) == 0:
            continue
        for remove in pair_dict[type]["remove"]:
            for add in pair_dict[type]["add"]:
                score = similarity(remove, add, type)
                if score > 0:
                    key = str(remove)
                    if key not in similarity_dict:
                        similarity_dict[key] = (remove, add, score)
                    else:
                        # if score is greater than the current score, update it
                        if similarity_dict[key][2] < score:
                            similarity_dict[key] = (remove, add, score)
                    # print(f"similarity_dict: {similarity_dict}")

    # print(f"similarity_dict: {similarity_dict}")
    # 2. refine the signature: 가장 높은 유사도를 가진 pair 들만 refine
    for key in similarity_dict:
        remove, add, _ = similarity_dict[key]
        ref_vuln, ref_patch = refine_pair(remove, add)
        refined_vuln.append(ref_vuln)
        refined_patch.append(ref_patch)
    
        
    return refined_vuln, refined_patch    