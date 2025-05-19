from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol
from inspect_info import InspectInfo

def traverse_effect(effect: Effect):
    if isinstance(effect, Effect.Store):
        print(f"Store: {effect.addr} = {effect.expr}")
        traverse_expr(effect.addr)
        traverse_expr(effect.expr)

    elif isinstance(effect, Effect.Call):
        print(f"Call: {effect.name}({', '.join(map(str, effect.args))})")
        for arg in effect.args:
            traverse_expr(arg)
    elif isinstance(effect, Effect.Condition):
        print(f"Condition: {effect.expr}")
        traverse_expr(effect.expr)
    elif isinstance(effect, Effect.Return):
        print(f"Return: {effect.expr}")
        traverse_expr(effect.expr)
    elif isinstance(effect, Effect.Put):
        print(f"Put: {effect.reg} = {effect.expr}")
        traverse_expr(effect.reg)
        traverse_expr(effect.expr)

def traverse_expr(expr: IRExpr):
    if isinstance(expr, Binop):
        print(f"Binop: {expr.op}({', '.join(map(str, expr.args))})")
        for arg in expr.args:
            traverse_expr(arg)
    
    elif isinstance(expr, MemSymbol):
        print(f"MemSymbol: {expr}")
    elif isinstance(expr, ReturnSymbol):
        print(f"ReturnSymbol: {expr}")
    elif isinstance(expr, AnySymbol):
        print(f"AnySymbol: {expr}")

    elif isinstance(expr, RegSymbol):
        print(f"RegSymbol: {expr}")

    elif isinstance(expr, Effect):
        print(f"Effect: {expr}")
    
    elif isinstance(expr, Unop):
        print(f"Unop: {expr.op}({', '.join(map(str, expr.args))})")
        for arg in expr.args:
            traverse_expr(arg)
    elif isinstance(expr, Const):
        # expr = AnySymbol()
        print(f"Const: {expr}")
    
        
    elif isinstance(expr, str):
        print(f"String: {expr}")

    elif isinstance(expr, int):
        print(f"Integer: {expr}")
    else:
        print(f"Unknown expression type: {type(expr)}")


def similarity(vuln: Effect, patch: Effect, type) -> int:
    if type == "call":
        score = 1
        for a, b in zip(vuln.args, patch.args):
            score += similarity_expr(a, b)
        return score
    elif type == "condition":
        return 1 + similarity_expr(vuln.expr, patch.expr)
    elif type == "return":
        return 1 + similarity_expr(vuln.expr, patch.expr)
    elif type == "put":
        return 1 + similarity_expr(vuln.reg, patch.reg) + similarity_expr(vuln.expr, patch.expr)
    elif type == "store":
        return 1 + similarity_expr(vuln.addr, patch.addr) + similarity_expr(vuln.expr, patch.expr)
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
        print(f"RegSymbol: {a}, {b}")
        return 1

    # Binary operations
    elif isinstance(a, Binop) and isinstance(b, Binop):
        print(f"Binop: {a}, {b}")
        if a.op != b.op:
            return 0
        return 1 + similarity_expr(a.args[0], b.args[0]) + similarity_expr(a.args[1], b.args[1])

    # Memory load
    elif isinstance(a, Load) and isinstance(b, Load):
        print(f"Load: {a}, {b}")
        return 1 + similarity_expr(a.addr, b.addr)

    # Unary operations
    elif isinstance(a, Unop) and isinstance(b, Unop):
        print(f"Unop: {a}, {b}")
        if a.op != b.op:
            return 0
        return 1 + similarity_expr(a.args[0], b.args[0])
    
    # Memory symbols
    elif isinstance(a, MemSymbol) and isinstance(b, MemSymbol):
        print(f"MemSymbol: {a}, {b}")
        return 1 + similarity_expr(a.address, b.address)
    
    # IRConst symbols
    elif isinstance(a, IRConst) and isinstance(b, IRConst):
        print(f"IRConst: {a}, {b}")
        return 1

    else:
        print(f"Unknown expression type: {type(a)}")
        print(f"Unknown expression type: {type(b)}")
        print(f"Unknown expression: {a}")
        print(f"Unknown expression: {b}")
        exit(1)
    return 0

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

    # 2. refine the signature: 가장 높은 유사도를 가진 pair 들만 refine
    print(f"similarity_dict: {similarity_dict}")
        
    return vuln_effect, patch_effect    