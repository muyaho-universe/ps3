import pyvex
import pyvex.expr as pe
from symbol_value import AnySymbol
from simplify import simplify
import node

def expr_to_str(expr):
    from pyvex.expr import Const, Binop, Unop, Load, ITE, Get, RdTmp

    if isinstance(expr, Const):
        if hasattr(expr, "con") and expr.con.__class__.__name__ == "AnySymbol":
            return "T"
        return str(expr.con)
    
    if isinstance(expr, Binop):
        op = expr.op.split("_")[-1]  # 예: Iop_Add64 → Add64
        left = expr_to_str(expr.args[0])
        right = expr_to_str(expr.args[1])
        return f"{left} + {right}" if "Add" in op else f"{op}({left}, {right})"

    if isinstance(expr, Unop):
        return f"{expr.op}({expr_to_str(expr.args[0])})"

    if isinstance(expr, Load):
        return f"Load({expr_to_str(expr.addr)})"

    if isinstance(expr, ITE):
        return f"ITE({expr_to_str(expr.cond)}, {expr_to_str(expr.iftrue)}, {expr_to_str(expr.iffalse)})"

    if isinstance(expr, Get):
        return f"SR({expr.offset})"

    if isinstance(expr, RdTmp):
        return f"t{expr.tmp}"

    return str(expr)


class Effect:
    class Call:
        # pyvex.expr in list
        def __init__(self, name: str, args: list):
            self.name = name
            self.args = args
            # print("Inside Effect.Call")
            # print(f"name: {name}, type: {type(name)}")
            # print(f"args: {args}, type: {type(args)}")

        def __eq__(self, other):
            if isinstance(other, Effect.Call):
                if self.name == other.name:
                    for arg1, arg2 in zip(self.args, other.args):
                        if isinstance(arg1, AnySymbol) or isinstance(arg2, AnySymbol):
                            continue
                        elif arg1 == arg2:
                            continue
                        else:
                            return False
                    return True
                else:
                    return False
            return False

        def __hash__(self):
            return hash((self.name, tuple(self.args)))

        def __str__(self):
            args_str = ", ".join(expr_to_str(arg) for arg in self.args)
            return f"Call({self.name}, [{args_str}])"

        
    class Condition:
        def __init__(self, expr: pyvex.expr):
            self.expr = expr
            # print("Inside Effect.Condition")
            # print(f"expr: {expr}, type: {type(expr)}")

        def __eq__(self, other):
            # return isinstance(other, Effect.Condition) and self.expr == other.expr
            if isinstance(other, Effect.Condition):
                # print(f"self.expr: {self.expr}, type: {type(self.expr)}")
                # print(f"other.expr: {other.expr}, type: {type(other.expr)}")
            
                return equal_with_top(self.expr, other.expr)
            return False

        def __hash__(self):
            return hash(("Condition", self.expr))

        def __str__(self):
            return f"Condition({expr_to_str(self.expr)})"

    class Return:
        def __init__(self, expr):
            self.expr = expr
            # print("Inside Effect.Return")
            # print(f"expr: {expr}, type: {type(expr)}")

        def __eq__(self, other):
            # return isinstance(other, Effect.Return) and self.expr == other.expr
            if isinstance(other, Effect.Return):
                if isinstance(self.expr, AnySymbol) or isinstance(other.expr, AnySymbol):
                    return True
                return self.expr == other.expr

        def __hash__(self):
            return hash(("Return", self.expr))

        def __str__(self):
            return f"Return({expr_to_str(self.expr)})"
        
    class Put:
        def __init__(self, reg: int, expr: pyvex.expr):
            self.reg = reg
            self.expr = expr
            # print("Inside Effect.Put")
            # print(f"reg: {reg}, type: {type(reg)}")
            # print(f"expr: {expr}, type: {type(expr)}")

        def __eq__(self, other):
            # return isinstance(other, Effect.Put) and self.reg == other.reg and self.expr == other.expr
            if isinstance(other, Effect.Put):
                if self.reg == other.reg:
                    if isinstance(self.expr, AnySymbol) or isinstance(other.expr, AnySymbol):
                        return True
                    return self.expr == other.expr
                else:
                    return False

        def __hash__(self):
            return hash(("Put", self.reg, self.expr))

        def __str__(self):
            return f"Put(reg{self.reg}, {expr_to_str(self.expr)})"
        
    class Store:
        def __init__(self, addr: pyvex.expr, expr: pyvex.expr):
            self.addr = addr
            self.expr = expr
            # print("Inside Effect.Store")
            # print(f"addr: {addr}, type: {type(addr)}")
            # print(f"expr: {expr}, type: {type(expr)}")
            # print(f"expr.const: {expr.con}, type: {type(expr.con)}")

        def __eq__(self, other):
            # return isinstance(other, Effect.Store) and self.addr == other.addr and self.expr == other.expr
            if isinstance(other, Effect.Store):
                if isinstance(self.addr, AnySymbol) or isinstance(other.addr, AnySymbol):
                    if isinstance(self.expr, AnySymbol) or isinstance(other.expr, AnySymbol):
                        return True
                    return self.expr == other.expr
                return self.addr == other.addr and self.expr == other.expr
        def __hash__(self):
            return hash(("Store", self.addr, self.expr))

        def __str__(self):
            return f"Store: {expr_to_str(self.addr)} = {expr_to_str(self.expr)}"
        
def equal_with_top(a, b):
    
    if isinstance(a, AnySymbol) or isinstance(b, AnySymbol):
        print(f"a or b is AnySymbol: {a}, {b}")
        return True
    a = simplify(a)
    b = simplify(b)
    print(f"Comparing: {a}:{type(a)} and {b}:{type(b)}")
    
    if type(a) != type(b):
        return False
    if isinstance(a, pe.Binop):
        return (a.op == b.op and
                equal_with_top(a.args[0], b.args[0]) and
                equal_with_top(a.args[1], b.args[1]))
    if isinstance(a, pe.Unop):
        return a.op == b.op and equal_with_top(a.args[0], b.args[0])
    if isinstance(a, pe.ITE):
        return (equal_with_top(a.cond, b.cond) and
                equal_with_top(a.iftrue, b.iftrue) and
                equal_with_top(a.iffalse, b.iffalse))
    if isinstance(a, pe.Const):
        if isinstance(a.con, AnySymbol) or isinstance(b.con, AnySymbol):
            return True
        return equal_with_top(a.con, b.con)

    # 이 아래 추가!
    if isinstance(a, pe.IRConst) or isinstance(b, pe.IRConst):
        if isinstance(a, AnySymbol) or isinstance(b, AnySymbol):
            return True
        return getattr(a, "_value", None) == getattr(b, "_value", None)
    if isinstance(a, pe.IRConst):
        return a._value == b._value
    if isinstance(a, int) or isinstance(a, str):
        return a == b
    return a == b