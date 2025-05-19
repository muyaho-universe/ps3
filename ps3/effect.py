import pyvex
import pyvex.expr as pe

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
            return isinstance(other, Effect.Call) and self.name == other.name and self.args == other.args

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
            return isinstance(other, Effect.Condition) and self.expr == other.expr

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
            return isinstance(other, Effect.Return) and self.expr == other.expr

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
            return isinstance(other, Effect.Put) and self.reg == other.reg and self.expr == other.expr

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
            return isinstance(other, Effect.Store) and self.addr == other.addr and self.expr == other.expr

        def __hash__(self):
            return hash(("Store", self.addr, self.expr))

        def __str__(self):
            return f"Store: {expr_to_str(self.addr)} = {expr_to_str(self.expr)}"
        
    class Any:
        def __init__(self):
            pass

        def __eq__(self, other):
            return True

        def __hash__(self):
            return hash("Any")

        def __str__(self):
            return "T"