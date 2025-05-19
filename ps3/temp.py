from pyvex.expr import IRExpr, Binop, Const
from symbol_value import AnySymbol
from effect import Effect
from inspect_info import InspectInfo
from pyvex.expr import Binop, Const
from symbol_value import RegSymbol
from effect import Effect


# Traversing the effect tree
# Store: 64 = 56 + SR(72)

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
    elif isinstance(expr, Const):
        print(f"Const: {expr}")

    elif isinstance(expr, AnySymbol):
        print(f"AnySymbol: {expr}")

    elif isinstance(expr, RegSymbol):
        print(f"RegSymbol: {expr}")

    elif isinstance(expr, Effect):
        print(f"Effect: {expr}")
        
    elif isinstance(expr, str):
        print(f"String: {expr}")
    else:
        print(f"Unknown expression type: {type(expr)}")



# 56 + SR(72)
expr1 = 64
expr2 = Binop("Iop_Add64", [AnySymbol(), Const(RegSymbol(72))])
eff = Effect.Store(expr1, expr2)
print(f"Original Effect: {eff}")

# Traverse the effect tree
print("Traversing the effect tree:")
traverse_effect(eff)

# abstracts = abstract_effect(eff)
# print(f"Abstracted Effects:")
# for a in abstracts:
#     print(a)
