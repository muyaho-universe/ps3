from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
from inspect_info import InspectInfo
from typing import Iterator
from copy import deepcopy
from simplify import simplify, equal

t = InspectInfo(Effect.Put(64 , Binop("Iop_Add64", (AnySymbol(), 1))))
q = InspectInfo(Effect.Put(64 , Binop("Iop_Add64", (1, 2))))
a = t == q
# t = simplify(Binop("Iop_Add64", (AnySymbol(), AnySymbol())))
# q = simplify(Binop("Iop_Add64", (1, 2)))
# a = equal(t, q)
print(a)