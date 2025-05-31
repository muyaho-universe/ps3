from pyvex.expr import Binop, Unop, Const, Load, IRConst, IRExpr  # …필요한 클래스만 임포트
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
from effect import Effect
from inspect_info import InspectInfo
import pyvex.expr as pe
from refinement import effect_to_node

COMMUTATIVE_OPS = {
    "Iop_Add64", "Iop_Add32", "Add64", "Add32",
    "Iop_Mul64", "Mul64",
}

COMMUTATIVE_OPS = {
    "Iop_Add64", "Iop_Add32", "Add64", "Add32",
    "Iop_Mul64", "Mul64",
}

def unwrap_const(expr):
    """
    Recursively strip Const wrappers that merely wrap another IRExpr /
    SymbolicValue, so AnySymbol 등 내부 노드가 드러나도록 만든다.
    """
    while isinstance(expr, pe.Const) and isinstance(expr.con, (pe.IRExpr, SymbolicValue)):
        expr = expr.con

    # 재귀적으로 하위 노드도 처리
    if isinstance(expr, pe.Unop):
        expr.args = [unwrap_const(expr.args[0])]
    elif isinstance(expr, pe.Binop):
        expr.args = (
            unwrap_const(expr.args[0]),
            unwrap_const(expr.args[1]),
        )
    return expr

# ---------- 1) 단일 식(Expr) 수준 ----------
# def is_generalization_of(g, c, depth=0):
#     tab = "  " * depth  # indent for debugging
#     g = unwrap_const(g)
#     c = unwrap_const(c)
#     # 0) Wildcard
#     if isinstance(g, AnySymbol):
#         # print(f"{tab}AnySymbol matches {c}")
#         return True
#     if isinstance(c, AnySymbol):
#         # print(f"{tab}{c} is AnySymbol (concrete side) – no match")
#         return False

#     # 1) 타입 불일치
#     if type(g) is not type(c):
#         # print(f"{tab}Type mismatch {type(g).__name__} vs {type(c).__name__}")
#         return False

#     # 2) 리프 노드
#     if isinstance(g, (int, str)):
#         ok = g == c
#         # print(f"{tab}Primitive {g} == {c}? {ok}")
#         return ok

#     # ----- 진짜 상수(pyVEX Const / IRConst) -----
#     if isinstance(g, (Const, IRConst)) and not isinstance(g, SymbolicValue):
#         return g.con == c.con

#     # ----- 심볼릭 값(RegSymbol, ReturnSymbol, …) -----
#     if isinstance(g, SymbolicValue):
#         return g == c          # __eq__ 이미 구현됨
#     # 3) Unop
#     if isinstance(g, Unop):
#         same_op = g.op == c.op
#         # print(f"{tab}Unop op {g.op} == {c.op}? {same_op}")
#         return same_op and is_generalization_of(g.args[0], c.args[0], depth+1)

#     # 4) Binop
#     if isinstance(g, Binop):
#         same_op = g.op == c.op
#         # print(f"{tab}Binop op {g.op} == {c.op}? {same_op}")
#         if not same_op:
#             return False
#         # 순서 유지
#         if (is_generalization_of(g.args[0], c.args[0], depth+1) and
#             is_generalization_of(g.args[1], c.args[1], depth+1)):
#             return True
#         # 교환 법칙
#         if g.op in COMMUTATIVE_OPS:
#             return (is_generalization_of(g.args[0], c.args[1], depth+1) and
#                     is_generalization_of(g.args[1], c.args[0], depth+1))
#         return False

#     # 5) Load
#     if isinstance(g, Load):
#         return is_generalization_of(g.addr, c.addr, depth+1)

#     # FakeRet, ReturnSymbol 등 사용자 정의 expr
#     if isinstance(g, ReturnSymbol) and isinstance(c, ReturnSymbol):
#         # 이름이 AnySymbol이면 무조건 일반화
#         if isinstance(g.name, AnySymbol):
#             return True
#         return is_generalization_of(g.name, c.name, depth+1)

#     # …Call, ITE 등 필요한 타입 추가
#     print(f"{tab}Unhandled node type {type(g).__name__}")
#     return False
def is_generalization_of(g, c, depth=0):
    tab = "  " * depth  # indent for debugging
    g = unwrap_const(g)
    c = unwrap_const(c)
    # 0) Wildcard
    if isinstance(g, AnySymbol):
        # print(f"{tab}AnySymbol matches {c}")
        return True
    if isinstance(c, AnySymbol):
        # print(f"{tab}{c} is AnySymbol (concrete side) – no match")
        return False

    # 1) 타입 불일치
    if type(g) is not type(c):
        # print(f"{tab}Type mismatch {type(g).__name__} vs {type(c).__name__}")
        return False

    # 2) 리프 노드
    if isinstance(g, (int, str)):
        ok = g == c
        # print(f"{tab}Primitive {g} == {c}? {ok}")
        return ok

    # ----- 진짜 상수(pyVEX Const / IRConst) -----
    if isinstance(g, (Const, IRConst)) and not isinstance(g, SymbolicValue):
        return g.con == c.con

    # ----- 심볼릭 값(RegSymbol, ReturnSymbol, …) -----
    if isinstance(g, SymbolicValue):
        return g == c          # __eq__ 이미 구현됨
    # 3) Unop
    if isinstance(g, Unop):
        same_op = g.op == c.op
        # print(f"{tab}Unop op {g.op} == {c.op}? {same_op}")
        return same_op and is_generalization_of(g.args[0], c.args[0], depth+1)

    # 4) Binop
    if isinstance(g, Binop):
        same_op = g.op == c.op
        # print(f"{tab}Binop op {g.op} == {c.op}? {same_op}")
        if not same_op:
            return False
        # 순서 유지
        if (is_generalization_of(g.args[0], c.args[0], depth+1) and
            is_generalization_of(g.args[1], c.args[1], depth+1)):
            return True
        # 교환 법칙
        if g.op in COMMUTATIVE_OPS:
            return (is_generalization_of(g.args[0], c.args[1], depth+1) and
                    is_generalization_of(g.args[1], c.args[0], depth+1))
        return False

    # 5) Load
    if isinstance(g, Load):
        return is_generalization_of(g.addr, c.addr, depth+1)

    # …Call, ITE 등 필요한 타입 추가
    print(f"{tab}Unhandled node type {type(g).__name__}")
    return False

# ---------- 2) Effect(예: Put, Condition …) 수준 ----------
def effect_generalization(g, c):
    if type(g) is not type(c):
        return False

    # Put 예시
    if g.__class__.__name__ == "Put":
        # 실제 필드명에 맞추세요 (reg / offset / dst 등)
        dst_g = getattr(g, "reg", getattr(g, "offset", None))
        dst_c = getattr(c, "reg", getattr(c, "offset", None))
        if dst_g != dst_c:
            return False
        return is_generalization_of(g.expr, c.expr)

    # Condition
    if g.__class__.__name__ == "Condition":
        return is_generalization_of(g.expr, c.expr)

    # Call
    if g.__class__.__name__ == "Call":
        return all(is_generalization_of(ga, ca) for ga, ca in zip(g.args, c.args))

    # Store, Return 등 필요시 추가
    return False


def per_related(e1, e2) -> bool:
    """
    Partial Equivalence Relation check:
    e1 R e2  ⇔  e1 ⪰ e2  ∨  e2 ⪰ e1
    """
    return (effect_generalization(e1, e2) or
            effect_generalization(e2, e1))


# Put: 32 = 2 + FakeRet(bn_get_top)
put_concrete = Effect.Put(32, Binop("Iop_Add64",
                    (Const(2),
                     ReturnSymbol("bn_get_top"))))

# Put: 32 = FakeRet(T) + T
put_general  = Effect.Put(32, Binop("Iop_Add64",
                    (ReturnSymbol(AnySymbol()),
                     AnySymbol())))

# Put: 32 = 1 + FakeRet(T)
put_wrong    = Effect.Put(32, Binop("Iop_Add64",
                    (Const(1),
                     ReturnSymbol(AnySymbol()))))


# Put: 32 = 1 + FakeRet(T) But with Const wrapping on return symbol
put_wrap_t    = Effect.Put(32, Binop("Iop_Add64",
                    (Const(1),
                     Const(ReturnSymbol(AnySymbol())))))
# Put: 32 = 1 + FakeRet(T)
put_wrong_concrete    = Effect.Put(32, Binop("Iop_Add64",
                    (Const(1),
                     ReturnSymbol("bn_get_top"))))

# Put: 32 = 2 + FakeRet(bn_get_top)
put_concrete_wrap = Effect.Put(32, Binop("Iop_Add64",
                    (Const(2),
                    Const(ReturnSymbol("bn_get_top")))))



# print("==========================")
# # print("put_wrap_t:", put_wrap_t)
# # print("put_concrete == put_general:", per_related(put_concrete, put_general)) # True
# print("put_concrete == put_wrong:", per_related(put_concrete, put_wrong)) # False
# print("===========================")
# print("put_wrong_concrete == put_wrong:", per_related(put_wrong_concrete, put_wrong)) # True   
# print("===========================")
# print("put_concrete == put_wrong_concrete:", per_related(put_concrete, put_wrong_concrete)) # False
# print("===========================")
# print("put_general == put_concrete:", per_related(put_general, put_concrete)) # True
# print("===========================")
# put_concrete = InspectInfo(put_concrete)
# put_general = InspectInfo(put_general)
# put_wrong = InspectInfo(put_wrong)
# put_wrong_concrete = InspectInfo(put_wrong_concrete)
# # assert not per_related(put_wrong,  put_concrete)  # ✔︎ False
# # print("RALO")

# # print("put_concrete_t:", put_concrete_wrap)
# # print("put_concrete == put_concrete_wrap:", per_related(put_concrete, put_concrete_wrap))  # True
# # print("put_concrete_wrap == put_general:", per_related(put_concrete_wrap, put_general))  # True

# # print("put_general:", put_general)
# print("put_concrete:", put_concrete)
# print("put_wrong:", put_wrong)
# print("put_wrong_concrete:", put_wrong_concrete)
# print("put_general:", put_general)
# print("==========================")
# # print("put_wrap_t:", put_wrap_t)
# # print("put_concrete == put_general:", per_related(put_concrete, put_general)) # True
# print("put_concrete == put_wrong:", put_concrete == put_wrong) # False
# print("===========================")
# print("put_wrong_concrete == put_wrong:", put_wrong_concrete == put_wrong) # True   
# print("===========================")
# print("put_concrete == put_wrong_concrete:", put_concrete == put_wrong_concrete) # False
# print("===========================")
# print("put_general == put_concrete:", put_general == put_concrete) # True
r1 = effect_to_node(put_general)
r2 = effect_to_node(put_concrete)
r1.print()
r2.print()

