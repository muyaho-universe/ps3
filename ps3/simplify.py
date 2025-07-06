import pyvex.expr as pe
import pyvex.const as pc
from symbol_value import RegSymbol, ReturnSymbol, MemSymbol, AnySymbol
import z3
from pyvex.expr import Binop, Unop, Const, Load, IRConst, IRExpr  # …필요한 클래스만 임포트
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
from effect import Effect

mapfunction = z3.Function("Mem", z3.BitVecSort(64), z3.BitVecSort(64))

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
def is_generalization_of(g, c, depth=0):
    tab = "  " * depth  # indent for debugging
    # print(f"{tab}Before unwrap, is_generalization_of: {type(g)} {g} vs {type(c)} {c} (depth={depth})")
    g = unwrap_const(g)
    c = unwrap_const(c)
    # print(f"{tab}After unwrap, is_generalization_of: {type(g)} {g} vs {type(c)} {c} (depth={depth})")
    if isinstance(g, pe.Const) and isinstance(c, int):
        # Const는 int로 취급
        g = g.con

    if isinstance(c, pe.Const) and isinstance(g, int):
        # Const는 int로 취급
        c = c.con
    # print(f"{tab}RALO: {type(g)} {g} vs {type(c)} {c} (depth={depth})")    
    # 0) Wildcard
    if isinstance(g, AnySymbol):
        # print(f"{tab}AnySymbol matches {c}")
        return True
    if isinstance(c, AnySymbol):
        # print(f"{tab}{c} is AnySymbol (concrete side) – no match")
        return False
    # # Unop
    # if isinstance(g, Unop) and isinstance(g.args[0], AnySymbol):
    #     return True
    # if isinstance(c, Unop) and isinstance(c.args[0], AnySymbol):
    #     return False
    # # Binop
    # if isinstance(g, Binop) and (isinstance(g.args[0], AnySymbol) or isinstance(g.args[1], AnySymbol)):
    #     return True
    # if isinstance(c, Binop) and (isinstance(c.args[0], AnySymbol) or isinstance(c.args[1], AnySymbol)):
    #     return False
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
        # print(f"{tab}Const/IRConst: {g} == {c}? {g.con == c.con}")
        return g.con == c.con

    # ----- 심볼릭 값(RegSymbol, ReturnSymbol, MemSymbol 등) -----
    if isinstance(g, MemSymbol) and isinstance(c, MemSymbol):
        # print(f"{tab}MemSymbol: {g} vs {c} (compare address)")
        return is_generalization_of(g.address, c.address, depth+1)
    if isinstance(g, RegSymbol) and isinstance(c, RegSymbol):
        # print(f"{tab}RegSymbol: {g} vs {c} (compare offset)")
        return is_generalization_of(g.offset, c.offset, depth+1)
    if isinstance(g, ReturnSymbol) and isinstance(c, ReturnSymbol):
        # print(f"{tab}ReturnSymbol: {g} vs {c} (compare name)")
        return is_generalization_of(g.name, c.name, depth+1)
    # 기존 SymbolicValue 분기(위 세 타입이 아닌 경우만)
    if isinstance(g, SymbolicValue):
        # print(f"{tab}SymbolicValue: {g} == {c}? {g == c}")
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
            # print(f"{tab}Binop op mismatch: {g.op} vs {c.op}")
            return False
        # 순서 유지
        # print(f"{tab}Binop args: {g.args}, {g.args[0]},  {g.args[1]} vs {c.args}, {c.args[0]},  {c.args[1]}")
        t = (is_generalization_of(g.args[0], c.args[0], depth+1) and
            is_generalization_of(g.args[1], c.args[1], depth+1))
        # print(f"{tab}Binop args match? {t}")
        if t:
            return True
        # 교환 법칙
        if g.op in COMMUTATIVE_OPS:
            # print(f"{tab}Checking commutative match for {g.op}")
            t = (is_generalization_of(g.args[0], c.args[1], depth+1) and
                    is_generalization_of(g.args[1], c.args[0], depth+1))
            # print(f"{tab}Commutative match? {t}")
            return t
        # print(f"{tab}Binop args do not match: {g.args} vs {c.args}")
        return False

    # 5) Load
    if isinstance(g, Load):
        # print(f"{tab}Load: {g.addr} vs {c.addr}")
        t = is_generalization_of(g.addr, c.addr, depth+1)
        # print(f"{tab}Load addr match? {t}")
        return t

    # 6) ITE (If-Then-Else)
    if hasattr(pe, "ITE") and isinstance(g, pe.ITE) and isinstance(c, pe.ITE):
        # print(f"{tab}ITE: {g.cond} vs {c.cond}, {g.iftrue} vs {c.iftrue}, {g.iffalse} vs {c.iffalse}")
        t = (
            is_generalization_of(g.cond, c.cond, depth+1) and
            is_generalization_of(g.iftrue, c.iftrue, depth+1) and
            is_generalization_of(g.iffalse, c.iffalse, depth+1)
        )
        # print(f"{tab}ITE match? {t}")
        return t

    # 7) Call (pyvex.expr.CCall)
    if hasattr(pe, "CCall") and isinstance(g, pe.CCall) and isinstance(c, pe.CCall):
        # 함수명과 인자 수가 같아야 함
        if getattr(g, "cee", None) != getattr(c, "cee", None):
            # print(f"{tab}CCall cee mismatch: {g.cee} vs {c.cee}")
            return False
        if len(g.args) != len(c.args):
            # print(f"{tab}CCall arg count mismatch: {len(g.args)} vs {len(c.args)}")
            return False
        t = all(is_generalization_of(ga, ca, depth+1) for ga, ca in zip(g.args, c.args))
        return t

    # print(f"{tab}Unhandled node type {type(g).__name__}")
    return False

# ---------- 2) Effect(예: Put, Condition …) 수준 ----------
def effect_generalization(g, c):
    if type(g) is not type(c):
        # print(f"Type mismatch: {type(g).__name__} vs {type(c).__name__}")
        return False

    # Put 예시
    if isinstance(g, Effect.Put):
        dst_g = getattr(g, "reg", getattr(g, "offset", None))
        dst_c = getattr(c, "reg", getattr(c, "offset", None))
        if dst_g != dst_c:
            # print(f"Destination mismatch: {dst_g} vs {dst_c}")
            return False
        t = is_generalization_of(g.expr, c.expr)
        # print(f"Put: {dst_g} vs {dst_c}, checking exprs, result: {t}")
        return t
    # Condition
    if isinstance(g, Effect.Condition):
        t = is_generalization_of(g.expr, c.expr)
        # print(f"Condition: {g.expr} vs {c.expr}, result: {t}")
        return t

    # Call
    if isinstance(g, Effect.Call):
        # 각 인자 쌍이 한쪽이 다른 쪽을 일반화하거나, 반대도 일반화하면 True
        t = all(
            # print(f"Comparing args: {ga} and {ca} / {is_generalization_of(ga, ca)} and {is_generalization_of(ca, ga)}") or
            is_generalization_of(ga, ca) or is_generalization_of(ca, ga)
            for ga, ca in zip(g.args, c.args)
        )
        # print(f"Call: {g.args} vs {c.args}, result: {t}")
        return t
    # Store
    if isinstance(g, Effect.Store):
        # Store는 addr, value 모두 비교
        t = (is_generalization_of(g.addr, c.addr) and
                is_generalization_of(g.expr, c.expr))
        # print(f"Store: {g.addr} vs {c.addr}, {g.value} vs {c.value}, result: {t}")
        return t
    # Store, Return 등 필요시 추가
    # print(f"Unhandled Effect type: {type(g).__name__}")
    return False


def per_related(e1, e2) -> bool:
    """
    Partial Equivalence Relation check:
    e1 R e2  ⇔  e1 ⪰ e2  ∨  e2 ⪰ e1
    """
    return (effect_generalization(e1, e2) or
            effect_generalization(e2, e1))




def simplify(expr: pe.IRExpr):
    if isinstance(expr, int) or isinstance(expr, str) or expr == None:
        return expr
    if isinstance(expr, list):
        return [simplify(e) for e in expr]
    return simplify_z3(to_z3(expr))


# def equal(expr1: pe.IRExpr, expr2: pe.IRExpr) -> bool:
#     if isinstance(expr1, AnySymbol) and not hasattr(expr2, "args"):
#         return True
#     if isinstance(expr2, AnySymbol) and not hasattr(expr1, "args"):
#         return True
#     # print(f"Comparing: {simplify(expr1)} and {simplify(expr2)}")
#     # if "T" in str(simplify(expr1)).split("*")[-1]:
#     #     return True
#     # # if str(simplify(expr2)) == "T":
#     # if "T" in str(simplify(expr2)).split("*")[-1]:
#     #     return True
#     if isinstance(expr1, int) or isinstance(expr1, str):
#         return expr1 == expr2
#     if isinstance(expr1, list):
#         if not isinstance(expr2, list):
#             return False
#         if len(expr1) != len(expr2):
#             return False
#         for i in range(len(expr1)):
#             if not equal(expr1[i], expr2[i]):
#                 return False
#         return True
#     return equal_z3(to_z3(expr1), to_z3(expr2))

def effect_to_expr(effect):
    """
    Effect 객체에서 pyvex expr(혹은 expr 리스트)을 추출.
    """
    if hasattr(effect, "expr"):
        return effect.expr
    if hasattr(effect, "args"):
        return effect.args
    if hasattr(effect, "addr"):
        return effect.addr
    return effect  # 이미 expr일 수도 있음

def contains_anysymbol(expr) -> bool:
    """
    expr(Effect, pyvex expr 등) 내부에 AnySymbol이 하나라도 포함되어 있으면 True.
    """
    expr = unwrap_const(expr)

    if isinstance(expr, AnySymbol):
        return True

    # Effect 객체의 주요 필드 검사
    if hasattr(expr, "expr"):
        if contains_anysymbol(expr.expr):
            return True
    if hasattr(expr, "args"):
        for arg in expr.args:
            if contains_anysymbol(arg):
                return True
    if hasattr(expr, "addr"):
        if contains_anysymbol(expr.addr):
            return True

    # pyvex.expr.ITE 등: cond, iftrue, iffalse
    if hasattr(expr, "cond") and contains_anysymbol(expr.cond):
        return True
    if hasattr(expr, "iftrue") and contains_anysymbol(expr.iftrue):
        return True
    if hasattr(expr, "iffalse") and contains_anysymbol(expr.iffalse):
        return True

    # pyvex.expr.Load 등: addr
    if hasattr(expr, "value") and contains_anysymbol(expr.value):
        return True

    # 사용자 정의 객체: __dict__의 값들 재귀 검사
    if hasattr(expr, "__dict__"):
        for v in expr.__dict__.values():
            if contains_anysymbol(v):
                return True

    if isinstance(expr, (list, tuple)):
        for e in expr:
            if contains_anysymbol(e):
                return True

    return False

def is_effect_instance(obj):
    """
    True  ⇔  obj 가 effect.py 안에 정의된 Effect.<Something> 중첩 클래스
    """
    return (obj.__class__.__module__ == "effect"         # 파일이 effect.py
            and obj.__class__.__qualname__.startswith("Effect."))

def equal(expr1, expr2) -> bool:
    """
    구조-일반화(PER)·AnySymbol·Z3 논리적 동등성을 모두 고려하는 비교 함수.
    """
    # 처음엔 effect로 시작
    if is_effect_instance(expr1) and is_effect_instance(expr2):
        # 0. 껍데기 제거
        # print("Comparing effects")
        # try:
        #     print(f"before unwrap, expr2: {expr2.expr.args[1].con}, type: {type(expr2.expr.args[1].con)}")

        # except Exception as e:
        #     pass
        # expr1 = unwrap_const(expr1)
        # expr2 = unwrap_const(expr2)
        # try:
        #     print(f"Comparing: {expr2.expr.args[1].con}, type: {type(expr2.expr.args[1].con.value)}")
        # except Exception as e:
        #     pass
        # print(f"expr1 contains AnySymbol: {contains_anysymbol(expr1)}")
        # print(f"expr2 contains AnySymbol: {contains_anysymbol(expr2)}")
        # 1. 구조적 PER 먼저 (refine 부터 AnySymbol이 있을 수 있으므로 이때부터는 구조적 PER)
        
        if contains_anysymbol(expr1) or contains_anysymbol(expr2):
            t = per_related(expr1, expr2)
            # print("Using per_related due to AnySymbol presence")
            # print(f"per_related(expr1, expr2): {t}")
            return t
        else:
            if isinstance(expr1, Effect.Call) and isinstance(expr2, Effect.Call):
                # return expr1 == expr2
                return expr1.name == expr2.name and all(equal(a, b) for a, b in zip(expr1.args, expr2.args))
            elif isinstance(expr1, Effect.Condition) and isinstance(expr2, Effect.Condition):
                # return expr1 == expr2
                # print(f"Comparing {expr1}:{type(expr1.expr)} with {expr2} in InspectInfo.__eq__")
                return equal(expr1.expr, expr2.expr)
            elif isinstance(expr1, Effect.Return) and isinstance(expr2, Effect.Return):
                return equal(expr1.expr, expr2.expr)
                # return expr1 == expr2
            elif isinstance(expr1, Effect.Put) and isinstance(expr2, Effect.Put):
                return expr1.reg == expr2.reg and equal(expr1.expr, expr2.expr)
                # return expr1 == expr2
            elif isinstance(expr1, Effect.Store) and isinstance(expr2, Effect.Store):
                return equal(expr1.addr, expr2.addr) and equal(expr1.expr, expr2.expr)
                # return expr1.ins == __o.ins
            else:
                return False
    # vex ir expr
    else:
        if isinstance(expr1, int) or isinstance(expr1, str):
            return expr1 == expr2
        if isinstance(expr1, list):
            if not isinstance(expr2, list):
                return False
            if len(expr1) != len(expr2):
                return False
            for i in range(len(expr1)):
                if not equal(expr1[i], expr2[i]):
                    return False
            return True
        return equal_z3(to_z3(expr1), to_z3(expr2))


# def equal(expr1, expr2):
#     """
#     Rust Expr PartialEq의 동작을 반영:
#     - AnySymbol이 한쪽에 있으면 무조건 True (와일드카드)
#     - 리스트/구조체는 재귀적으로 비교
#     - 값/타입이 다르면 False
#     """
#     expr1 = unwrap_const(expr1)
#     expr2 = unwrap_const(expr2)

#     # AnySymbol은 어떤 값과도 같다
#     if isinstance(expr1, AnySymbol) or isinstance(expr2, AnySymbol):
#         # partial equivalence relation 우선 확인
#         # Effect 타입만 per_related 적용 (아니면 그냥 True)
#         if isinstance(expr1, Effect) and isinstance(expr2, Effect):
#             if per_related(expr1, expr2):
#                 return True
#         else:
#             return True

#     # 내부에 AnySymbol이 있는 pyvex expr/사용자 정의 객체도 True
#     # (Unop, Binop, FakeRet 등)
#     for e in (expr1, expr2):
#         if hasattr(e, "args") and any(isinstance(arg, AnySymbol) for arg in getattr(e, "args", [])):
#             # partial equivalence relation 우선 확인
#             if isinstance(expr1, Effect) and isinstance(expr2, Effect):
#                 if per_related(expr1, expr2):
#                     return True
#             else:
#                 return True
#         # FakeRet 등 사용자 정의 expr의 속성에 AnySymbol이 있으면 True
#         if hasattr(e, "__dict__"):
#             if any(isinstance(v, AnySymbol) for v in e.__dict__.values()):
#                 if isinstance(expr1, Effect) and isinstance(expr2, Effect):
#                     if per_related(expr1, expr2):
#                         return True
#                 else:
#                     return True

#     # 타입이 다르면 False
#     if type(expr1) != type(expr2):
#         return False

#     # int, str은 값 비교
#     if isinstance(expr1, (int, str)):
#         return expr1 == expr2

#     # 리스트는 길이와 각 원소 재귀 비교
#     if isinstance(expr1, list):
#         if not isinstance(expr2, list):
#             return False
#         if len(expr1) != len(expr2):
#             return False
#         for a, b in zip(expr1, expr2):
#             if not equal(a, b):
#                 return False
#         return True

#     # pyvex expr 등: op, args 비교
#     if hasattr(expr1, "op") and hasattr(expr2, "op"):
#         if getattr(expr1, "op", None) != getattr(expr2, "op", None):
#             return False
#         if hasattr(expr1, "args") and hasattr(expr2, "args"):
#             if len(expr1.args) != len(expr2.args):
#                 return False
#             for a, b in zip(expr1.args, expr2.args):
#                 if not equal(a, b):
#                     return False
#             return True
#         return True

#     # 사용자 정의 객체: __dict__ 비교
#     if hasattr(expr1, "__dict__") and hasattr(expr2, "__dict__"):
#         for k in expr1.__dict__:
#             if k not in expr2.__dict__:
#                 return False
#             if not equal(expr1.__dict__[k], expr2.__dict__[k]):
#                 return False
#         for k in expr2.__dict__:
#             if k not in expr1.__dict__:
#                 return False
#         return True

#     # 마지막으로 z3로 동치성 확인
#     return equal_z3(to_z3(expr1), to_z3(expr2))

def show_equal(expr1: pe.IRExpr, expr2: pe.IRExpr) -> bool:
    if isinstance(expr1, int) or isinstance(expr1, str):
        return expr1 == expr2
    if isinstance(expr1, list):
        print("expr1 is list")
        if not isinstance(expr2, list):
            return False
        if len(expr1) != len(expr2):
            return False
        for i in range(len(expr1)):
            print(f"i: {i}")
            print(f"expr1[i]: {expr1[i]}")
            print(f"expr2[i]: {expr2[i]}")
            if not equal(expr1[i], expr2[i]):
                return False
        return True
    print("to_z3(expr1): ", to_z3(expr1))
    print("to_z3(expr2): ", to_z3(expr2))
    return show_equal_z3(to_z3(expr1), to_z3(expr2))

def to_z3(expr):
    try:
        return to_z3_true(expr)
    except Exception as e:
        print(f"Error converting {expr}:{type(expr)} : {e}")
        return z3.BitVecVal(0, 64)

# def is_effect_instance(obj):
#     """
#     True  ⇔  obj 가 effect.py 안에 정의된 Effect.<Something> 중첩 클래스
#     """
#     return (obj.__class__.__module__ == "effect"         # 파일이 effect.py
#             and obj.__class__.__qualname__.startswith("Effect."))

# def to_z3(expr):
#     """
#     pyvex IRExpr / SymbolicValue → z3.BitVec / Bool 로 변환.
#     AnySymbol 은 unconstrained BitVec 로, Uto64 는 ZeroExt 로 처리.
#     """
#     expr = unwrap_const(expr)

#     # 0) Effect.*  (Put, Condition, Call, Store …)
#     if isinstance(expr, Effect):
#         return z3.BitVec(str(expr), 64)      # 이름만 갖는 64-bit 심볼
    
#     # ───────── AnySymbol ─────────
#     if isinstance(expr, AnySymbol):
#         return z3.BitVec(f"any_{id(expr)}", 64)

#     # ───────── 심볼릭 값들 ────────
#     if isinstance(expr, (ReturnSymbol, RegSymbol, MemSymbol)):
#         return z3.BitVec(str(expr), 64)

#     # ───────── 진짜 상수 ──────────
#     if isinstance(expr, (pe.Const, pc.IRConst)) and not isinstance(expr, SymbolicValue):
#         # pyvex.expr.Const      → expr.con
#         # pyvex.const.IRConst   → expr._value
#         raw = expr.con if hasattr(expr, "con") else expr._value

#         # ⚠️ 문자열이면 BitVec 변수로 취급
#         if isinstance(raw, int):
#             return z3.BitVecVal(raw, 64)
#         else:
#             # e.g. "SR(48)" · "FakeRet(bn_get_top)"
#             return z3.BitVec(str(raw), 64)
        
#     # Unary op (예: 1Uto64)
#     if isinstance(expr, pe.Unop):
#         inner = to_z3(expr.args[0])
#         if expr.op.endswith("Uto64"):
#             return z3.ZeroExt(32, inner)
#         # 필요 시 다른 Unop 추가
#         raise NotImplementedError(f"Unhandled Unop {expr.op}")

#     # Binary op
#     if isinstance(expr, pe.Binop):
#         a, b = map(to_z3, expr.args)
#         match expr.op:
#             case "Iop_Add64" | "Add64":
#                 return a + b
#             case "Iop_Sub64" | "Sub64":
#                 return a - b
#             # 기타 연산 필요 시 추가
#         raise NotImplementedError(f"Unhandled Binop {expr.op}")

#     raise NotImplementedError(f"Unhandled expr type {type(expr)}")

# def to_z3_true(expr):
#     """z3 변환의 helper (이름만 유지)."""
#     return to_z3(expr)

def to_z3_true(expr: pe.IRExpr | pc.IRConst | int) -> z3.ExprRef:
    if isinstance(expr, AnySymbol):
        return z3.BitVec("T", 64)
    if isinstance(expr, int):
        return z3.BitVecVal(expr, 64)
    if isinstance(expr, pc.IRConst):
        if isinstance(expr, RegSymbol):
            return z3.BitVec(str(expr), 64)
        if isinstance(expr, MemSymbol):
            # use the memory address as the variable name
            return mapfunction(to_z3(expr.address))
        if isinstance(expr, ReturnSymbol):
            return z3.BitVec(str(expr), 64)
        return z3.BitVecVal(expr._value, 64)
    if isinstance(expr, pe.Const):
        return to_z3(expr.con)
    if isinstance(expr, pe.Unop):
        if isinstance(expr.args[0], AnySymbol):
            return z3.BitVec("T", 64)
        if expr.op.find("to") != -1:
            if expr.op == "Iop_1Uto64":  # 1U means bool
                return z3.If(to_z3(expr.args[0]), z3.BitVecVal(0, 64), z3.BitVecVal(1, 64))
            return to_z3(expr.args[0])
        match expr.op:
            case "Iop_Not32" | "Iop_Not64" | "Iop_Not8" | "Iop_Not16" | "Iop_Not":
                inner = to_z3(expr.args[0])
                if isinstance(inner, z3.BitVecRef):
                    return z3.If(inner == z3.BitVecVal(0, 64), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                return z3.Not(inner)
            case _:
                return z3.BitVecVal(0, 64)
                raise Exception(f"{expr.op} Unop not considered")
    if isinstance(expr, pe.CCall):
        raise Exception(f"{expr} CCall not considered")
    if isinstance(expr, pe.ITE):
        cond = to_z3(expr.cond)
        if isinstance(cond, z3.BitVecRef):
            return z3.If(cond == 0, to_z3(expr.iffalse), to_z3(expr.iftrue))
        return z3.If(cond, to_z3(expr.iftrue), to_z3(expr.iffalse))
    if isinstance(expr, pe.Binop):
        match expr.op:
            case "Iop_Add32" | "Iop_Add64" | "Iop_Add8" | "Iop_Add16":
                return to_z3(expr.args[0]) + to_z3(expr.args[1])
            case "Iop_Sub32" | "Iop_Sub64" | "Iop_Sub8" | "Iop_Sub16":
                return to_z3(expr.args[0]) - to_z3(expr.args[1])
            case "Iop_Mul32" | "Iop_Mul64" | "Iop_Mul8" | "Iop_Mul16":
                return to_z3(expr.args[0]) * to_z3(expr.args[1])
            case "Iop_Div32" | "Iop_Div64" | "Iop_Div8" | "Iop_Div16":
                return z3.UDiv(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_And32" | "Iop_And64" | "Iop_And8" | "Iop_And16" | "Iop_AndV128" | "Iop_AndV256" | "Iop_AndV512":
                z31 = to_z3(expr.args[0])
                z32 = to_z3(expr.args[1])
                if isinstance(z31, z3.BoolRef) and isinstance(z32, z3.BoolRef):
                    return z3.And(z31, z32)
                return z31 & z32
            case "Iop_Or32" | "Iop_Or64" | "Iop_Or8" | "Iop_Or16" | "Iop_OrV128" | "Iop_OrV256" | "Iop_OrV512":
                z31 = to_z3(expr.args[0])
                z32 = to_z3(expr.args[1])
                if isinstance(z31, z3.BoolRef) and isinstance(z32, z3.BoolRef):
                    return z3.Or(z31, z32)
                return z31 | z32
            case "Iop_Shl32" | "Iop_Shl64" | "Iop_Shl8" | "Iop_Shl16":
                return to_z3(expr.args[0]) << to_z3(expr.args[1])
            case "Iop_Shr32" | "Iop_Shr64" | "Iop_Shr8" | "Iop_Shr16":
                return z3.LShR(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_Sar32" | "Iop_Sar64" | "Iop_Sar8" | "Iop_Sar16":
                return to_z3(expr.args[0]) >> to_z3(expr.args[1])
            case "Iop_Xor32" | "Iop_Xor64" | "Iop_Xor8" | "Iop_Xor16":
                return to_z3(expr.args[0]) ^ to_z3(expr.args[1])
            case "Iop_CmpEQ32" | "Iop_CmpEQ64" | "Iop_CmpEQ8" | "Iop_CmpEQ16":
                to_z31 = to_z3(expr.args[0])
                to_z32 = to_z3(expr.args[1])
                return to_z31 == to_z32
            case "Iop_CmpNE32" | "Iop_CmpNE64" | "Iop_CmpNE8" | "Iop_CmpNE16" | "Iop_CasCmpNE32" | "Iop_CasCmpNE64" | "Iop_CasCmpNE128" | "Iop_CasCmpNE256" | "Iop_CasCmpNE512":
                value = to_z3(expr.args[0]) != to_z3(expr.args[1])
                return value
            case "Iop_CmpLT32S" | "Iop_CmpLT64S" | "Iop_CmpLT8S" | "Iop_CmpLT16S":
                value = to_z3(expr.args[0]) < to_z3(expr.args[1])
                return value
            case "Iop_CmpLT32U" | "Iop_CmpLT64U" | "Iop_CmpLT8U" | "Iop_CmpLT16U":
                value = z3.ULT(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpLE32S" | "Iop_CmpLE64S" | "Iop_CmpLE8S" | "Iop_CmpLE16S":
                value = to_z3(expr.args[0]) <= to_z3(expr.args[1])
                return value
            case "Iop_CmpLE32U" | "Iop_CmpLE64U" | "Iop_CmpLE8U" | "Iop_CmpLE16U":
                value = z3.ULE(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpGT32S" | "Iop_CmpGT64S" | "Iop_CmpGT8S" | "Iop_CmpGT16S":
                value = to_z3(expr.args[0]) > to_z3(expr.args[1])
                return value
            case "Iop_CmpGT32U" | "Iop_CmpGT64U" | "Iop_CmpGT8U" | "Iop_CmpGT16U":
                value = z3.UGT(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_CmpGE32S" | "Iop_CmpGE64S" | "Iop_CmpGE8S" | "Iop_CmpGE16S":
                value = to_z3(expr.args[0]) >= to_z3(expr.args[1])
                return value
            case "Iop_CmpGE32U" | "Iop_CmpGE64U" | "Iop_CmpGE8U" | "Iop_CmpGE16U":
                value = z3.UGE(to_z3(expr.args[0]), to_z3(expr.args[1]))
                return value
            case "Iop_DivModU64to32" | "Iop_DivModS64to32" | "Iop_DivModU128to64" | "Iop_DivModS128to64":
                # return z3.Concat(z3.UDiv(to_z3(expr.args[0]) , to_z3(expr.args[1])) , z3.UMod(to_z3(expr.args[0]) , to_z3(expr.args[1])))
                return z3.BitVecVal(0, 64)
            case "Iop_32HLto64" | "Iop_64HLto128" | "Iop_64HLtoV128" | "Iop_128HLtoV128":
                return z3.Concat(to_z3(expr.args[0]), to_z3(expr.args[1]))
            case "Iop_MullU32":
                return to_z3(expr.args[0]) * to_z3(expr.args[1])
            case "Iop_ExpCmpNE64":
                return to_z3(expr.args[0]) != to_z3(expr.args[1])
            case _:
                print(f"{expr.op} is not a valid op type")
    return z3.BitVecVal(0, 64)
    assert False, (f"{expr}, {type(expr)} is not considered")


def simplify_z3(expr):
    return z3.simplify(expr)

# def equal_z3(expr1, expr2):
#     expr1_simplify = simplify_z3(expr1)
#     expr2_simplify = simplify_z3(expr2)
#     result = z3.eq(expr1_simplify, expr2_simplify)
#     if result:
#         return True
#     else:
#         # use prove to check if the two expr are equal semanticly
#         if 'If' in str(expr1_simplify) and 'If' in str(expr2_simplify):
#             try:
#                 return prove(expr1_simplify == expr2_simplify)
#             except Exception:
#                 return False
#         return False

def equal_z3(expr1, expr2):
    # print("in equal_z3")
    # print(f"expr1: {expr1}, {type(expr1)}")
    # print(f"expr2: {expr2}, {type(expr2)}")
    expr1_simplify = simplify_z3(expr1)
    expr2_simplify = simplify_z3(expr2)
    result = z3.eq(expr1_simplify, expr2_simplify)
    # print(f"expr1_simplify: {expr1_simplify}")
    # print(f"expr2_simplify: {expr2_simplify}")
    if result:
        return True
    else:
        # use prove to check if the two expr are equal semanticly
        if 'If' in str(expr1_simplify) and 'If' in str(expr2_simplify):
            try:
                return prove(expr1_simplify == expr2_simplify)
            except Exception:
                return False
        return False

# def equal_z3(expr1, expr2):
#     expr1_simplify = simplify_z3(expr1)
#     expr2_simplify = simplify_z3(expr2)

#     # fast path
#     if expr1_simplify.eq(expr2_simplify):
#         return True

#     # check if 'T' appears
#     vars1 = set(z3.z3util.get_vars(expr1_simplify))
#     vars2 = set(z3.z3util.get_vars(expr2_simplify))
#     all_vars = vars1 | vars2

#     T_var = next((v for v in all_vars if str(v) == "T"), None)
#     if T_var is not None:
#         solver = z3.Solver()
#         # ✅ try multiple concrete instantiations
#         for concrete in [0, 1, 2]:
#             solver.push()
#             solver.add(T_var == z3.BitVecVal(concrete, 64))
#             solver.add(expr1_simplify != expr2_simplify)
#             if solver.check() == z3.unsat:
#                 return True
#             solver.pop()
#         return False

#     return prove(expr1_simplify == expr2_simplify)
    
def show_equal_z3(expr1, expr2):
    print("in show_equal_z3")
    print(f"expr1: {expr1}")
    expr1_simplify = simplify_z3(expr1)
    print(f"expr1_simplify: {expr1_simplify}")
    print(f"expr2: {expr2}")
    expr2_simplify = simplify_z3(expr2)
    print(f"expr2_simplify: {expr2_simplify}")
    result = z3.eq(expr1_simplify, expr2_simplify)
    print(f"result: {result}")
    if result:
        return True
    else:
        # use prove to check if the two expr are equal semanticly
        if 'If' in str(expr1_simplify) and 'If' in str(expr2_simplify):
            try:
                return prove(expr1_simplify == expr2_simplify)
            except Exception:
                return False
        return False
    
def show_prove(f):
    s = z3.Solver()
    print(f"z3.Not(f): {z3.Not(f)}")
    s.add(z3.Not(f))
    print(f"s.check(): {s.check()}")
    print(f"s.check() == z3.unsat: {s.check() == z3.unsat}")
    if s.check() == z3.unsat:
        return True
    else:
        return False


def expr_similarity(expr1, expr2):
    expr1_simplify = simplify_z3(expr1)
    expr2_simplify = simplify_z3(expr2)
    # print(expr1, expr2, result)
    raise NotImplementedError("expr_similarity")


def prove(f):
    s = z3.Solver()
    s.add(z3.Not(f))
    if s.check() == z3.unsat:
        return True
    else:
        return False
