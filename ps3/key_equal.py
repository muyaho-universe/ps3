from effect import Effect
from inspect_info import InspectInfo
from simplify import equal
from pyvex.expr import ITE, Unop

def key_checker(ref_key, target_keys: list) -> InspectInfo | None:
    """
    ref_key와 target_keys의 각 요소를 비교하여 일치하는 키가 있는지 확인
    """
    if not isinstance(ref_key, tuple) or not isinstance(target_keys, list):
        print("Invalid input types: ref_key must be a tuple and target_keys must be a list. ref_key type:", type(ref_key), "target_keys type:", type(target_keys))
        exit(1)
        return None
    
    for key in target_keys:
        if isinstance(key, tuple) and len(key) == 2:
            if _signature_equal(ref_key, key):
                return key
    return None

def _signature_equal(sig1, sig2):
    """
    시그니처 튜플 (InspectInfo, bool) 간의 동등성 비교
    논리적 반전도 고려함
    """
    if not (isinstance(sig1, tuple) and isinstance(sig2, tuple) and 
            len(sig1) == 2 and len(sig2) == 2):
        return False
    
    info1, branch1 = sig1
    if not isinstance(info1, InspectInfo) and not isinstance(info1,str):
        print(f"Invalid InspectInfo in info1: {info1}, type: {type(info1)}")
        exit(1)
    
    info2, branch2 = sig2
    if not isinstance(info2, InspectInfo) and not isinstance(info2,str):
        print(f"Invalid InspectInfo in info2: {info2}, type: {type(info2)}")
        exit(1)
    
    # 같은 조건, 같은 분기
    if info1 == info2 and branch1 == branch2:
        return True
    
    if info1 == "None":
        if info2 == "None":
            return branch1 == branch2
        return False
    if info2 == "None":
        return False
    

    # 반대 조건, 반대 분기
    
    if isinstance(info1.ins, Effect.Condition) and isinstance(info2.ins, Effect.Condition):
        if branch1 != branch2 and _is_logical_negation(info1, info2):
            return True
    
    return False

def _is_logical_negation(info1: InspectInfo, info2: InspectInfo) -> bool:
    """If(A, 0, 1)과 If(A, 1, 0) 같은 논리적 반전 확인"""
    expr1 = info1.ins.expr
    expr2 = info2.ins.expr
    print(f"DEBUG: expr1: {info1}, expr2: {info2}, type(expr1): {type(expr1)}, expr1: {expr1}, type(expr2): {type(expr2)}, expr2: {expr2}")


    if isinstance(expr1, ITE) and isinstance(expr2, ITE):
        if equal(expr1.cond, expr2.cond) and \
           equal(expr1.iftrue, expr2.iffalse) and \
           equal(expr1.iffalse, expr2.iftrue):
            return True
    return False