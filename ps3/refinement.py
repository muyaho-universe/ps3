from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue, WildCardSymbol
import pyvex.const as pc
from inspect_info import InspectInfo
from typing import Iterator
from copy import deepcopy
from simplify import simplify
from node import Node
from itertools import product
from collections import deque
import re
from log import *
from settings import *

logger = get_logger(__name__)
logger.setLevel(INFO)
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)
ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

def tree_possible_subs(tree: Node, fallback_effect: Effect) -> Iterator[Effect]:
    # print(f"tree_possible_subs(tree{tree.print()})")
    # 각 노드에서 가능한 대체 표현을 재귀적으로 생성
    def helper(node: Node) -> list[Node]:
        # print(f"helper(node{node.label})")
        # 자식이 없는 리프 노드인 경우: 자신 그대로, 그리고 T로 대체
        if not node.children:
            return [deepcopy(node), Node("Const: T", level=node.level)]

        # 자식이 있는 경우: 각 자식에서 가능한 노드 조합 생성
        children_sub_lists = [helper(child) for child in node.children]
        combinations = product(*children_sub_lists)

        result = []

        for comb in combinations:
            new_node = Node(node.label, list(comb), level=node.level)
            result.append(new_node)

        # 자기 자신도 T로 바꾸는 경우 추가
        if node.level >= 1:  # level 0은 effect root이므로 제외
            result.append(Node("Const: T", level=node.level))

        return result

    # 전체 트리에서 가능한 대체 트리 생성
    candidates = helper(tree)
    # print("helper done")
    sorted_candidates = sorted(candidates, key=abstraction_score) # [1:] # 가장 추상화된 트리는 제외 (T로만 구성된 트리)

    # 각 트리를 effect로 변환 (불가능한 경우 fallback 사용)
    for cand in sorted_candidates:
        try:
            yield node_to_effect(cand, fallback_effect=fallback_effect)
        except Exception:
            continue


def abstraction_score(node: Node) -> int:
    """
    더 추상화된 트리는 더 낮은 점수를 갖는다.
    """
    # 완전히 추상화된 경우
    if node.label == "Const: T":
        return 0

    score = 0

    # 재귀적으로 자식 노드들을 검사
    for child in node.children:
        score += abstraction_score(child)

    # 노드 자체가 T가 아닌 경우 penalty
    if node.label != "Const: T":
        score += 1

    return score


def refine_one(myself: list[InspectInfo], other: list[InspectInfo]) -> list[InspectInfo]:
    for i, info in enumerate(myself):
        effect = deepcopy(info.ins) 
        temp = []
        go = True
        # print("go into other with info:", info)
        root = effect_to_node(info.ins)
        first = True
        for generalized_tree in tree_possible_subs(root, fallback_effect=effect):
            if first:
                first = False
                continue
            new_effect = generalized_tree   
            new_info = InspectInfo(new_effect)
            # temp.append(new_info)
            if go and new_info not in other :
                print(f"refine_one: {new_info} not in other, {new_info in other}, type(other){type(other)}, type(new_info): {type(new_info)}")
                for a in other:
                    print(f"new_info == i: {new_info == a}, new_info: {new_info}, i: {a}")
                myself[i] = new_info
                go = False
                break  # 다른 효과와 겹치지 않는 첫 번째 generalized_tree를 찾으면 중단
    return myself 

def generalize_node(node: Node) -> Node:
    # SR 노드이며 자식이 int면 T로 대체
    # if node.label == "SR" and node.children and node.children[0].label.startswith("int: "):
    #     return Node("SR", [Node("Const: T", level=node.level+1)], level=node.level)
    # # Mem 노드이며 자식이 int면 T로 대체
    # if node.label == "Mem" and node.children and node.children[0].label.startswith("int: "):
    #     return Node("Const: T", [Node("Const: T", level=node.level+1)], level=node.level)
    # int값이 1000000 크면 T로 대체 6828016
    if node.label.startswith("int: "):
        try:
            val = int(node.label[len("int: "):])
            if val >= 1000000:
                return Node("Const: T", level=node.level)
        except Exception:
            pass
    if node.label.startswith("IRConst: "):
        try:
            val = int(node.label[len("IRConst: "):])
            if val >= 1000000:
                return Node("Const: T", level=node.level)
        except Exception:
            pass
    # 자식 노드들 재귀적으로 처리
    # if node.label.startswith("IRConst: "):
    new_children = [generalize_node(child) for child in node.children]
    return Node(node.label, new_children, level=node.level)

def single_refine_one(info: InspectInfo) -> InspectInfo:
    """
    InspectInfo의 ins가 Call 또는 Condition인 경우, 그 안의 expr를 T로 바꾼다.
    """
    effect = deepcopy(info.ins)
    root = effect_to_node(info.ins)
    # root.print()
    new_tree = generalize_node(root)
    # new_tree.print() 
    try:
        new_effect = node_to_effect(new_tree, fallback_effect=effect)
    except Exception as e:
        print(f"info: {info}")
        new_tree.print()
        raise e
    
    return InspectInfo(new_effect)

def single_refine(myself: dict[(InspectInfo, bool):list[InspectInfo]]) -> dict[(InspectInfo, bool):list[InspectInfo]]:
    """
    한 쪽이 비어 있다면, 자기의 시그니처 중에 call과 condition의 내부 표현 중 메모리 주소나 Register의 offset을 모두 T로 바꿈
    예) Call: uninit_options(18446744073709550680 + SR(48)) -> Call: uninit_options(T + SR(T))
    """
    old_myself = deepcopy(myself)
    my_effects = {}
    for key, value in myself.items():
        if key != ("None", False):
            key_info = key[0] 
            old_key = deepcopy(key_info)
            new_key_info = rebuild_effects(key_info)
            # assert new_key_info == old_key, f"Rebuild failed for key {new_key_info}\n!=\n {old_key}"
            
            rebuild_new_key = single_refine_one(new_key_info)
            key = (rebuild_new_key, key[1])  # key는 (InspectInfo, bool) 형태
        my_effects[key] = []
        for info in value:
            new_info = rebuild_effects(info)
            # assert new_info == info, f"Rebuild failed for info {new_info}\n!=\n {info}"
            # if isinstance(new_info.ins, (Effect.Call, Effect.Condition)):
                # Call 또는 Condition인 경우, 그 안의 expr를 T로 바꿈
            # print(f"new_info: {new_info}")
            new_info = single_refine_one(new_info)
            # print(f"after single_refine_one: {new_info}")
            # if isinstance(new_info.ins, (Effect.Put, Effect.Store)):
            #     print(f"new_info.ins.expr: {new_info.ins.expr}")
            my_effects[key].append(new_info)
    # exit(0)
    return my_effects


def refine_sig(vuln_effect: list[InspectInfo], patch_effect: list[InspectInfo]) -> tuple[list[InspectInfo], list[InspectInfo]]:    
    old_vuln_effect = deepcopy(vuln_effect)
    old_patch_effect = deepcopy(patch_effect)
    vuln_effect = [rebuild_effects(effect) for effect in vuln_effect]
    patch_effect = [rebuild_effects(effect) for effect in patch_effect]
    # print(f"old_vuln_effect: {old_vuln_effect}")
    # print(f"rebuild vuln_effect: {vuln_effect}")
    # print(f"same: {old_vuln_effect == vuln_effect}")
    assert vuln_effect == old_vuln_effect, f"Rebuild failed for vuln_effect {vuln_effect}\n!=\n {old_vuln_effect}"
    assert patch_effect == old_patch_effect, "Rebuild failed for patch_effect"
    # exit(1)
    # vuln_effect = simplify_effects(vuln_effect)
    # patch_effect = simplify_effects(patch_effect)
    temp = []
    # for i in range(len(vuln_effect)):
    #     # if isinstance(vuln_effect[i].ins, Effect.Call):     
    #     tree = effect_to_node(vuln_effect[i].ins)
    #     tree.print()
        
    #     restored = node_to_effect(tree)
    #     print(f"restored: {InspectInfo(restored)}")
    #     temp.append(InspectInfo(restored))
    #     print("=" * 50)
    # print(f"old == restored: {old_vuln_effect == temp}")
    vuln_effect = refine_one(vuln_effect, patch_effect)
    logger = logging.getLogger(__name__)

    logger.info("=" * 50)
    logger.info(f"old_vuln_effect: {old_vuln_effect}")
    logger.info(f"vuln_effect: {vuln_effect}")
    logger.info("-" * 50)
    patch_effect = refine_one(patch_effect, vuln_effect)
    logger.info(f"old_patch_effect: {old_patch_effect}")
    logger.info(f"patch_effect: {patch_effect}")
    logger.info("=" * 50)

    
    # exit(1)
    return vuln_effect, patch_effect 


def strip_trivial_unop(expr):
    """
    의미 없는 타입 변환(Unop) 껍데기를 재귀적으로 벗기고 core만 반환.
    예: Unop("Iop_32Uto64", Unop("Iop_64to32", x)) -> strip_trivial_unop(x)
    """
    # 의미 없는 변환 목록 (필요시 추가)
    trivial_unops = {
        # Zero/Sign extend, truncate
        "Iop_8Uto32", "Iop_16Uto32", "Iop_32Uto64", "Iop_8Uto64", 
        # "Iop_1Uto64",
        "Iop_8Sto32", "Iop_16Sto32", "Iop_32Sto64", "Iop_8Sto64", "Iop_1Sto64",
        "Iop_64to32", "Iop_32to8", "Iop_32to16", "Iop_64to8", "Iop_64to16",
        "Iop_8to32", "Iop_16to32", "Iop_8to64", "Iop_16to64", "Iop_32to64",
        "Iop_64to1",
        # Identity/bitcast
        "Iop_Identity32", "Iop_Identity64", "Iop_Identity8", "Iop_Identity16",
        "Iop_Bitcast32to32", "Iop_Bitcast64to64",
        # Redundant ZeroExt/SignExt
        "Iop_ZeroExt8to8", "Iop_ZeroExt16to16", "Iop_ZeroExt32to32", "Iop_ZeroExt64to64",
        "Iop_SignExt8to8", "Iop_SignExt16to16", "Iop_SignExt32to32", "Iop_SignExt64to64",
        # Redundant Extract/Concat
        "Iop_Extract8", "Iop_Extract16", "Iop_Extract32", "Iop_Extract64",
        "Iop_Concat8", "Iop_Concat16", "Iop_Concat32", "Iop_Concat64",
        # No-op
        "Iop_Copy", "Iop_Move",
        # 기타
        "Iop_1Uto8", "Iop_1Uto16", "Iop_1Uto32",
        "Iop_8Uto8", "Iop_16Uto16", "Iop_32Uto32", "Iop_64Uto64",
    }
    # Unop이면서 의미 없는 변환이면 재귀적으로 벗김
    while isinstance(expr, Unop) and expr.op in trivial_unops:
        expr = expr.args[0]
    # 내부도 재귀적으로 처리
    if isinstance(expr, Unop):
        return Unop(expr.op, [strip_trivial_unop(expr.args[0])])
    elif isinstance(expr, Binop):
        # if expr.op == "Iop_Sub8":
        #     return Binop("Iop_Sub64", [strip_trivial_unop(expr.args[0]), strip_trivial_unop(expr.args[1])])
        return Binop(expr.op, [strip_trivial_unop(expr.args[0]), strip_trivial_unop(expr.args[1])])
    elif isinstance(expr, Load):
        return Load(expr.end, strip_trivial_unop(expr.addr))
    elif isinstance(expr, ITE):
        # ITE(조건, iftrue, iffalse)에서 조건이 항상 True/False면 단순화
        cond = strip_trivial_unop(expr.cond)
        iftrue = strip_trivial_unop(expr.iftrue)
        iffalse = strip_trivial_unop(expr.iffalse)
        if isinstance(cond, Const):
            try:
                val = int(cond.con)
                if val:
                    return iftrue
                else:
                    return iffalse
            except Exception:
                pass
        return ITE(cond, iffalse, iftrue)
    elif isinstance(expr, list):
        return [strip_trivial_unop(e) for e in expr]
    elif isinstance(expr, Const):
        if isinstance(expr.con, IRConst):
            # IRConst의 경우, 단순화된 표현으로 변환
            if isinstance(expr.con.value, int):
                return expr
            elif isinstance(expr.con, SymbolicValue):
                return strip_trivial_unop(expr.con)
        else:
            return expr
    # RdTmp와 Get은 단순화하지 않음
    elif isinstance(expr, (RdTmp, Get)):
        return expr
    elif isinstance(expr, MemSymbol):
            # MemSymbol의 주소 부분도 재귀적으로 단순화
            ret = MemSymbol(strip_trivial_unop(expr.address))
            return ret
    elif isinstance(expr, RegSymbol):
        return RegSymbol(strip_trivial_unop(expr.offset))

    else:
        return expr

def simplify_all_addr_expr(expr):
    """
    모든 expr 내부의 Add64/Sub64에 대해 상수 누적 단순화를 재귀적으로 적용.
    """
    if isinstance(expr, Binop):
        if expr.op in ("Iop_Add64", "Iop_Sub64"):
            simplified = simplify_addr_expr(expr)
            # simplified가 Binop이면 재귀적으로, 아니면 그대로 반환
            if isinstance(simplified, Binop):
                return Binop(simplified.op, [simplify_all_addr_expr(simplified.args[0]), simplify_all_addr_expr(simplified.args[1])])
            else:
                return simplify_all_addr_expr(simplified)
        else:
            return Binop(expr.op, [simplify_all_addr_expr(expr.args[0]), simplify_all_addr_expr(expr.args[1])])
    elif isinstance(expr, Unop):
        return Unop(expr.op, [simplify_all_addr_expr(expr.args[0])])
    elif isinstance(expr, Load):
        return Load(expr.end, simplify_all_addr_expr(expr.addr))
    elif isinstance(expr, ITE):
        return ITE(simplify_all_addr_expr(expr.cond), simplify_all_addr_expr(expr.iffalse), simplify_all_addr_expr(expr.iftrue))
    elif isinstance(expr, MemSymbol):
        return MemSymbol(simplify_all_addr_expr(expr.address))
    elif isinstance(expr, RegSymbol):
        return RegSymbol(simplify_all_addr_expr(expr.offset))
    elif isinstance(expr, list):
        return [simplify_all_addr_expr(e) for e in expr]
    else:
        return expr

def simplifier(expr):
    sim_expr = strip_trivial_unop(expr)
    try:
        bin_expr = binop_simplifier(sim_expr)
    except Exception as e:
        print(f"simplifier: 파싱 실패: {sim_expr}, type(sim_expr): {type(sim_expr)}")
        print(f"sim_expr: {sim_expr.args[1]}, type(sim_expr): {type(sim_expr.args[1])}, error: {e}")
        exit(0)
    cmp_expr = simplify_arith_cmp(bin_expr)
    addr_expr = simplify_all_addr_expr(cmp_expr)
    return addr_expr

def rebuild_checker(original, ret, effect):
    return normalize_str(original) != normalize_str(str(ret)) and effect != ret


def rebuild_effects(effect: InspectInfo) -> InspectInfo:
    """
    InspectInfo를 받아서, str 형태 그대로 최소화된 effect로 변환합니다.
    """
    if str(effect) == "None":
        return effect

    original_str = str(effect).replace('\n', '').strip()
    if len(original_str) > 1000:
        return effect

    if isinstance(effect.ins, Effect.Put):
        ret_expr = simplifier(effect.ins.expr)
        ret = InspectInfo(Effect.Put(effect.ins.reg, ret_expr))
        # if rebuild_checker(original_str, ret, effect):
        #     logger.info(f"Rebuild failed for Put: {normalize_str(original_str)} != {normalize_str(str(ret))}")
        #     logger.info(f"effect.ins.expr: {effect.ins.expr}")
        #     logger.info(f"ret.ins.expr: {ret.ins.expr}")
        #     logger.info(f"effect == ret: {effect == ret}")
        #     logger.info("=" * 50)
        #     exit(1)
        #     return effect
        return ret
    elif isinstance(effect.ins, Effect.Call):
        name = effect.ins.name
        args = []
        for arg in effect.ins.args:
            ret_arg = simplifier(arg)
            args.append(ret_arg)
        ret = InspectInfo(Effect.Call(name, args))
        # if rebuild_checker(original_str, ret, effect):
        #     logger.info(f"Rebuild failed for Call: {normalize_str(original_str)} != {normalize_str(str(ret))}")
        #     logger.info(f"effect.ins.expr: {effect.ins.args}")
        #     logger.info(f"ret.ins.expr: {ret.ins.args}")
        #     logger.info(f"effect == ret: {effect == ret}")
        #     logger.info("=" * 50)
        #     exit(1)
        return ret
    elif isinstance(effect.ins, Effect.Condition):
        ret_expr = simplifier(effect.ins.expr)
        ret = InspectInfo(Effect.Condition(ret_expr))
        # if rebuild_checker(original_str, ret, effect):
        #     logger.info(f"Rebuild failed for Condition: {normalize_str(original_str)} != {normalize_str(str(ret))}")
        #     logger.info(f"effect.ins.expr: {effect.ins.expr}")
        #     logger.info(f"ret.ins.expr: {ret.ins.expr}")
        #     logger.info(f"effect == ret: {effect == ret}")
        #     logger.info("=" * 50)
        #     exit(1)
        return ret
    elif isinstance(effect.ins, Effect.Return):
        ret_expr = simplifier(effect.ins.expr)
        ret = InspectInfo(Effect.Return(ret_expr))
        # if rebuild_checker(original_str, ret, effect):
        #     print(f"Rebuild failed for Return: {normalize_str(original_str)} != {normalize_str(str(ret))}")
        #     logger.info(f"effect.ins.expr: {effect.ins.expr}")
        #     logger.info(f"ret.ins.expr: {ret.ins.expr}")
        #     logger.info(f"effect == ret: {effect == ret}")
        #     logger.info("=" * 50)
        #     exit(1)
        return ret
    elif isinstance(effect.ins, Effect.Store):
        ret_addr = simplifier(effect.ins.addr)
        ret_expr = simplifier(effect.ins.expr)
        ret = InspectInfo(Effect.Store(ret_addr, ret_expr))
        # if rebuild_checker(original_str, ret, effect):
        #     print(f"Rebuild failed for Store: {normalize_str(original_str)} != {normalize_str(str(ret))}")
        #     print(f"effect.ins.expr: {effect.ins.expr}")
        #     print(f"ret.ins.expr: {ret.ins.expr}")
        #     print(f"effect == ret: {effect == ret}")
        #     logger.info("=" * 50)
        #     exit(1)
        return ret
    else:
        print(f"Unknown effect format: {original_str}")
        exit(1)
    # except Exception as e:
    #     print(f"rebuild_effects: 파싱 실패: {effect}, original_str: {normalize_str(original_str)}, error: {e}, len(normalize_str(original_str)): {len(normalize_str(original_str))}")

def binop_simplifier(expr: IRExpr | pc.IRConst | int):
    """
    단순화된 Binop 표현식을 반환합니다.
    Add8, Sub8 등의 8비트 연산을 64비트로 변환합니다.
    """
    if isinstance(expr, Binop):
        match expr.op:
            case "Iop_Add8":
                if isinstance(expr.args[1], Const):
                    # if isinstance(expr.args[1].con, int):
                    #     val = int(expr.args[1].con) 
                    # elif isinstance(expr.args[1].con, pc.U8):
                    #     val = int(expr.args[1].con.value)
                    # elif isinstance(expr.args[1].con, Const):
                    #     val = int(expr.args[1].con.value)
                    # if isinstance(val, int):
                    val = int(str(expr.args[1]), 16)
                    if val > 0x7f:
                        # 8비트에서 -2는 0xfe로 표현되므로, Sub64로 변환
                        return Binop("Iop_Sub64", [expr.args[0], Const(0x100 - val)])
                    else:
                        # 양수는 Add64로 변환
                        return Binop("Iop_Add64", [expr.args[0], Const(val)])
        
            case "Iop_Add16":
                if isinstance(expr.args[1], Const):
                    # if isinstance(expr.args[1].con, int):
                    #     val = int(expr.args[1].con)
                    # elif isinstance(expr.args[1].con, pc.U16):
                    #     val = int(expr.args[1].con.value)
                    # elif isinstance(expr.args[1].con, Const):
                    #     val = int(expr.args[1].con.value)
                    # if isinstance(val, int):
                    val = int(str(expr.args[1]), 16)
                    if val > 0x7fff:
                        # 16비트에서 -2는 0xfffe로 표현되므로, Sub64로 변환
                        return Binop("Iop_Sub64", [expr.args[0], Const(0x10000 - val)])
                    else:
                        # 양수는 Add64로 변환
                        return Binop("Iop_Add64", [expr.args[0], Const(val)])
            case "Iop_Add32":
                if isinstance(expr.args[1], Const):
                    # if isinstance(expr.args[1].con, int):
                    #     val = int(expr.args[1].con)
                    # elif isinstance(expr.args[1].con, pc.U32):
                    #     val = int(expr.args[1].con.value)
                    # elif isinstance(expr.args[1].con, Const):
                    #     val = int(expr.args[1].con.value)
                    # if isinstance(val, int):
                    val = int(str(expr.args[1]), 16)
                    if val > 0x7fffffff:
                        # 32비트에서 -2는 0xfffffffe로 표현되므로, Sub64로 변환
                        return Binop("Iop_Sub64", [expr.args[0], Const(0x100000000 - val)])
                    else:
                        # 양수는 Add64로 변환
                        return Binop("Iop_Add64", [expr.args[0], Const(val)])
            case _:
                # 다른 Binop은 그대로 반환
                return Binop(expr.op, [binop_simplifier(expr.args[0]), binop_simplifier(expr.args[1])])
    elif isinstance(expr, Unop):
        # Unop의 경우, 내부 expr을 재귀적으로 처리
        return Unop(expr.op, [binop_simplifier(expr.args[0])])
    elif isinstance(expr, Load):
        # Load의 경우, addr을 재귀적으로 처리
        return Load(binop_simplifier(expr.addr))
    elif isinstance(expr, IRConst):
        if isinstance(expr, Const):
            # Const는 내부 expr을 재귀적으로 처리
            return Const(binop_simplifier(expr.con))
        elif isinstance(expr, MemSymbol):
            # MemSymbol은 주소를 재귀적으로 처리
            return MemSymbol(binop_simplifier(expr.address))
        elif isinstance(expr, RegSymbol):
            # RegSymbol은 오프셋을 재귀적으로 처리
            return RegSymbol(binop_simplifier(expr.offset))
        elif isinstance(expr, ReturnSymbol):
            # ReturnSymbol은 이름을 재귀적으로 처리
            return ReturnSymbol(binop_simplifier(expr.name))
    elif isinstance(expr, ITE):
        # ITE의 경우, cond, iftrue, iffalse를 재귀적으로 처리
        return ITE(
            binop_simplifier(expr.cond),
            binop_simplifier(expr.iffalse),
            binop_simplifier(expr.iftrue)            
        )
    # elif isinstance(expr, pe.CCall):

    elif isinstance(expr, int):
        # int는 그대로 반환
        return expr
    elif isinstance(expr, str):
        # str은 그대로 반환
        return expr
    else:
        # 다른 타입은 그대로 반환
        return expr

def simplify_addr_expr(expr):
    """
    연속된 Sub64/Add64의 상수 부분을 모두 누적해서 단순화.
    예: Add64(Add64(SR(64), 3), 1) → Add64(SR(64), 4)
        Sub64(Sub64(SR(48), 8), 8) → Sub64(SR(48), 16)
    """
    base = expr
    total = 0
    while isinstance(base, Binop):
        if base.op == "Iop_Sub64":
            left, right = base.args
            if isinstance(right, (Const, int)):
                val = right.con if isinstance(right, Const) else right
                if hasattr(val, "value"):
                    val = val.value
                val = int(val)
                total -= val
                base = left
            else:
                break
        elif base.op == "Iop_Add64":
            left, right = base.args
            if isinstance(right, (Const, int)):
                val = right.con if isinstance(right, Const) else right
                if hasattr(val, "value"):
                    val = val.value
                val = int(val)
                total += val
                base = left
            else:
                break
        else:
            break
    # base가 더 이상 Binop이 아니면, 누적된 상수와 함께 재구성
    if total == 0:
        return base
    elif total > 0:
        return Binop("Iop_Add64", [base, Const(total)])
    else:
        return Binop("Iop_Sub64", [base, Const(-total)])

def simplify_effects(effects: list[InspectInfo]) -> list[InspectInfo]:
    for effect in effects:
        if isinstance(effect.ins, Effect.Call):
            args = effect.ins.args
            for i, arg in enumerate(args):
                args[i] = simplify_expr(arg)
            effect.ins.args = args
        elif isinstance(effect.ins, Effect.Condition):
            effect.ins.expr = simplify_expr(effect.ins.expr)
        elif isinstance(effect.ins, Effect.Return):
            effect.ins.expr = simplify_expr(effect.ins.expr)
        elif isinstance(effect.ins, Effect.Put):
            effect.ins.expr = simplify_expr(effect.ins.expr)
        elif isinstance(effect.ins, Effect.Store):
            # 여기서 addr을 추가로 단순화
            effect.ins.addr = simplify_addr_expr(simplify_expr(effect.ins.addr))
            effect.ins.expr = simplify_expr(effect.ins.expr)
    return effects


def simplify_expr(expr: IRExpr) -> IRExpr:
    if isinstance(expr, Unop):
        inner = simplify_expr(expr.args[0])  # 먼저 안쪽을 단순화
        # 패턴 제거: 32Uto64(64to32(x)) -> x
        if expr.op == "Iop_32Uto64" and isinstance(inner, Unop) and inner.op == "Iop_64to32":
            return simplify_expr(inner.args[0])
        # 패턴 제거: 64to32(32Uto64(x)) -> x
        if expr.op == "Iop_64to32" and isinstance(inner, Unop) and inner.op == "Iop_32Uto64":
            return simplify_expr(inner.args[0])
        return Unop(expr.op, [inner])

    elif isinstance(expr, Binop):
        return Binop(expr.op, [simplify_expr(arg) for arg in expr.args])

    elif isinstance(expr, Load):
        return Load(expr.end, simplify_expr(expr.addr))

    elif isinstance(expr, ITE):
        return ITE(simplify_expr(expr.cond), simplify_expr(expr.iftrue), simplify_expr(expr.iffalse))

    elif isinstance(expr, (Const, RdTmp, Get)):
        return expr  # 원자 표현식은 그대로 유지

    elif isinstance(expr, list):
        return [simplify_expr(e) for e in expr]

    else:
        return expr  # 처리하지 않는 타입은 그대로 반환
    

def expr_to_node(expr, level=0) -> Node:
    if isinstance(expr, Binop):
        return Node(f"Binop({expr.op})", [
            expr_to_node(expr.args[0], level + 1),
            expr_to_node(expr.args[1], level + 1)
        ], level)
    elif isinstance(expr, Unop):
        return Node(f"Unop({expr.op})", [
            expr_to_node(expr.args[0], level + 1)
        ], level)
    elif isinstance(expr, Load):
        return Node("Load", [expr_to_node(expr.addr, level + 1)], level)
    elif isinstance(expr, ITE):
        return Node("ITE", [
            expr_to_node(expr.cond, level + 1),
            expr_to_node(expr.iftrue, level + 1),
            expr_to_node(expr.iffalse, level + 1)
        ], level)
    elif isinstance(expr, Get):
        return Node(f"Get(offset={expr.offset})", level=level)
    elif isinstance(expr, RdTmp):
        return Node(f"RdTmp(t{expr.tmp})", level=level)
    elif isinstance(expr, Const):
        if hasattr(expr, "con") and expr.con.__class__.__name__ == "AnySymbol":
            return Node("Const: T", level=level)
        return expr_to_node(expr.con, level)  # Const의 값을 재귀적으로 처리
        # return Node(f"Const: {expr.con}", level=level)
    elif isinstance(expr, AnySymbol):
        return Node("AnySymbol", level=level)
    elif isinstance(expr, int):
        return Node(f"int: {expr}", level=level)
    elif isinstance(expr, str):
        return Node(f"str: \"{expr}\"", level=level)
    elif isinstance(expr, ReturnSymbol):
    # FakeRet (즉, expr.name이 None)인 경우
        if getattr(expr, "name", None) is None:
            return Node("ReturnSymbol", level=level)
        return Node("ReturnSymbol", [expr_to_node(expr.name, level + 1)], level=level)
    elif isinstance(expr, (pc.F32, pc.F64, pc.U1, pc.U8, pc.U16, pc.U32, pc.U64)):
        return Node(f"IRConst: {expr.value}", level=level)

    elif isinstance(expr, CCall):
        # 함수명과 타입을 노드에 기록, 인자들은 자식 노드로
        return Node(f"CCall({expr.cee}:{expr.retty})", [expr_to_node(arg, level + 1) for arg in expr.args], level)
    
    elif isinstance(expr, MemSymbol):
        # MemSymbol은 주소를 표현하는 노드로 변환
        return Node("Mem", [expr_to_node(expr.address, level + 1)], level=level)
    elif isinstance(expr, RegSymbol):
        # RegSymbol은 레지스터를 표현하는 노드로 변환
        return Node("SR", [expr_to_node(expr.offset, level + 1)], level=level)
    elif isinstance(expr, WildCardSymbol):
        return Node("WildCard", level=level)
    else:
        return Node(f"[UNKNOWN expr] {expr} ({type(expr).__name__})", level=level)



def effect_to_node(effect) -> Node:
    if isinstance(effect, Effect.Call):
        # args_top이 level 0이 되도록 함
        args_node = Node("args_top", [expr_to_node(arg, 1) for arg in effect.args], level=0)
        return Node(f"Call({effect.name})", [args_node], level=0)
    elif isinstance(effect, Effect.Condition):
        return Node("Condition", [expr_to_node(effect.expr, 1)], level=0)
    elif isinstance(effect, Effect.Return):
        return Node("Return", [expr_to_node(effect.expr, 1)], level=0)
    elif isinstance(effect, Effect.Put):
        return Node(f"Put(reg{effect.reg})", [expr_to_node(effect.expr, 1)], level=0)
    elif isinstance(effect, Effect.Store):
        return Node("Store", [
            Node("addr", [expr_to_node(effect.addr, 2)], level=1),
            Node("expr", [expr_to_node(effect.expr, 2)], level=1)
        ], level=0)
    else:
        return Node(f"[UNKNOWN Effect] {type(effect).__name__}", level=0)
    
def node_to_expr(node: Node):
    if node.label.startswith("Binop("):
        op = node.label[len("Binop("):-1]
        left = node_to_expr(node.children[0])
        right = node_to_expr(node.children[1])
        return Binop(op, [left, right])

    elif node.label.startswith("Unop("):
        op = node.label[len("Unop("):-1]
        return Unop(op, [node_to_expr(node.children[0])])

    elif node.label == "Load":
        return Load("end_unknown", node_to_expr(node.children[0]))  # end는 유실되어 'dummy'

    elif node.label == "ITE":
        cond = node_to_expr(node.children[0])
        iftrue = node_to_expr(node.children[1])
        iffalse = node_to_expr(node.children[2])
        return ITE(cond, iffalse, iftrue)  # pyvex는 iftrue, iffalse 순서가 반대임에 유의

    elif node.label.startswith("Get(offset="):
        offset = int(node.label[len("Get(offset="):-1])
        return Get(offset)

    elif node.label.startswith("RdTmp(t"):
        tmp = int(node.label[len("RdTmp(t"):-1])
        return RdTmp(tmp)

    elif node.label.startswith("Const: T"):
        # return Const(AnySymbol())
        return AnySymbol()  # T는 AnySymbol로 변환

    elif node.label.startswith("Const: "):
        value = node.label[len("Const: "):]
        try:
            return Const(int(value))
        except:
            return Const(value)

    elif node.label.startswith("int: "):
        return int(node.label[len("int: "):])

    elif node.label.startswith('str: "'):
        return node.label[len('str: "'):-1]

    elif node.label == "AnySymbol":
        return AnySymbol()

    elif node.label == "ReturnSymbol":
        if not node.children:
            return ReturnSymbol(None)
        return ReturnSymbol(node_to_expr(node.children[0]))
    
    elif node.label.startswith("IRConst: "):
        value_str = node.label[len("IRConst: "):]
        try:
            value = int(value_str)
        except ValueError:
            value = value_str
        # 기본적으로 U64로 복원한다고 가정 (실제 타입 보존하려면 node.meta 필요)
        return pc.U64(value)  # 또는 pc.U32(value) 등 필요에 따라
    
    elif node.label.startswith("CCall("):
        # 예: CCall(Iop_Concat:Ity_I64)
        label = node.label[len("CCall("):-1]
        cee, retty = label.split(":")
        args = [node_to_expr(child) for child in node.children]
        return CCall(retty, cee, args)
    elif node.label == "Mem":
        # MemSymbol 노드 처리
        if not node.children or len(node.children) != 1:
            raise ValueError("Malformed Mem node")
        addr = node_to_expr(node.children[0])
        return MemSymbol(addr)
    elif node.label == "SR":
        # RegSymbol 노드 처리
        if not node.children or len(node.children) != 1:
            raise ValueError("Malformed SR node")
        offset = node_to_expr(node.children[0])
        return RegSymbol(offset)
    elif node.label == "WildCard":
        return WildCardSymbol()
    else:
        node.print()
        raise ValueError(f"Unknown node label: {node.label}")
    

def node_to_effect(node: Node, fallback_effect: Effect = None) -> Effect:
    label = node.label
    if label.startswith("Call("):
        name = label[len("Call("):-1]

        if not node.children or node.children[0].label != "args_top":
            # fallback 상황: generalized_tree가 "Const: T" 하나로만 구성된 경우 등
            if fallback_effect is not None:
                return Effect.Call(fallback_effect.name, [AnySymbol()] * len(fallback_effect.args))
            else:
                raise ValueError("Malformed Call node and no fallback provided")

        args_top = node.children[0]
        args = [node_to_expr(child) for child in args_top.children]
        return Effect.Call(name, args)

    elif label == "Condition":
        expr = node_to_expr(node.children[0])
        return Effect.Condition(expr)

    elif label == "Return":
        expr = node_to_expr(node.children[0])
        return Effect.Return(expr)

    elif label.startswith("Put(reg"):
        reg = int(label[len("Put(reg"):-1])
        expr = node_to_expr(node.children[0])
        return Effect.Put(reg, expr)

    elif label == "Store":
        addr_node = node.children[0]
        expr_node = node.children[1]
        assert addr_node.label == "addr" and expr_node.label == "expr"
        addr = node_to_expr(addr_node.children[0])
        expr = node_to_expr(expr_node.children[0])
        return Effect.Store(addr, expr)

    elif label == "Const: T" and fallback_effect is not None:
        # Fallback: wrap generalized expr into original effect
        if isinstance(fallback_effect, Effect.Call):
            args = [AnySymbol()] * len(fallback_effect.args)
            return Effect.Call(fallback_effect.name, args)
        elif isinstance(fallback_effect, Effect.Put):
            return Effect.Put(fallback_effect.reg, AnySymbol())
        elif isinstance(fallback_effect, Effect.Condition):
            return Effect.Condition(AnySymbol())
        elif isinstance(fallback_effect, Effect.Return):
            return Effect.Return(AnySymbol())
        elif isinstance(fallback_effect, Effect.Store):
            return Effect.Store(AnySymbol(), AnySymbol())
        else:
            raise ValueError(f"Fallback not supported for: {type(fallback_effect)}")

    else:
        raise ValueError(f"Unknown effect node: {label}")

def normalize_str(s: str) -> str:
    # 모든 공백 문자(\n, \r, \t, 스페이스 등)를 제거
    return "".join(s.split())

def simplify_arith_cmp(expr):
    """
    산술 비교식에서 (x - c) == k → x == (k + c)
    (x + c) == k → x == (k - c)
    (x * c) == k → x == (k // c) (단, c ≠ 0, k % c == 0)
    (x // c) == k → x == (k * c)
    등으로 단순화.
    """
    def get_int(val):
        if hasattr(val, "value"):
            return int(val.value)
        return int(val)

    if isinstance(expr, Binop) and expr.op.startswith("Iop_CmpEQ"):
        left, right = expr.args
        # (Sub(x, c), k) → (x, k + c)
        if isinstance(left, Binop) and left.op.startswith("Iop_Sub"):
            x, c = left.args
            if isinstance(c, Const) and isinstance(right, Const):
                new_val = get_int(right.con) + get_int(c.con)
                return Binop(expr.op, [x, Const(new_val)])
        # (Add(x, c), k) → (x, k - c)
        if isinstance(left, Binop) and left.op.startswith("Iop_Add"):
            x, c = left.args
            if isinstance(c, Const) and isinstance(right, Const):
                new_val = get_int(right.con) - get_int(c.con)
                return Binop(expr.op, [x, Const(new_val)])
        # (Mul(x, c), k) → (x, k // c) (단, c ≠ 0, k % c == 0)
        if isinstance(left, Binop) and left.op.startswith("Iop_Mul"):
            x, c = left.args
            if isinstance(c, Const) and isinstance(right, Const):
                c_val = get_int(c.con)
                k_val = get_int(right.con)
                if c_val != 0 and k_val % c_val == 0:
                    new_val = k_val // c_val
                    return Binop(expr.op, [x, Const(new_val)])
        # (Div(x, c), k) → (x, k * c) (단, c ≠ 0)
        if isinstance(left, Binop) and (left.op.startswith("Iop_Div") or left.op.startswith("Iop_DivU")):
            x, c = left.args
            if isinstance(c, Const) and isinstance(right, Const):
                c_val = get_int(c.con)
                k_val = get_int(right.con)
                if c_val != 0:
                    new_val = k_val * c_val
                    return Binop(expr.op, [x, Const(new_val)])
        # (x, Sub(k, c)) → (x, k - c)
        if isinstance(right, Binop) and right.op.startswith("Iop_Sub"):
            k, c = right.args
            if isinstance(k, Const) and isinstance(c, Const):
                new_val = get_int(k.con) - get_int(c.con)
                return Binop(expr.op, [left, Const(new_val)])
        # (x, Add(k, c)) → (x, k + c)
        if isinstance(right, Binop) and right.op.startswith("Iop_Add"):
            k, c = right.args
            if isinstance(k, Const) and isinstance(c, Const):
                new_val = get_int(k.con) + get_int(c.con)
                return Binop(expr.op, [left, Const(new_val)])
        # (x, Mul(k, c)) → (x, k * c)
        if isinstance(right, Binop) and right.op.startswith("Iop_Mul"):
            k, c = right.args
            if isinstance(k, Const) and isinstance(c, Const):
                new_val = get_int(k.con) * get_int(c.con)
                return Binop(expr.op, [left, Const(new_val)])
        # (x, Div(k, c)) → (x, k // c) (단, c ≠ 0)
        if isinstance(right, Binop) and (right.op.startswith("Iop_Div") or right.op.startswith("Iop_DivU")):
            k, c = right.args
            if isinstance(k, Const) and isinstance(c, Const):
                c_val = get_int(c.con)
                k_val = get_int(k.con)
                if c_val != 0:
                    new_val = k_val // c_val
                    return Binop(expr.op, [left, Const(new_val)])

    # 재귀적으로 내부도 처리
    if isinstance(expr, Binop):
        return Binop(expr.op, [simplify_arith_cmp(expr.args[0]), simplify_arith_cmp(expr.args[1])])
    elif isinstance(expr, Unop):
        return Unop(expr.op, [simplify_arith_cmp(expr.args[0])])
    elif isinstance(expr, Load):
        return Load(expr.end, simplify_arith_cmp(expr.addr))
    elif isinstance(expr, ITE):
        return ITE(simplify_arith_cmp(expr.cond), simplify_arith_cmp(expr.iffalse), simplify_arith_cmp(expr.iftrue))
    elif isinstance(expr, list):
        return [simplify_arith_cmp(e) for e in expr]
    else:
        return expr
