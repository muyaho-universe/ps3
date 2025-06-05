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
    result = []
    for i, info in enumerate(myself):
        effect = deepcopy(info.ins) 
        temp = []
        count = 0
        go = True
        # print("go into other with info:", info)
        root = effect_to_node(info.ins)
        for generalized_tree in tree_possible_subs(root, fallback_effect=effect):
            # try:
            #     new_effect = generalized_tree
            # except ValueError as e:
            #     print(f"Error converting node to effect: {e}, node: {generalized_tree.print()}")
            #     exit(1)
            new_effect = generalized_tree   
            new_info = InspectInfo(new_effect)
            temp.append(new_info)

            # if isinstance(new_info.ins, Effect.Call):

            # if count < 2  and  isinstance(effect, Effect.Put):
                
            #     count += 1
            # else:
            t = "Call: bn_wexpand(FakeRet(T), T)"
            t2 = "Call: bn_wexpand(T, 1 + T)"
            # print(f"new_info: {new_info} {str(new_info) == t }") # Put: 32 = 2 + FakeRet(bn_get_top)
            # if str(new_info) == t:
            #     print(other)
            #     for item in other:
            #         print(f"item: {item} {str(item) == t2}") # Put: 32 = 2 + FakeRet(bn_get_top)
            #         if str(item) == t2:
            # #     # print("other:", other) # Put: 64 = 2 + FakeRet(bn_get_top), Put: 32 = 2 + FakeRet(bn_get_top), Call: bn_wexpand(FakeRet(BN_CTX_get), 2 + FakeRet(bn_get_top))
            #             print("==========RALO==========")
            #             print(f"Found: {new_info} and {item}") # True
            #             r1 = effect_to_node(new_info.ins)
            #             r2 = effect_to_node(item.ins)
            #             print("-" * 50)
            #             # print(f"r1: {r1.print()}")
            #             r1.print()
            #             print("-" * 50)
            #             # print(f"r2: {r2.print()}")
            #             r2.print()
            #             print("-" * 50)
            #             # print(f"type({item.ins.expr.args[1].con}): {type(item.ins.expr.args[1].con)}") # <class 'inspect_info.InspectInfo'>
            #             print(f"new_info == item: {new_info == item}") # True
            #             print("==========RALO==========")
            #             exit(1)

            # if str(new_info) == "Put: 32 = 1 + FakeRet(T)":
            #     for item in other:
            #         if str(item) == "Put: 32 = 2 + FakeRet(bn_get_top)":
            #             print("==========RALO==========")
            #             print(f"Found: {new_info} and {item}") # False
            #             r1 = effect_to_node(new_info.ins)
            #             r2 = effect_to_node(item.ins)
            #             print("-" * 50)
            #             # print(f"r1: {r1.print()}")
            #             r1.print()
            #             print("-" * 50)
            #             # print(f"r2: {r2.print()}")
            #             r2.print()
            #             print("-" * 50)
            #             print(f"new_info == item: {new_info == item}") # False
            #             print("==========RALO==========")
            #             if go:
            #                 go = False
            #             else:
            #                 exit(1)
            #     # print(f"type(new_info.ins.expr.args[0]): {type(new_info.ins.expr.args[0])}")
            #     # print(f"type(item.ins.expr.args[0]): {type(item.ins.expr.args[0])} {item.ins.expr.args[0]}")
            #     exit(1)
            # print("go into other with new_info:", new_info)

            if go and new_info not in other :
                # print(f"refine_one: {new_info} not in other")
                myself[i] = new_info
                go = False
                break  # 다른 효과와 겹치지 않는 첫 번째 generalized_tree를 찾으면 중단

                
        
    #     result.append(temp)
    # print(f"refine result: {result}")
    # exit(0)
    return myself 


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

def parse_expr(expr_str):
    expr_str = expr_str.strip()

    # Helper: 괄호 매칭으로 내부 추출
    def extract_inner(s, prefix):
        assert s.startswith(prefix)
        depth = 0
        for i in range(len(prefix), len(s)):
            if s[i] == '(':
                depth += 1
            elif s[i] == ')':
                if depth == 0:
                    return s[len(prefix):i]
                depth -= 1
        # fallback: 마지막 )까지
        return s[len(prefix):-1]

    # FakeRet
    if expr_str.startswith("FakeRet(") and expr_str.endswith(")"): 
        inner = extract_inner(expr_str, "FakeRet(").strip()
        parsed = parse_expr(inner)
        if isinstance(parsed, ReturnSymbol):
            return parsed
        return ReturnSymbol(parsed)
    if expr_str == "FakeRet":
        return ReturnSymbol(None)
    # Mem
    if expr_str.startswith("Mem(") and expr_str.endswith(")"):
        inner = extract_inner(expr_str, "Mem(").strip()
        addr = parse_expr(inner)
        return MemSymbol(addr)
    # SR
    if expr_str.startswith("SR(") and expr_str.endswith(")"):
        inner = extract_inner(expr_str, "SR(").strip()
        # 숫자면 int, 아니면 재귀 파싱
        try:
            return RegSymbol(int(inner))
        except ValueError:
            return RegSymbol(parse_expr(inner))
    # WildCard
    if expr_str == "WildCard":
        return WildCardSymbol()
    # T (AnySymbol)
    if expr_str == "T":
        return AnySymbol()
    # If
    if expr_str.startswith("If(") and expr_str.endswith(")"):
        # 괄호 매칭으로 내부 추출
        inner = expr_str[3:-1]
        args = []
        depth = 0
        last = 0
        for i, ch in enumerate(inner):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ',' and depth == 0:
                args.append(inner[last:i].strip())
                last = i+1
        args.append(inner[last:].strip())
        if len(args) != 3:
            raise ValueError(f"If() must have 3 arguments: {expr_str}")
        # print(f"parse_expr: If() args[0]: {args[0]}")
        ret = ITE(parse_expr(args[0]), parse_expr(args[2]), parse_expr(args[1]))
        # print(f"parse_expr: ITE found: ITE:{ret}, InsepctInfo: {InspectInfo(Effect.Condition(ret))}")
        return ret
        # return ITE(parse_expr(args[0]), parse_expr(args[1]), parse_expr(args[2]))

    # Binop: 가장 바깥의 +만 분리
    # 연산자 우선순위: 괄호 깊이 0에서 오른쪽부터 차례로 분리
    # Binop: 괄호 깊이 0에서 연산자 분리
    binops = [
        (" == ", "Iop_CmpEQ64"),
        (" != ", "Iop_CmpNE64"),
        (" <= ", "Iop_CmpLE64S"),
        (" >= ", "Iop_CmpGE64S"),
        (" < ", "Iop_CmpLT64S"),
        (" > ", "Iop_CmpGT64S"),
        (" | ", "Iop_Or64"),
        (" ^~ ", "Iop_XorNot64"),
        (" ^ ", "Iop_Xor64"),
        (" + ", "Iop_Add64"),
        (" - ", "Iop_Sub64"),
    ]
    for op_str, op_name in binops:
        depth = 0
        for i in range(len(expr_str) - len(op_str) + 1):
            if expr_str[i] == '(':
                depth += 1
            elif expr_str[i] == ')':
                depth -= 1
            elif expr_str[i:i+len(op_str)] == op_str and depth == 0:
                left = expr_str[:i]
                right = expr_str[i+len(op_str):]

                # left_expr = parse_expr(left)
                # right_expr = parse_expr(right)

                # if not isinstance(left_expr, IRExpr):
                #     left_expr = Unop("Iop_64to32", [left_expr])
                # if not isinstance(right_expr, IRExpr):
                #     right_expr = Unop("Iop_64to32", [right_expr])

                # ret = Binop(op_name, [left_expr, right_expr])
                # print(f"parse_expr: Binop found: {op_name} with left: {left} and right: {right} and ret: {ret}")
                ret = Binop(op_name, [parse_expr(left), parse_expr(right)])
                # print(f"parse_expr: Binop found: {op_name} with left: {left} and right: {right} and ret: {ret}")
                # return Binop(op_name, [parse_expr(left), parse_expr(right)])
                return ret

    # 단항 연산자: ~
    if expr_str.startswith("~"):
        rest = expr_str[1:].lstrip()
        if rest.startswith("("):
            # 괄호 매칭으로 ~() 전체를 추출
            depth = 0
            for i, ch in enumerate(rest):
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                    if depth == 0:
                        # i는 닫는 괄호 위치
                        inner = rest[1:i]
                        after = rest[i+1:].strip()
                        # ~(...) 뒤에 또 연산자가 붙을 수도 있으니, after가 있으면 재귀 파싱
                        if after:
                            # ~(...)뒤에 연산자가 붙는 경우: ~(...) | ... 등
                            return parse_expr(f"~({inner}) {after}")
                        return Unop("Iop_Not64", [parse_expr(inner)])
            # 괄호가 안 맞으면 그냥 전체를 넘김
            return Unop("Iop_Not64", [parse_expr(rest)])
        else:
            return Unop("Iop_Not64", [parse_expr(rest)])

    # int
    if expr_str.isdigit():
        return Const(int(expr_str))

    # 알파벳, 언더스코어 등으로만 이루어진 경우(심볼)
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", expr_str):
        return expr_str

    # 함수형 연산자: Concat, Extract, Subpiece, ZeroExt 등
    for func in ["Concat", "Extract", "Subpiece", "ZeroExt"]:
        if expr_str.startswith(f"{func}(") and expr_str.endswith(")"):
            inner = expr_str[len(func) + 1:-1]
            args = []
            depth = 0
            last = 0
            for i, ch in enumerate(inner):
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    args.append(inner[last:i].strip())
                    last = i + 1
            args.append(inner[last:].strip())
            # 각 함수에 맞는 pyvex 표현으로 변환
            if func == "Concat":
                return CCall("Iop_Concat", [parse_expr(a) for a in args])
            elif func == "Extract":
                return CCall("Ity_I64", "Iop_Extract64", [parse_expr(a) for a in args])
            elif func == "Subpiece":
                return CCall("Ity_I64", "Iop_Subpiece64", [parse_expr(a) for a in args])
            elif func == "ZeroExt":
                return CCall("Ity_I64", "Iop_ZeroExt64", [parse_expr(a) for a in args])

    raise ValueError(f"parse_expr: 파싱 실패: {expr_str}")

def rebuild_effects(effect: InspectInfo) -> InspectInfo:
    """
    InspectInfo를 받아서, str 형태 그대로 최소화된 effect로 변환합니다.
    """
    original_str = str(effect).strip().replace('\n', '')
    # temp = "Condition: If(FakeRet == 0, 0, 1)"
    # if original_str == temp:
    #     print(f"effect.ins.expr.cond: {effect.ins.expr.args[0].args[0].args[0].args[0].args[0].args[0].con.name}, type: {type(effect.ins.expr.args[0].args[0].args[0].args[0].args[0].args[0].con.name)}")
    #     exit(1)
    concat = "Concat"
    hat = "^"
    extract = "Extract"
    if concat in original_str or hat in original_str or extract in original_str:
        # Concat이나 ^가 있는 경우는 처리하지 않음
        return effect
    if "Put: " in original_str:
        parts = original_str.split(" = ")
        reg_part = parts[0].replace("Put: ", "").strip()
        expr_part = parts[1].strip()
        reg = int(reg_part)
        expr = parse_expr(expr_part)
        ret = InspectInfo(Effect.Put(reg, expr))
        if original_str != str(ret):
            print(f"Rebuild failed for Put: {original_str} != {str(ret)}")
            exit(1)
        return ret
    elif "Call: " in original_str:
        # Call: name(arg1, arg2, ...)
        m = re.match(r"Call: ([^(]+)\((.*)\)", original_str)
        if not m:
            raise ValueError(f"Cannot parse Call: {original_str}")
        name = m.group(1).strip()
        args_str = m.group(2).strip()
        # 괄호 깊이 기반 인자 분리
        args = []
        current = ""
        depth = 0
        for ch in args_str:
            if ch == "," and depth == 0:
                if current.strip():
                    args.append(current.strip())
                current = ""
            else:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                current += ch
        if current.strip():
            args.append(current.strip())
        args = [parse_expr(a) for a in args]
        ret = InspectInfo(Effect.Call(name, args))
        if original_str != str(ret):
            print(f"Rebuild failed for Call: {original_str} != {str(ret)}")
            exit(1)
        return ret
    elif "Condition: " in original_str:
        expr_part = original_str.replace("Condition: ", "").strip()
        expr = parse_expr(expr_part)
        ret = InspectInfo(Effect.Condition(expr))
        if original_str != str(ret):
            print(f"Rebuild failed for Condition: {original_str} != {str(ret)}")
            exit(1)
        return ret
    elif "Return: " in original_str:
        expr_part = original_str.replace("Return: ", "").strip()
        expr = parse_expr(expr_part)
        ret = InspectInfo(Effect.Return(expr))
        if original_str != str(ret):
            print(f"Rebuild failed for Return: {original_str} != {str(ret)}")
            exit(1)
        return ret
    elif "Store: " in original_str:
        parts = original_str.split(" = ")
        addr_part = parts[0].replace("Store: ", "").strip()
        expr_part = parts[-1].strip()
        addr = parse_expr(addr_part)
        expr = parse_expr(expr_part)
        ret = InspectInfo(Effect.Store(addr, expr))
        if original_str != str(ret):
            print(f"Rebuild failed for Store: {original_str} != {str(ret)}")
            exit(1)
        return ret
    else:
        print(f"Unknown effect format: {original_str}")
        exit(1)

def simplify_addr_expr(expr):
    """
    연속된 Sub64/Add64의 상수 부분을 모두 누적해서 단순화.
    예: Sub64(Sub64(Sub64(SR(48), 8) + 8) + 8) → Sub64(SR(48), 8*n)
    """
    base = expr
    total = 0
    sign = 1
    while isinstance(base, Binop):
        if base.op == "Iop_Sub64":
            left, right = base.args
            # 오른쪽이 상수면 누적
            if isinstance(right, (Const, int)):
                val = right.con if isinstance(right, Const) else right
                # pyvex U64/U32 등은 .value, 아니면 int 변환
                if hasattr(val, "value"):
                    val = val.value
                val = int(val)
                total += sign * val
                base = left
                sign = 1
            else:
                break
        elif base.op == "Iop_Add64":
            left, right = base.args
            if isinstance(right, (Const, int)):
                val = right.con if isinstance(right, Const) else right
                if hasattr(val, "value"):
                    val = val.value
                val = int(val)
                total += sign * val
                base = left
            else:
                break
        else:
            break
    # base가 더 이상 Binop이 아니면, 누적된 상수와 함께 재구성
    if total == 0:
        return base
    else:
        return Binop("Iop_Sub64", [base, Const(total)])

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
        return Node(f"ReturnSymbol", [expr_to_node(expr.name, level + 1)], level=level)
    elif isinstance(expr, (pc.F32, pc.F64, pc.U1, pc.U8, pc.U16, pc.U32, pc.U64)):
        return Node(f"IRConst: {expr.value}", level=level)
       
    elif isinstance(expr, CCall):
        # 함수명과 타입을 노드에 기록, 인자들은 자식 노드로
        return Node(f"CCall({expr.cee}:{expr.retty})", [expr_to_node(arg, level + 1) for arg in expr.args], level)
        
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

    else:
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