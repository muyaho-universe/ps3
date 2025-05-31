from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
import pyvex.const as pc
from inspect_info import InspectInfo
from typing import Iterator
from copy import deepcopy
from simplify import simplify
from node import Node
from itertools import product
from collections import deque
from partail_eq import is_generalization_of


def tree_possible_subs(tree: Node, fallback_effect: Effect) -> Iterator[Effect]:
    print(f"tree_possible_subs(tree{tree.print()})")
    # 각 노드에서 가능한 대체 표현을 재귀적으로 생성
    def helper(node: Node) -> list[Node]:
        print(f"helper(node{node.label})")
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
    print("helper done")
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
        print("go into other with info:", info)
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
                
            # if str(new_info) == "Put: 32 = 1 + T":
            #     # for item in other:
            #     #     if str(item) == "Put: 32 = 2 + FakeRet(bn_get_top)":
            #     print("other:", other) # Put: 64 = 2 + FakeRet(bn_get_top), Put: 32 = 2 + FakeRet(bn_get_top), Call: bn_wexpand(FakeRet(BN_CTX_get), 2 + FakeRet(bn_get_top))
            #     print(f"Found: {new_info}, new_info in other: {new_info in other}") # False
            #     # print(f"type(new_info.ins.expr.args[0]): {type(new_info.ins.expr.args[0])}")
            #     # print(f"type(item.ins.expr.args[0]): {type(item.ins.expr.args[0])} {item.ins.expr.args[0]}")
            #     exit(1)
            print("go into other with new_info:", new_info)
            if go and new_info not in other:
                myself[i] = new_info
                go = False
                    # break  # 다른 효과와 겹치지 않는 첫 번째 generalized_tree를 찾으면 중단

                

        result.append(temp)
    print(f"refine result: {result}")
    return myself 


def refine_sig(vuln_effect: list[InspectInfo], patch_effect: list[InspectInfo]) -> tuple[list[InspectInfo], list[InspectInfo]]:    
    old_vuln_effect = deepcopy(vuln_effect)
    old_patch_effect = deepcopy(patch_effect)
    
    vuln_effect = simplify_effects(vuln_effect)
    patch_effect = simplify_effects(patch_effect)
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
    
    print(f"old_vuln_effect: {old_vuln_effect}")
    print(f"vuln_effect: {vuln_effect}")
    print("=" * 50)
    patch_effect = refine_one(patch_effect, vuln_effect)
    print(f"old_patch_effect: {old_patch_effect}")
    print(f"patch_effect: {patch_effect}")
    print("=" * 50)

    # for i in (0, 1):
    #     if isinstance(vuln_effect[i][0].ins, Effect.Put):
    #         print(f"vuln_effect[{i}]: {vuln_effect[i]}")
    #         print(f"vuln_effect[{i}][1].ins: {vuln_effect[i][1].ins.expr}, type: {type(vuln_effect[i][1].ins.expr)}")
    #         print(f"vuln_effect[{i}][3].ins: {vuln_effect[i][2].ins.expr}, type: {type(vuln_effect[i][3].ins.expr)}")
    
    exit(1)
    return vuln_effect, patch_effect   

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
        return ITE(cond, iftrue, iffalse)

    elif node.label.startswith("Get(offset="):
        offset = int(node.label[len("Get(offset="):-1])
        return Get(offset)

    elif node.label.startswith("RdTmp(t"):
        tmp = int(node.label[len("RdTmp(t"):-1])
        return RdTmp(tmp)

    elif node.label.startswith("Const: T"):
        return Const(AnySymbol())

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