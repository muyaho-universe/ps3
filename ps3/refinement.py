from effect import Effect
from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue
import pyvex.const as pc
from inspect_info import InspectInfo
from typing import Iterator
from copy import deepcopy
from simplify import simplify
from node import Node

# def possible_subs(expr) -> Iterator[IRExpr | SymbolicValue]:
#     # print(f"[possible_subs] Generating substitutions type {type(expr)}")
#     # yield AnySymbol()  # Always yield AnySymbol first
#     if isinstance(expr, IRExpr):
#         if isinstance(expr, Binop):
#             left, right = expr.args
#             if isinstance(left, (int, str, Const)):
#                 for rsub in possible_subs(right):
#                     yield Binop(expr.op, (AnySymbol(), rsub))

#             if isinstance(right, (int, str, Const)):
#                 for lsub in possible_subs(left):
#                     yield Binop(expr.op, (lsub, AnySymbol()))
#             for lsub in possible_subs(left):
#                 yield Binop(expr.op, (lsub, right))
#             for rsub in possible_subs(right):
#                 yield Binop(expr.op, (left, rsub))
            
#             yield expr
            

#         elif isinstance(expr, Unop):
#             for sub in possible_subs(expr.args[0]):
#                 yield Unop(expr.op, [sub])
#             yield expr  # 원래 표현식도 포함
#         # elif isinstance(expr, Load):
#         #     # yield Load(expr.end, AnySymbol())  # ⊤을 허용하는 경우
#         #     for sub in possible_subs(expr.addr):
#         #         yield Load(expr.end, expr.ty, sub)
#         # elif isinstance(expr, ITE):
#         #     for c in possible_subs(expr.cond):
#         #         yield ITE(c, expr.iftrue, expr.iffalse)
#         #     for t in possible_subs(expr.iftrue):
#         #         yield ITE(expr.cond, t, expr.iffalse)
#         #     for f in possible_subs(expr.iffalse):
#         #         yield ITE(expr.cond, expr.iftrue, f)
#         # elif isinstance(expr, CCall):
#         #     for i, arg in enumerate(expr.args):
#         #         # call은 level 1에서만 ⊤을 허용
#         #         new_args = list(expr.args)
#         #         new_args[i] = AnySymbol()
#         #         yield CCall(expr.retty, expr.cee, tuple(new_args))
#         elif isinstance(expr, Const):
#             yield from possible_subs(expr.con)  # Const의 값에 대해 ⊤을 허용하는 경우
#             yield expr  # 원래 표현식도 포함
#         else:
#             print(f"[possible_subs] Unknown IRExpr type: {expr} {type(expr)}")
#             exit(1)


#     elif isinstance(expr, IRConst):
#     #     # print(f"[possible_subs] IRConst: {expr}")
#     #     yield from possible_subs(expr)  # IRConst의 값에 대해 ⊤을 허용하는 경우
        
#         if isinstance(expr, SymbolicValue):
#             yield AnySymbol()  # ⊤을 허용하는 경우
#             if isinstance(expr.value, AnySymbol):
#                 return  
#             elif isinstance(expr, ReturnSymbol):
                
#                 for sub in possible_subs(expr.name):
#                     yield ReturnSymbol(sub)
#             elif isinstance(expr, MemSymbol):
#                 # yield MemSymbol(AnySymbol())  # ⊤을 허용하는 경우
#                 for sub in possible_subs(expr.address):
#                     yield MemSymbol(sub)
#         elif isinstance(expr, (pc.F32, pc.F64, pc.U1, pc.U8, pc.U16, pc.U32, pc.U64)):
#             yield from possible_subs(expr.value)  # IRConst의 값에 대해 ⊤을 허용하는 경우
#         else:
#             print(f"[possible_subs] Unknown IRConst type: {expr} {type(expr)}")
#             exit(1)
#     elif isinstance(expr, int) or isinstance(expr, str):
#         yield AnySymbol()  # int나 str 타입도 ⊤을 허용

#     else:
#         print(f"[possible_subs] Unknown expr type: {type(expr)}")
#         exit(1)

def tree_possible_subs(node: Node) -> Iterator[Node]:
    if not node.children:
        # 리프 노드는 자신과 AnySymbol 두 가지
        yield Node("AnySymbol", level=node.level)
        yield deepcopy(node)
        return

    # 자식들을 전부 재귀적으로 대체해봄
    for i, child in enumerate(node.children):
        for sub_child in tree_possible_subs(child):
            new_children = deepcopy(node.children)
            new_children[i] = sub_child
            yield Node(node.label, new_children, level=node.level)

    # 자기 자신도 항상 포함
    yield deepcopy(node)
        
def refine_one(myself: list[InspectInfo], other: list[InspectInfo]) -> list[InspectInfo]:
    result = []
    for i, info in enumerate(myself):
        effect = deepcopy(info.ins) 
        temp = []
        
        if isinstance(effect, Effect.Call):
            args = deepcopy(effect.args)
            any_args = [AnySymbol() for _ in args]
            new_call = InspectInfo(Effect.Call(effect.name, any_args))
            temp.append(new_call)
            # if new_call not in other:
                #     myself[i] = new_call
                #     break
            for j, arg in enumerate(args):
                # print(f"==========> {j}th arg: {arg} <==========")
                for sub in tree_possible_subs(arg):
                    # new_call = InspectInfo(Effect.Call(effect.name, args[:j] + [sub] + args[j+1:]))
                    # print(f"str(sub): {str(sub)}")
                    temp.append(sub)
                    # if new_call not in other:
                    #     myself[i] = new_call
                    #     break
            
        elif isinstance(effect, Effect.Condition):
            # if InspectInfo(Effect.Condition(AnySymbol())) not in other:
            #     new_condition = InspectInfo(Effect.Condition(AnySymbol()))
            #     temp.append(new_condition)
            # else:   
            for sub in tree_possible_subs(effect.expr):
                sub_effect = node_to_effect(sub)
                new_condition = InspectInfo(Effect.Condition(sub))
                temp.append(new_condition)
                # if new_condition not in other:
                #     myself[i] = new_condition
                #     break
        elif isinstance(effect, Effect.Return):
            for sub in tree_possible_subs(effect.expr):
                
                new_return = InspectInfo(Effect.Return(sub))
                
                temp.append(new_return)
                # if new_return not in other:
                #     myself[i] = new_return
                #     break

        elif isinstance(effect, Effect.Put):
            for sub in tree_possible_subs(effect.expr):
                # print(f"str(sub): {str(sub)}")
                if "T,T" in str(sub):
                    continue 
                new_put = InspectInfo(Effect.Put(effect.reg, sub))
                # if str(new_put) not in temp:
                # temp.append(new_put)
                # if new_put not in other:
                #     myself[i] = new_put
                #     break
        elif isinstance(effect, Effect.Store):
            for addr_sub in tree_possible_subs(effect.addr):
                for expr_sub in tree_possible_subs(effect.expr):
                    new_store = InspectInfo(Effect.Store(addr_sub, expr_sub))
                    temp.append(new_store)
                    # if new_store not in other:
                    #     myself[i] = new_store
                    #     break
        else:
            print(f"Unknown effect type: {type(effect)}")
            # exit(1)
            # raise ValueError(f"Unknown Effect type: {type(effect)}")
        # result.append(temp)
    return result 


def refine_sig(vuln_effect: list[InspectInfo], patch_effect: list[InspectInfo]) -> tuple[list[InspectInfo], list[InspectInfo]]:    
    old_vuln_effect = deepcopy(vuln_effect)
    old_patch_effect = deepcopy(patch_effect)
    
    vuln_effect = simplify_effects(vuln_effect)
    patch_effect = simplify_effects(patch_effect)
    temp = []
    print(f"vuln_effect: {vuln_effect}")
    for i in range(len(vuln_effect)):
        # if isinstance(vuln_effect[i].ins, Effect.Call):     
        tree = effect_to_node(vuln_effect[i].ins)
        tree.print()
        
        restored = node_to_effect(tree)
        print(f"restored: {InspectInfo(restored)}")
        temp.append(InspectInfo(restored))
        print("=" * 50)
    print(f"old == restored: {old_vuln_effect == temp}")
    # vuln_effect = refine_one(vuln_effect, patch_effect)
    # patch_effect = refine_one(patch_effect, vuln_effect)
    # print(f"old_vuln_effect: {old_vuln_effect}")
    # print(f"vuln_effect: {vuln_effect}")

    # for i in (0, 1):
    #     if isinstance(vuln_effect[i][0].ins, Effect.Put):
    #         print(f"vuln_effect[{i}]: {vuln_effect[i]}")
    #         print(f"vuln_effect[{i}][1].ins: {vuln_effect[i][1].ins.expr}, type: {type(vuln_effect[i][1].ins.expr)}")
    #         print(f"vuln_effect[{i}][3].ins: {vuln_effect[i][2].ins.expr}, type: {type(vuln_effect[i][3].ins.expr)}")
    
    exit(1)
    return vuln_effect, patch_effect   

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
            effect.ins.addr = simplify_expr(effect.ins.addr)
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
    

def node_to_effect(node: Node) -> Effect:
    label = node.label

    if label.startswith("Call("):
        name = label[len("Call("):-1]
        args_top = node.children[0]
        assert args_top.label == "args_top", "Expected args_top under Call"
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

    else:
        raise ValueError(f"Unknown effect node: {label}")