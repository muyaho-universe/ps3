import z3
import simplify as simplify
import pyvex.expr as pe
import pyvex.const as pc
from pyvex.expr import *
from symbol_value import MemSymbol, AnySymbol, RegSymbol
from effect import Effect
from inspect_info import InspectInfo
from refinement import strip_trivial_unop, simplify_arith_cmp, simplify_all_addr_expr
# i = z3.Extract(7, 0, z3.BitVec('x', 64))  # x의 하위 8비트
# j = z3.Concat(z3.BitVecVal(0, 56), i)  # x의 하위 8비트를 64비트로 확장
# print(i)
# print(type(i))
# print(j)
# print(type(j))

# a = 32Uto64(And32(64to32(32Uto64(8Uto32(Mem(SR(64))))),0x000000e0)
# b = pe.Unop("Iop_32Uto64", [pe.Binop("Iop_And32",
#                 [pe.Unop("Iop_64to32", [pe.Unop("Iop_32Uto64", [pe.Unop("Iop_8Uto32", [MemSymbol(RegSymbol(64))])])]),
#                 pe.Const(0x000000e0)])])
# a =  pe.Unop("Iop_32Uto64", [pe.Binop("Iop_And32", [MemSymbol(RegSymbol(64)), pe.Const(0x000000e0)])])
# a = pe.Binop("Iop_And32", [MemSymbol(RegSymbol(64)), pe.Const(0x000000e0)])
# info = InspectInfo(Effect.Put(RegSymbol(64), a))
# # print(a)
# sim = simplify.to_z3(a)
# # print(sim)
# # print(type(sim))

# sisi = str(z3.simplify(sim))
# # print(sisi)
# # print(type(sisi))
# zz = str(z3.simplify(simplify.to_z3(b)))

# # print(f"inspect info: {info}")
# print(f"a :{a}, b : {b}, {sisi} == {zz} : {sisi == zz}")


# b = 64to1(1Uto64(CmpEQ8(64to8(8Uto64(Sub8(32Uto64(8Uto32(Mem(Add64(Add64(SR(64),0x0000000000000003),0x0000000000000001)))),0x02))),64to8(0x0000000000000004))))

# b = Unop("Iop_1Uto64" ,[Binop("Iop_CmpEQ8", [
#         Unop("Iop_64to8", [
#             Unop("Iop_8Uto64", [
#                 Binop("Iop_Sub8", [
#                     Unop("Iop_32Uto64", [
#                         Unop("Iop_8Uto32", [MemSymbol(RegSymbol(64))])
#                     ]),
#                     Const(0x02)
#                 ])
#             ])
#         ]),
#         Unop("Iop_64to8", [Const(0x0000000000000004)])
#     ])
#     ]
# )

# b = Unop("Iop_1Uto64", [
#     Binop("Iop_CmpEQ32", [
#         MemSymbol(
#             Binop("Iop_Add64", [
#                 Binop(
#                     "Iop_Add64",
#                     [
#                         Binop("Iop_Add64", [
#                             RegSymbol(64),
#                             Const(0x0000000000000003)
#                         ]),
#                         Const(0x0000000000000002)
#                     ]
#                 ),
#                 Unop("Iop_32Uto64", [Const(0x0000000000000000)])
#                 ]
#             )
               
#         ),
#         Const(0x0000000000000000)
#     ])
# ])

# 64to1(1Uto64(CmpEQ32(64to32(32Uto64(64to32(32Uto64(8Uto32(Mem(Add64(Add64(Add64(SR(64),0x0000000000000003),0x0000000000000002),32Uto64(0x00000000)))))))),64to32(0x0000000000000000))))
# b = Unop("Iop_64to1", [
#     Unop("Iop_1Uto64", [
#         Binop("Iop_CmpEQ32", [
#             Unop("Iop_64to32", [
#                 Unop("Iop_32Uto64", [
#                     Unop("Iop_64to32", [
#                         Unop("Iop_32Uto64", [
#                             Unop("Iop_8Uto32", [
#                                 MemSymbol(
#                                     Binop("Iop_Add64", [
#                                         Binop("Iop_Add64", [
#                                             Binop("Iop_Add64", [
#                                                 RegSymbol(64),
#                                                 Const(U64(3))
#                                             ]),
#                                             Const(U64(2))
#                                         ]),
#                                         Unop("Iop_32Uto64", [Const(U64(0))])
#                                     ])
#                                 )
#                             ])
#                         ])
#                     ])
#                 ])
#             ]),
#             Unop("Iop_64to32", [Const(U64(0))])
#         ])
#     ])
# ])
# # 32Uto64(And32(64to32(32Uto64(8Uto32(Mem(SR(64))))),0x000000e0))
# b = Unop("Iop_32Uto64", [
#     Binop("Iop_And32", [
#         Unop("Iop_64to32", [
#             Unop("Iop_32Uto64", [
#                 Unop("Iop_8Uto32", [MemSymbol(RegSymbol(64))])
#             ])
#         ]),
#         Const(0x000000e0)
#     ])
# ])
# 64to1(1Uto64(CmpEQ32(64to32(32Uto64(64to32(32Uto64(8Uto32(Add8(Mem(Add64(Add64(SR(64),0x0000000000000003),0x0000000000000001)),0xfe)))))),64to32(0x0000000000000004))))
b = Unop("Iop_64to1", [
    Unop("Iop_1Uto64", [
        Binop("Iop_CmpEQ32", [
            Unop("Iop_64to32", [
                Unop("Iop_32Uto64", [
                    Unop("Iop_64to32", [
                        Unop("Iop_32Uto64", [
                            Unop("Iop_8Uto32", [
                                Binop("Iop_Add8", [
                                    MemSymbol(
                                        Binop("Iop_Add64", [
                                            Binop("Iop_Add64", [
                                                RegSymbol(64),
                                                Const(0x0000000000000003)
                                            ]),
                                            Const(0x0000000000000001)
                                        ])
                                    ),
                                    Const(0xfe)
                                ])
                            ])
                        ])
                    ])
                ])
            ]),
            Unop("Iop_64to32", [Const(0x0000000000000004)])
        ])
    ])
])



# print(f"b : {b}" )
# i = InspectInfo(Effect.Condition(b))
# print(f"i : {i}")
# def strip_trivial_unop(expr):
#     """
#     의미 없는 타입 변환(Unop) 껍데기를 재귀적으로 벗기고 core만 반환.
#     예: Unop("Iop_32Uto64", Unop("Iop_64to32", x)) -> strip_trivial_unop(x)
#     """
#     # 의미 없는 변환 목록 (필요시 추가)
#     print(f"strip_trivial_unop : {expr}, expr type : {type(expr)}, expr op : {getattr(expr, 'op', None)}")
#     trivial_unops = {
#         # Zero/Sign extend, truncate
#         "Iop_8Uto32", "Iop_16Uto32", "Iop_32Uto64", "Iop_8Uto64", 
#         # "Iop_1Uto64",
#         "Iop_8Sto32", "Iop_16Sto32", "Iop_32Sto64", "Iop_8Sto64", "Iop_1Sto64",
#         "Iop_64to32", "Iop_32to8", "Iop_32to16", "Iop_64to8", "Iop_64to16",
#         "Iop_8to32", "Iop_16to32", "Iop_8to64", "Iop_16to64", "Iop_32to64",
#         "Iop_64to1",
#         # Identity/bitcast
#         "Iop_Identity32", "Iop_Identity64", "Iop_Identity8", "Iop_Identity16",
#         "Iop_Bitcast32to32", "Iop_Bitcast64to64",
#         # Redundant ZeroExt/SignExt
#         "Iop_ZeroExt8to8", "Iop_ZeroExt16to16", "Iop_ZeroExt32to32", "Iop_ZeroExt64to64",
#         "Iop_SignExt8to8", "Iop_SignExt16to16", "Iop_SignExt32to32", "Iop_SignExt64to64",
#         # Redundant Extract/Concat
#         "Iop_Extract8", "Iop_Extract16", "Iop_Extract32", "Iop_Extract64",
#         "Iop_Concat8", "Iop_Concat16", "Iop_Concat32", "Iop_Concat64",
#         # No-op
#         "Iop_Copy", "Iop_Move",
#         # 기타
#         "Iop_1Uto8", "Iop_1Uto16", "Iop_1Uto32",
#         "Iop_8Uto8", "Iop_16Uto16", "Iop_32Uto32", "Iop_64Uto64",
#     }
#     # Unop이면서 의미 없는 변환이면 재귀적으로 벗김
#     while isinstance(expr, Unop) and expr.op in trivial_unops:
        
#         expr = expr.args[0]
#     # 내부도 재귀적으로 처리
#     if isinstance(expr, Unop):
#         return Unop(expr.op, [strip_trivial_unop(expr.args[0])])
#     elif isinstance(expr, Binop):
#         return Binop(expr.op, [strip_trivial_unop(expr.args[0]), strip_trivial_unop(expr.args[1])])
#     elif isinstance(expr, Load):
#         return Load(expr.end, strip_trivial_unop(expr.addr))
#     elif isinstance(expr, ITE):
#         # ITE(조건, iftrue, iffalse)에서 조건이 항상 True/False면 단순화
#         cond = strip_trivial_unop(expr.cond)
#         iftrue = strip_trivial_unop(expr.iftrue)
#         iffalse = strip_trivial_unop(expr.iffalse)
#         if isinstance(cond, Const):
#             try:
#                 val = int(cond.con)
#                 if val:
#                     return iftrue
#                 else:
#                     return iffalse
#             except Exception:
#                 pass
#         return ITE(cond, iffalse, iftrue)
#     elif isinstance(expr, list):
#         return [strip_trivial_unop(e) for e in expr]
#     elif isinstance(expr, MemSymbol):
#         # MemSymbol의 주소 부분도 재귀적으로 단순화
#         return MemSymbol(strip_trivial_unop(expr.address))
#     elif isinstance(expr, RegSymbol):
#         return RegSymbol(strip_trivial_unop(expr.offset))

#     else:
#         return expr
    
# def simplify_addr_expr(expr):
#     """
#     연속된 Sub64/Add64의 상수 부분을 모두 누적해서 단순화.
#     예: Add64(Add64(SR(64), 3), 1) → Add64(SR(64), 4)
#         Sub64(Sub64(SR(48), 8), 8) → Sub64(SR(48), 16)
#     """
#     print(f"simplify_addr_expr : {expr}, expr type : {type(expr)}")
#     base = expr
#     total = 0
#     while isinstance(base, Binop):
#         if base.op == "Iop_Sub64":
#             left, right = base.args
#             if isinstance(right, (Const, int)):
#                 val = right.con if isinstance(right, Const) else right
#                 if hasattr(val, "value"):
#                     val = val.value
#                 val = int(val)
#                 total -= val
#                 base = left
#             else:
#                 break
#         elif base.op == "Iop_Add64":
#             left, right = base.args
#             if isinstance(right, (Const, int)):
#                 val = right.con if isinstance(right, Const) else right
#                 if hasattr(val, "value"):
#                     val = val.value
#                 val = int(val)
#                 total += val
#                 base = left
#             else:
#                 break
#         else:
#             break
#     # base가 더 이상 Binop이 아니면, 누적된 상수와 함께 재구성
#     if total == 0:
#         return base
#     elif total > 0:
#         return Binop("Iop_Add64", [base, Const(total)])
#     else:
#         return Binop("Iop_Sub64", [base, Const(-total)])
    
# def simplify_arith_cmp(expr):
#     """
#     산술 비교식에서 (x - c) == k → x == (k + c)
#     (x + c) == k → x == (k - c)
#     등으로 단순화.
#     """
#     def get_int(val):
#         if hasattr(val, "value"):
#             return int(val.value)
#         return int(val)

#     if isinstance(expr, Binop) and expr.op.startswith("Iop_CmpEQ"):
#         left, right = expr.args
#         # (Sub8(x, c), k) → (x, k + c)
#         if isinstance(left, Binop) and left.op.startswith("Iop_Sub"):
#             x, c = left.args
#             if isinstance(c, Const) and isinstance(right, Const):
#                 new_val = get_int(right.con) + get_int(c.con)
#                 return Binop(expr.op, [x, Const(new_val)])
#         # (Add8(x, c), k) → (x, k - c)
#         if isinstance(left, Binop) and left.op.startswith("Iop_Add"):
#             x, c = left.args
#             if isinstance(c, Const) and isinstance(right, Const):
#                 new_val = get_int(right.con) - get_int(c.con)
#                 return Binop(expr.op, [x, Const(new_val)])
#         # (x, Sub8(k, c)) → (x, k - c)
#         if isinstance(right, Binop) and right.op.startswith("Iop_Sub"):
#             k, c = right.args
#             if isinstance(k, Const) and isinstance(c, Const):
#                 new_val = get_int(k.con) - get_int(c.con)
#                 return Binop(expr.op, [left, Const(new_val)])
#         # (x, Add8(k, c)) → (x, k + c)
#         if isinstance(right, Binop) and right.op.startswith("Iop_Add"):
#             k, c = right.args
#             if isinstance(k, Const) and isinstance(c, Const):
#                 new_val = get_int(k.con) + get_int(c.con)
#                 return Binop(expr.op, [left, Const(new_val)])
#     # 재귀적으로 내부도 처리
#     if isinstance(expr, Binop):
#         return Binop(expr.op, [simplify_arith_cmp(expr.args[0]), simplify_arith_cmp(expr.args[1])])
#     elif isinstance(expr, Unop):
#         return Unop(expr.op, [simplify_arith_cmp(expr.args[0])])
#     elif isinstance(expr, Load):
#         return Load(expr.end, simplify_arith_cmp(expr.addr))
#     elif isinstance(expr, ITE):
#         return ITE(simplify_arith_cmp(expr.cond), simplify_arith_cmp(expr.iftrue), simplify_arith_cmp(expr.iffalse))
#     elif isinstance(expr, list):
#         return [simplify_arith_cmp(e) for e in expr]
#     else:
#         return expr


# def simplify_all_addr_expr(expr):
#     """
#     모든 expr 내부의 Add64/Sub64에 대해 상수 누적 단순화를 재귀적으로 적용.
#     """
#     print(f"simplify_all_addr_expr : {expr}, expr type : {type(expr)}")
#     if isinstance(expr, Binop):
#         print(f"Binop : {expr.op}, args : {expr.args}")
#         if expr.op in ("Iop_Add64", "Iop_Sub64"):
#             simplified = simplify_addr_expr(expr)
#             return Binop(simplified.op, [simplify_all_addr_expr(simplified.args[0]), simplify_all_addr_expr(simplified.args[1])])
#         else:
#             return Binop(expr.op, [simplify_all_addr_expr(expr.args[0]), simplify_all_addr_expr(expr.args[1])])
#     elif isinstance(expr, Unop):
#         return Unop(expr.op, [simplify_all_addr_expr(expr.args[0])])
#     elif isinstance(expr, Load):
#         return Load(expr.end, simplify_all_addr_expr(expr.addr))
#     elif isinstance(expr, ITE):
#         return ITE(simplify_all_addr_expr(expr.cond), simplify_all_addr_expr(expr.iftrue), simplify_all_addr_expr(expr.iffalse))
#     elif isinstance(expr, MemSymbol):
#         # 주소 부분도 재귀적으로 단순화
#         return MemSymbol(simplify_all_addr_expr(expr.address))
#     elif isinstance(expr, RegSymbol):
#         return RegSymbol(simplify_all_addr_expr(expr.offset))
#     elif isinstance(expr, list):
#         return [simplify_all_addr_expr(e) for e in expr]
#     else:
#         return expr

# print(f"b : {b}")
# b = strip_trivial_unop(b)
# print(f"b strip_trivial_unop : {b}")
# bb= simplify_all_addr_expr(b)
# # 1Uto64(CmpEQ32(Add8(Mem(Add64(SR(64),4)),254),4))
# print(f"bb : {bb}")


ap = Unop("Iop_1Uto64", [
    Binop("Iop_CmpEQ32",[
        Binop("Iop_Add8", [
            MemSymbol(
                Binop("Iop_Add64", [
                    RegSymbol(64),
                    Const(4)
                ])
            ),
            Const(0xfe)
        ]),
        Const(4)
    ])
])

# print(f"ap : {ap}")
# azz = strip_trivial_unop(ap)
# print(f"azz : {azz}")
# aaa = simplify_all_addr_expr(azz)
# print(f"aaa : {aaa}")
# z = InspectInfo(Effect.Condition(aaa))
# print(f"z : {z}")

def calculator(expr: pe.IRExpr | pc.IRConst | int):
    """
    expr을 z3로 변환하고 단순화
    특히, Add64, Sub64 같이 64비트 주소가 아닐 경우, 64비트에 맞춰서 계산할 수 있도록
    ex) Add8(a, 0xfe) -> Sub64(a, 2); 8비트 계산에서 0xfe는 two's complement로 -2로 해석되므로 sub 2로 바꿔야함
    """
    print(f"calculator expr : {expr}, type : {type(expr)}")
    if isinstance(expr, Binop):
        match expr.op:
            case "Iop_Add64":
                # 64비트 주소 계산이므로, Add8, Add16, Add32는 Sub64로 변환
                return Binop("Iop_Sub64", [expr.args[0], Const(-int(expr.args[1].con))])
            case "Iop_Sub64":
                # 64비트 주소 계산이므로, Sub8, Sub16, Sub32는 Add64로 변환
                return Binop("Iop_Add64", [expr.args[0], Const(int(expr.args[1].con))])
            case "Iop_Add8":
                # 8비트 주소 계산이므로, two's complement가 적용되었는지 확인
                if isinstance(expr.args[1], Const):
                    val = int(expr.args[1].con)
                    print(f"Add8 value : {val}")
                    
                    if val > 0x7f:
                        # 8비트에서 -2는 0xfe로 표현되므로, Sub64로 변환
                        print(f"Add8 value is negative in 8-bit: {256 - val}")
                        return Binop("Iop_Sub64", [expr.args[0], Const(256 - val)])
                    else:
                        # 양수는 Add64로 변환
                        return Binop("Iop_Add64", [expr.args[0], Const(val)])
            case _:
                # 다른 Binop은 그대로 반환
                return Binop(expr.op, [calculator(expr.args[0]), calculator(expr.args[1])])
    elif isinstance(expr, Unop):
        # Unop의 경우, 내부 expr을 재귀적으로 처리
        return Unop(expr.op, [calculator(expr.args[0])])
    elif isinstance(expr, MemSymbol):
        # MemSymbol의 주소 부분도 재귀적으로 처리
        return MemSymbol(calculator(expr.address))
    else:
        # Const나 RegSymbol 등 다른 타입은 그대로 반환
        return expr

# zs = calculator(ap)
# print(f"zs : {zs}")
aaa = InspectInfo(Effect.Condition(ap))
print(f"aaa : {aaa}")

# aa = simplify.to_z3(bb)
# print(f"aa : {aa}")
# qqq = z3.simplify(aa)
# print(f"qqq : {qqq}")
# i = InspectInfo(Effect.Condition(bb))
# print(f"i : {i}")
# print(f"b strip_trivial_unop : {strip_trivial_unop(b)}")