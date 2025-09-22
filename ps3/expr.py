import pyvex.expr as pe
import pyvex.const as pc
from symbol_value import ReturnSymbol
from env import Environment
from inspect_info import InspectInfo
from effect import Effect

def amd64g_to_ite(expr: pe.CCall, env: Environment) -> pe.IRExpr:
    """
    Converts amd64g_calculate_conditionX calls to ITE expressions.
    amd64g_calculate_condition은 다음과 같이 구성되어 있음
    amd64g_calculate_condition(cond, cc_op, cc_dep1, cc_dep2, cc_ndep)
    cond: 조건 코드, 매핑 정보는 다음과 같음
    AMD64CondO   = 0   // JO  - Overflow
    AMD64CondNO  = 1   // JNO - No Overflow  
    AMD64CondB   = 2   // JB  - Below (Carry set)
    AMD64CondNB  = 3   // JNB - Not Below (Carry clear)
    AMD64CondZ   = 4   // JZ/JE - Zero/Equal
    AMD64CondNZ  = 5   // JNZ/JNE - Not Zero/Not Equal
    AMD64CondBE  = 6   // JBE - Below or Equal
    AMD64CondNBE = 7   // JNBE - Not Below or Equal
    AMD64CondS   = 8   // JS  - Sign (negative)
    AMD64CondNS  = 9   // JNS - No Sign (positive)
    AMD64CondP   = 10  // JP  - Parity Even
    AMD64CondNP  = 11  // JNP - Parity Odd
    AMD64CondL   = 12  // JL  - Less (signed)
    AMD64CondNL  = 13  // JNL - Not Less (signed)
    AMD64CondLE  = 14  // JLE - Less or Equal (signed)  
    AMD64CondNLE = 15  // JNLE - Not Less or Equal (signed)
    ex) amd64g_calculate_condition(0xe, 0x14, t35, 0x0, t94) (t35 = GET:I64(r14), t94 = GET:I64(cc_ndep)) 
        -> test r14, r14, jle ***, if (r14 <= 0) then 1 else 0 
        -> ITE(LE(r14, 0), 1, 0)
    ex) amd64g_calculate_condition(0x000000000000000e,0x0000000000000014,t2,0x0000000000000000,t7) (t2 = GET:I64(r13), t7 = GET:I64(cc_ndep))
        -> test r13, r13, jle ***, if (r13 <= 0) then 1 else 0
        -> ITE(LE(r13, 0), 1, 0)
    """
    cond_map = {
        0: 'Iop_CmpLT64S',   # JO  - Overflow
        1: 'Iop_CmpGE64S',   # JNO - No Overflow
        2: 'Iop_CmpULT64S',  # JB  - Below (Carry set)
        3: 'Iop_CmpUGE64S',  # JNB - Not Below (Carry clear)
        4: 'Iop_CmpEQ64',   # JZ/JE - Zero/Equal
        5: 'Iop_CmpNE64',   # JNZ/JNE - Not Zero/Not Equal
        6: 'Iop_CmpULE64S',  # JBE - Below or Equal
        7: 'Iop_CmpUGT64S',  # JNBE - Not Below or Equal
        8: 'Iop_CmpLT64S',   # JS  - Sign (negative)
        9: 'Iop_CmpGE64S',   # JNS - No Sign (positive)
        10: 'Iop_CmpPar64S', # JP  - Parity Even
        11: 'Iop_CmpPnr64S', # JNP - Parity Odd
        12: 'Iop_CmpLT64S',  # JL  - Less (signed)
        13: 'Iop_CmpGE64S',  # JNL - Not Less (signed)
        14: 'Iop_CmpLE64S',  # JLE - Less or Equal (signed)
        15: 'Iop_CmpGT64S',  # JNLE - Not Less or Equal (signed)
    }
    args = expr.args
    if len(args) < 5:
        print(f"Invalid number of arguments for amd64g_calculate_condition: {len(args)}")
        exit(1)
    op = int(str(args[0]), 16)
    dep1= args[2]
    dep2 = args[3]
    cond_op = cond_map.get(op)
    if cond_op is None:
        print(f"Unsupported condition code: {op}")
        exit(1)
    dep1_reduced = reduce(dep1, env)
    dep2_reduced = reduce(dep2, env)
    cond = pe.Binop(cond_op, [dep1_reduced, dep2_reduced])
    true_branch = pe.Const(pc.U64(1))
    false_branch = pe.Const(pc.U64(0))
    # Iop_1Uto64 means bool
    # ite_expr = pe.ITE(cond, true_branch, false_branch)
    # ite_effect = Effect.Condition(expr=ite_expr)
    # ite_info = InspectInfo(ite_effect)

    bool_expr = pe.Unop('Iop_1Uto64', [cond])
    bool_effect = Effect.Condition(expr=bool_expr)
    bool_info = InspectInfo(bool_effect)
    # print(f"Converted amd64g_calculate_condition to ITE: {ite_expr}\nwith InspectInfo: {ite_info}")
    # print(f"Also created bool expression: {bool_expr}\nwith InspectInfo: {bool_info}")
    # print(f"ite_info == bool_info: {ite_info == bool_info}")
    return bool_expr

    
def reduce(expr: pe.IRExpr | pc.IRConst, env: Environment) -> pe.IRExpr:
    if not isinstance(expr, pe.IRExpr):
        if isinstance(expr, pc.IRConst):
            return expr
        print(f"{type(expr)} is not IRExpr | IRConst.")
        assert False
    # if isinstance(expr, pe.VECRET):
    #     return expr
    # if isinstance(expr, pe.GSPTR):
    #     return expr
    if isinstance(expr, pe.Binop):
        return pe.Binop(expr.op, [reduce(expr.args[0], env), reduce(expr.args[1], env)])
    if isinstance(expr, pe.Unop):
        return pe.Unop(expr.op, [reduce(expr.args[0], env)])
    # if isinstance(expr, pe.GetI):
    #     return pe.GetI(expr.descr, reduce(expr.ix, env))
    if isinstance(expr, pe.RdTmp):
        return env.get_tmp(expr.tmp)
    if isinstance(expr, pe.Get):
        return env.get_reg(expr.offset)
    if isinstance(expr, pe.Qop):
        return pe.Qop(expr.op, [reduce(arg, env) for arg in expr.args])
    if isinstance(expr, pe.Triop):
        return pe.Triop(expr.op, [reduce(arg, env) for arg in expr.args])
    if isinstance(expr, pe.Load):
        return env.get_mem(reduce(expr.addr, env))
    # if isinstance(expr, pe.ITE):
    #     return pe.ITE(reduce(expr.cond, env), reduce(expr.iftrue, env), reduce(expr.iffalse, env))
    if isinstance(expr, pe.Const):
        return expr
    if isinstance(expr, pe.CCall):
        if expr.cee.name.startswith("amd64g_calculate_condition"):
            # print(f"STARTSWITH: expr: {expr}, type(expr): {type(expr)}")
            # print(f" expr.cee: {expr.cee}, type(expr.cee): {type(expr.cee)}")
            # print(f" expr.cee.name: {expr.cee.name}, type(expr.cee.name): {type(expr.cee.name)}")
            # for arg in expr.args:
            #     print(f" arg: {arg}, type(arg): {type(arg)}")
            # cond = pe.Binop(
            #     'Iop_CmpEQ64',
            #     [
            #         pe.Get(16, 'Ity_I64'),      # rax (예시 offset=16)
            #         pe.Const(pc.U64(100))    # 64비트 상수 100
            #     ]
            # )

            # true_branch = pe.Const(pc.U64(1))
            # false_branch = pe.Const(pc.U64(0))
            # ite_expr = pe.ITE(cond, true_branch, false_branch)
            # print(f"ite_expr: {ite_expr}, type(ite_expr): {type(ite_expr)}")
            # return ite_expr # for debug
            try:
                new_expr = amd64g_to_ite(expr, env)
                # print(f"new_expr: {new_expr}, type(new_expr): {type(new_expr)}")
                return new_expr
            except Exception as e:
                print(f"Error occurred: {e}")
                exit(1)
        return ReturnSymbol(name=expr.cee.name)
    if isinstance(expr, pe.ITE):
        return pe.ITE(reduce(expr.cond, env), reduce(expr.iftrue, env), reduce(expr.iffalse, env))
    print(f"{type(expr)} is not considered.")
    assert False

def contain_symbol(expr: pe.IRExpr) -> bool:
    string = str(expr)
    return "FakeReturn" in string or "Mem" in string or "SR" in string

class Expression:
    def __init__(self, expr: pe.IRExpr):
        self.expr = expr
    
    @classmethod
    def construct(expr: pe.IRExpr):
        if isinstance(expr, pe.VECRET):
            return VECRET(expr)
        elif isinstance(expr, pe.GSPTR):
            return GSPTR(expr)
        elif isinstance(expr, pe.GetI):
            return GetI(expr)
        elif isinstance(expr, pe.RdTmp):
            return RdTmp(expr)
        elif isinstance(expr, pe.Get):
            return Get(expr)
        elif isinstance(expr, pe.Qop):
            return Qop(expr)
        elif isinstance(expr, pe.Triop):
            return Triop(expr)
        elif isinstance(expr, pe.Binop):
            return Binop(expr)
        elif isinstance(expr, pe.Unop):
            return Unop(expr)
        elif isinstance(expr, pe.Load):
            return Load(expr)
        elif isinstance(expr, pe.ITE):
            return ITE(expr)
        elif isinstance(expr, pe.CCall):
            return CCall(expr)
        else:
            raise NotImplementedError("You should implement this method in the subclass")

    def __str__(self) -> str:
        return str(self.expr)
    
    def reduce(self, env: Environment) -> "Expression":
        self.expr.replace_expression()
        raise NotImplementedError("You should implement this method in the subclass")
    
class VECRET(Expression):
    def __init__(self, expr: pe.VECRET):
        self.expr = expr
    
    def reduce(self, env: Environment):
        return self
        
class GSPTR(Expression):
    def __init__(self, expr: pe.IRExpr):
        self.expr = expr
    pass

class GetI(Expression):
    pass

class RdTmp(Expression):
    pass

class Get(Expression):
    pass

class Qop(Expression):
    pass

class Triop(Expression):
    pass

class Binop(Expression):
    pass

class Unop(Expression):
    pass

class Load(Expression):
    pass

class ITE(Expression):
    pass

class CCall(Expression):
    pass

class Const(Expression):
    pass

