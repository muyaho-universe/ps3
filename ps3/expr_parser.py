from pyvex.expr import IRExpr, Binop, Const, Unop, Load, IRConst, ITE, CCall, RdTmp, Get
from symbol_value import AnySymbol, RegSymbol, ReturnSymbol, MemSymbol, SymbolicValue, WildCardSymbol
import re


def parse_expr(expr_str):
    expr_str = expr_str.strip()
    binops = [
        ("==", "Iop_CmpEQ64"),
        ("!=", "Iop_CmpNE64"),
        ("<=", "Iop_CmpLE64S"),
        (">=", "Iop_CmpGE64S"),
        ("<", "Iop_CmpLT64S"),
        (">", "Iop_CmpGT64S"),
        ("|", "Iop_Or64"),
        ("^~", "Iop_XorNot64"),
        ("^", "Iop_Xor64"),
        ("+", "Iop_Add64"),
        ("-", "Iop_Sub64"),
        ("*", "Iop_Mul64"),
        ("/", "Iop_Div64S"),
        ("%", "Iop_Mod64S"),
        ("&", "Iop_And64"),
        ("<<", "Iop_Shl64"),
        (">>", "Iop_Shr64S"),
    ]
    if expr_str == "True":
        # 1 == 1을 CmpEQ64로 표현 (항상 True)
        return Binop("Iop_CmpEQ64", [Const(1), Const(1)])
    if expr_str == "False":
        # 1 == 0을 CmpEQ64로 표현 (항상 False)
        return Binop("Iop_CmpEQ64", [Const(1), Const(0)])
    # WildCard
    if expr_str == "WildCard":
        return WildCardSymbol()
    # T (AnySymbol)
    if expr_str == "T":
        return AnySymbol()
    
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

    for op_str, op_name in binops:
        # 괄호 깊이 0에서 op_str로 split
        depth = 0
        split_indices = []
        for i in range(len(expr_str) - len(op_str) + 1):
            if expr_str[i] == '(':
                depth += 1
            elif expr_str[i] == ')':
                depth -= 1
            elif expr_str[i:i+len(op_str)] == op_str and depth == 0:
                split_indices.append(i)
       
        if split_indices:
            # 오른쪽 결합: 마지막 연산자를 기준으로 분리
            idx = split_indices[-1]
            left = expr_str[:idx]
            right = expr_str[idx+len(op_str):]
            if op_name.startswith("Iop_Cmp"):
                # 비교 연산자는 왼쪽이 먼저 오도록
                return ITE(Binop(op_name, [parse_expr(left), parse_expr(right)]), Const(1), Const(0))
            return Binop(op_name, [parse_expr(left), parse_expr(right)])
        
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
                last = i + 1
        args.append(inner[last:].strip())

        if len(args) != 3:
            raise ValueError(f"If() must have 3 arguments: {expr_str}")
        # if expr_str == normalize_str("If(Mem(48 + Mem(SR(72))) <= SR(88), 0, 1)"):
        #         print(f"parse_expr: {expr_str} args[0]: {args[0]}, args[1]: {args[1]}, args[2]: {args[2]}")
        #         exit(1)
        ret = ITE(parse_expr(args[0]), parse_expr(args[2]), parse_expr(args[1]))
        # print(f"parse_expr: ITE found: ITE:{ret}, InsepctInfo: {InspectInfo(Effect.Condition(ret))}")
        return ret
        # return ITE(parse_expr(args[0]), parse_expr(args[1]), parse_expr(args[2]))

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
