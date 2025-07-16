# from simplify import simplify, equal, show_equal
import simplify
from effect import Effect

def _pretty_z3(expr):
    """
    z3 BitVecVal의 2의 보수 음수 상수는 -로, Add/Sub는 수식 형태로 예쁘게 출력.
    """
    import z3

    # BitVecVal(2의 보수 음수, 64) -> -n
    if isinstance(expr, z3.BitVecNumRef):
        val = expr.as_long()
        if expr.size() == 64 and val > 0x7fffffffffffffff:
            neg = 0x10000000000000000 - val
            return f"-{neg}"
        return str(val)

    # Add/Sub 등 연산자 예쁘게
    if z3.is_app_of(expr, z3.Z3_OP_BADD) and len(expr.children()) == 2:
        left, right = expr.children()
        # 오른쪽이 2의 보수 음수면 -로 출력
        if isinstance(right, z3.BitVecNumRef) and right.size() == 64 and right.as_long() > 0x7fffffffffffffff:
            neg = 0x10000000000000000 - right.as_long()
            return f"{_pretty_z3(left)} - {neg}"
        return f"{_pretty_z3(left)} + {_pretty_z3(right)}"
    if z3.is_app_of(expr, z3.Z3_OP_BSUB) and len(expr.children()) == 2:
        left, right = expr.children()
        return f"{_pretty_z3(left)} - {_pretty_z3(right)}"
    # 기타 연산은 기본 str
    return str(expr)

class InspectInfo:
    def __init__(self, ins:Effect) -> None:
        self.ins = ins
        self._hash = self._compute_hash()

    # def __str__(self) -> str:
    #     if isinstance(self.ins, tuple):
    #         if len(self.ins) == 3:
    #             return f"{self.ins[0]}: {str(simplify(self.ins[1]))} = {str(simplify(self.ins[2]))}"
    #         if len(self.ins) == 2:
    #             return f"{str(simplify(self.ins[0]))}: {str(simplify(self.ins[1]))}"
    #     else:
    #         return str(self.ins)

    # def __str__(self) -> str:
    #     if isinstance(self.ins, Effect.Call):
    #         simplified_args = [simplify.simplify(arg) for arg in self.ins.args]
    #         return f"Call: {self.ins.name}({', '.join(map(str, simplified_args))})"
    #     elif isinstance(self.ins, Effect.Condition):
    #         return f"Condition: {simplify.simplify(self.ins.expr)}"
    #     elif isinstance(self.ins, Effect.Return):
    #         return f"Return: {simplify.simplify(self.ins.expr)}"
    #     elif isinstance(self.ins, Effect.Put):
    #         return f"Put: {self.ins.reg} = {simplify.simplify(self.ins.expr)}"
    #     elif isinstance(self.ins, Effect.Store):
    #         return f"Store: {simplify.simplify(self.ins.addr)} = {simplify.simplify(self.ins.expr)}"
    #     else:
    #         return str(self.ins)

    def __str__(self) -> str:
        # simplify.simplify로 z3 expr를 얻고, _pretty_z3로 예쁘게 출력
        if isinstance(self.ins, Effect.Call):
            simplified_args = [simplify.simplify(arg) for arg in self.ins.args]
            pretty_args = [_pretty_z3(arg) for arg in simplified_args]
            return f"Call: {self.ins.name}({', '.join(pretty_args)})"
        elif isinstance(self.ins, Effect.Condition):
            expr = simplify.simplify(self.ins.expr)
            return f"Condition: {_pretty_z3(expr)}"
        elif isinstance(self.ins, Effect.Return):
            expr = simplify.simplify(self.ins.expr)
            return f"Return: {_pretty_z3(expr)}"
        elif isinstance(self.ins, Effect.Put):
            expr = simplify.simplify(self.ins.expr)
            return f"Put: {self.ins.reg} = {_pretty_z3(expr)}"
        elif isinstance(self.ins, Effect.Store):
            addr = simplify.simplify(self.ins.addr)
            expr = simplify.simplify(self.ins.expr)
            return f"Store: {_pretty_z3(addr)} = {_pretty_z3(expr)}"
        else:
            return str(self.ins)

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return self._hash
    
    def _compute_hash(self):
        if isinstance(self.ins, Effect.Call):
            return hash((self.ins.name, tuple(map(lambda x: str(simplify.simplify(x)), self.ins.args))))
        elif isinstance(self.ins, Effect.Condition):
            return hash(("Condition", str(simplify.simplify(self.ins.expr))))
        elif isinstance(self.ins, Effect.Return):
            return hash(("Return", str(simplify.simplify(self.ins.expr))))
        elif isinstance(self.ins, Effect.Put):
            return hash(("Put", self.ins.reg, str(simplify.simplify(self.ins.expr))))
        elif isinstance(self.ins, Effect.Store):
            return hash(("Store", str(simplify.simplify(self.ins.addr)), str(simplify.simplify(self.ins.expr))))
        else:
            return hash(str(simplify.simplify(self.ins)))

    # def __eq__(self, __o: object) -> bool:
    #     if isinstance(__o, InspectInfo):
    #         if isinstance(self.ins, tuple) and isinstance(__o.ins, tuple):
    #             if len(self.ins) != len(__o.ins):
    #                 return False
    #             for i in range(len(self.ins)):
    #                 if not equal(self.ins[i], __o.ins[i]):
    #                     return False
    #             return True
    #         else:
    #             print(self)
    #             assert False, "Not implemented"
    #     return False

    # def __eq__(self, __o: object) -> bool:
        
    #     if not isinstance(__o, InspectInfo):
    #         return False
    #     # if isinstance(self.ins, )
    #     if isinstance(self.ins, Effect.Call) and isinstance(__o.ins, Effect.Call):
    #         # return self.ins == __o.ins
    #         return self.ins.name == __o.ins.name and all(simplify.equal(a, b) for a, b in zip(self.ins.args, __o.ins.args))
    #     elif isinstance(self.ins, Effect.Condition) and isinstance(__o.ins, Effect.Condition):
    #         # return self.ins == __o.ins
    #         # print(f"Comparing {self}:{type(self.ins.expr)} with {__o} in InspectInfo.__eq__")
    #         return simplify.equal(self.ins.expr, __o.ins.expr)
    #     elif isinstance(self.ins, Effect.Return) and isinstance(__o.ins, Effect.Return):
    #         return simplify.equal(self.ins.expr, __o.ins.expr)
    #         # return self.ins == __o.ins
    #     elif isinstance(self.ins, Effect.Put) and isinstance(__o.ins, Effect.Put):
    #         return self.ins.reg == __o.ins.reg and simplify.equal(self.ins.expr, __o.ins.expr)
    #         # return self.ins == __o.ins
    #     elif isinstance(self.ins, Effect.Store) and isinstance(__o.ins, Effect.Store):
    #         return simplify.equal(self.ins.addr, __o.ins.addr) and simplify.equal(self.ins.expr, __o.ins.expr)
    #         # return self.ins == __o.ins
    #     else:
    #         return False
    def __eq__(self, other):
        if not isinstance(other, InspectInfo):
            return False
        # 오직 PER만 사용!
        return simplify.equal(self.ins, other.ins)

    def _z3_equal(self, a, b):
        # strict semantic equivalence
        if type(a) != type(b):
            return False
        if isinstance(a, Effect.Put):
            return a.reg == b.reg and simplify.equal(a.expr, b.expr)
        if isinstance(a, Effect.Call):
            return a.name == b.name and all(simplify.equal(x, y) for x, y in zip(a.args, b.args))
        if isinstance(a, Effect.Condition) or isinstance(a, Effect.Return):
            return simplify.equal(a.expr, b.expr)
        if isinstance(a, Effect.Store):
            return simplify.equal(a.addr, b.addr) and simplify.equal(a.expr, b.expr)
        return False
    


    def show_eq(self, other):
        if not isinstance(other, InspectInfo):
            return False
        print(f"self: {self}")
        print(f"other: {other}")
        print(f"self.ins: {self.ins}")
        print(f"other.ins: {other.ins}")
        if isinstance(self.ins, Effect.Call) and isinstance(other.ins, Effect.Call):
            print(f"self name: {self.ins.name}, other name: {other.ins.name}")
            print(f"args equal: {[simplify.show_equal(a, b) for a, b in zip(self.ins.args, other.ins.args)]}")
        elif isinstance(self.ins, Effect.Condition) and isinstance(other.ins, Effect.Condition):
            
            print(f"Condition show equal: {simplify.show_equal(self.ins.expr, other.ins.expr)}")
        elif isinstance(self.ins, Effect.Return) and isinstance(other.ins, Effect.Return):
            print(f"Return show equal: {simplify.show_equal(self.ins.expr, other.ins.expr)}")
        elif isinstance(self.ins, Effect.Put) and isinstance(other.ins, Effect.Put):
            print(f"Put show equal: {simplify.show_equal(self.ins.expr, other.ins.expr)}")
        elif isinstance(self.ins, Effect.Store) and isinstance(other.ins, Effect.Store):
            print(f"Store addr show equal: {simplify.show_equal(self.ins.addr, other.ins.addr)}")
            print(f"Store expr show equal: {simplify.show_equal(self.ins.expr, other.ins.expr)}")
        else:
            print(f"Different types or unsupported Effect: {type(self.ins)}, {type(other.ins)}")
        return self == other

    def refine(self, reference_list: list["InspectInfo"]):
        """
        Refine this InspectInfo by comparing with a reference list.
        If semantically equal info exists in reference_list, return None.
        Else, return self.
        """
        for ref in reference_list:
            if self == ref:
                return None
        return self
    
    # def __str__(self):
    #     return str(self.ins)