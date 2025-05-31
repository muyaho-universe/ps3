from effect import Effect
import simplify
from inspect_info import InspectInfo

def is_generalization_of(self, other: "InspectInfo") -> bool:
        # self ⊒ other
        if not isinstance(other, InspectInfo):
            return False
        a, b = self.ins, other.ins
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