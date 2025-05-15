from simplify import equal


class Effect:
    class Call:
        def __init__(self, name, args):
            self.name = name
            self.args = args

        def __eq__(self, other):
            return isinstance(other, Effect.Call) and self.name == other.name and self.args == other.args

        def __hash__(self):
            return hash((self.name, tuple(self.args)))

        def __str__(self):
            return f"Call({self.name}, {self.args})"
        
    class Condition:
        def __init__(self, expr):
            self.expr = expr

        def __eq__(self, other):
            return isinstance(other, Effect.Condition) and self.expr == other.expr

        def __hash__(self):
            return hash(("Condition", self.expr))

        def __str__(self):
            return f"Condition({self.expr})"

    class Return:
        def __init__(self, expr):
            self.expr = expr

        def __eq__(self, other):
            return isinstance(other, Effect.Return) and self.expr == other.expr

        def __hash__(self):
            return hash(("Return", self.expr))

        def __str__(self):
            return f"Return({self.expr})"
        
    class Put:
        def __init__(self, reg, expr):
            self.reg = reg
            self.expr = expr

        def __eq__(self, other):
            return isinstance(other, Effect.Put) and self.reg == other.reg and self.expr == other.expr

        def __hash__(self):
            return hash(("Put", self.reg, self.expr))

        def __str__(self):
            return f"Put({self.reg}, {self.expr})"
        
    class Store:
        def __init__(self, addr, expr):
            self.addr = addr
            self.expr = expr

        def __eq__(self, other):
            return isinstance(other, Effect.Store) and self.addr == other.addr and self.expr == other.expr

        def __hash__(self):
            return hash(("Store", self.addr, self.expr))

        def __str__(self):
            return f"Store({self.addr}, {self.expr})"
        
    class Any:
        def __init__(self):
            pass

        def __eq__(self, other):
            return True

        def __hash__(self):
            return hash("Any")

        def __str__(self):
            return "T"