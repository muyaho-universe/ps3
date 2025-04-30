from simplify import simplify, equal, show_equal

class InspectInfo:
    def __init__(self, ins) -> None:
        self.ins = ins

    def __str__(self) -> str:
        if isinstance(self.ins, tuple):
            if len(self.ins) == 3:
                return f"{self.ins[0]}: {str(simplify(self.ins[1]))} = {str(simplify(self.ins[2]))}"
            if len(self.ins) == 2:
                return f"{str(simplify(self.ins[0]))}: {str(simplify(self.ins[1]))}"
        else:
            return str(self.ins)

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return hash(self.ins[0])

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, InspectInfo):
            if isinstance(self.ins, tuple) and isinstance(__o.ins, tuple):
                if len(self.ins) != len(__o.ins):
                    return False
                for i in range(len(self.ins)):
                    if not equal(self.ins[i], __o.ins[i]):
                        return False
                return True
            else:
                print(self)
                assert False, "Not implemented"
        return False

    def show_eq(self, other):
        if isinstance(other, InspectInfo):
            if isinstance(self.ins, tuple) and isinstance(other.ins, tuple):
                print(f"self: {self}")
                print(f"other: {other}")
                print(f"self.ins: {self.ins}")
                print(f"other.ins: {other.ins}")
                print(f"len(self.ins): {len(self.ins)}")
                print(f"len(other.ins): {len(other.ins)}")
                if len(self.ins) != len(other.ins):
                    return False
                for i in range(len(self.ins)):
                    print(f"show_equal(self.ins[i], other.ins[i]): {show_equal(self.ins[i], other.ins[i])}")
                    if not show_equal(self.ins[i], other.ins[i]):
                        return False
                    print(f"self.ins[{i}]: {self.ins[i]}")
                    print(f"self.ins[{i}] type: {type(self.ins[i])}") 
                    print(f"other.ins[{i}]: {other.ins[i]}")
                    print(f"other.ins[{i}] type: {type(other.ins[i])}")
                print("\n")
                return True
            else:
                print(self)
                assert False, "Not implemented"
        return False

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
