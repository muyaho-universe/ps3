class Node:
    def __init__(self, label: str, children: list["Node"] = None, level: int = 0):
        self.label = label
        self.children = children if children is not None else []
        self.level = level 

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "children": [child.to_dict() for child in self.children]
        }

    def print(self, indent: int = 0):
        print("  " * indent + f"{self.label} (L{self.level})")
        for child in self.children:
            child.print(indent + 1)