import re
from pycparser import c_parser, c_ast

# 전처리 지시문 제거 (매크로, include 등)
def strip_directives(code: str) -> tuple[str, int]:
    lines = code.splitlines()
    clean_lines = []
    removed_count = 0
    for line in lines:
        if line.strip().startswith("#"):
            removed_count += 1
        else:
            clean_lines.append(line)
    return "\n".join(clean_lines), removed_count

# AST 노드 간단 버전
class CondNode:
    def __init__(self, node_type, coord, children=None, line_offset=0):
        self.node_type = node_type
        self.coord = coord
        self.children = children if children else []
        self.line_offset = line_offset

    def __repr__(self, level=0):
        if self.coord is not None and hasattr(self.coord, "line"):
            line = self.coord.line + self.line_offset
        else:
            line = "?"
        ret = "    " * level + f"{self.node_type} (Line: {line})\n"
        for child in self.children:
            # 자식에게도 offset 전달
            child.line_offset = self.line_offset
            ret += child.__repr__(level + 1)
        return ret

# C 스타일 주석 제거 함수
def strip_comments(code: str) -> str:
    # /* ... */ 주석 제거 (줄바꿈은 남김)
    def replacer(match):
        s = match.group()
        return ''.join('\n' if c == '\n' else ' ' for c in s)
    code = re.sub(r'/\*.*?\*/', replacer, code, flags=re.DOTALL)
    # // ... 주석 제거 (줄바꿈은 남김)
    code = re.sub(r'//.*', '', code)
    return code

# CondNode AST 생성
def extract_control_ast(node, line_offset=0) -> CondNode | list[CondNode] | None:
    if isinstance(node, c_ast.If):
        children = []
        # iftrue
        if node.iftrue:
            c = extract_control_ast(node.iftrue, line_offset)
            if c:
                if isinstance(c, list):
                    children.extend(c)
                else:
                    children.append(c)
        # else 블록(iffalse)
        if node.iffalse:
            if isinstance(node.iffalse, c_ast.If):
                # else if: 현재 If와 else if를 형제 노드로 반환
                this_if = CondNode("If", node.coord, children, line_offset)
                else_if = extract_control_ast(node.iffalse, line_offset)
                if isinstance(else_if, list):
                    return [this_if] + else_if
                elif else_if:
                    return [this_if, else_if]
                else:
                    return [this_if]
            else:
                else_child = extract_control_ast(node.iffalse, line_offset)
                if else_child:
                    children.append(CondNode("Else", node.iffalse.coord, [else_child], line_offset))
        return CondNode("If", node.coord, children, line_offset)
    elif isinstance(node, (c_ast.For, c_ast.While, c_ast.DoWhile, c_ast.Switch, c_ast.Case, c_ast.Default)):
        children = []
        for _, child in node.children():
            c = extract_control_ast(child, line_offset)
            if c:
                if isinstance(c, list):
                    children.extend(c)
                else:
                    children.append(c)
        return CondNode(type(node).__name__, node.coord, children, line_offset)
    # 자식 노드 재귀 탐색
    children = []
    for _, child in node.children():
        c = extract_control_ast(child, line_offset)
        if c:
            if isinstance(c, list):
                children.extend(c)
            else:
                children.append(c)
    if children:
        return CondNode("Block", node.coord, children, line_offset)
    return None

# main/test 함수에서 CondNode 리스트가 반환될 수니, 루트가 리스트면 Block으로 감싸기
def wrap_cond_ast(ast, line_offset=0):
    cond_ast = extract_control_ast(ast, line_offset)
    if isinstance(cond_ast, list):
        return CondNode("Block", None, cond_ast, line_offset)
    return cond_ast

def find_parent_condition_line(node: CondNode, target_line: int, parent_line: int = None) -> int | None:
    """
    node: CondNode 트리의 루트
    target_line: 찾고자 하는 실제 코드 라인 번호
    parent_line: 현재까지 찾은 가장 가까운 조건문의 라인 번호
    """
    if node.node_type in ("If", "For", "While", "DoWhile", "Switch", "Case", "Default", "Else") and node.coord and hasattr(node.coord, "line"):
        node_line = node.coord.line + node.line_offset
        # 조건문이 시작되는 줄은 parent로 삼지 않는다
        if node_line < target_line:
            parent_line = node_line

    for child in node.children:
        result = find_parent_condition_line(child, target_line, parent_line)
        # 자식이 target_line과 같은 조건문 줄을 parent로 반환하면 무시
        if result is not None and result != target_line:
            parent_line = result

    # 자기 자신이 조건문 시작 줄이면 parent가 아님
    if node.coord and hasattr(node.coord, "line") and node.coord.line + node.line_offset == target_line:
        return None

    return parent_line

def main():
    with open("test.c", "r") as f:
        raw_code = f.read()

    code, removed_count = strip_directives(raw_code)
    code = strip_comments(code)  # 주석 제거 추가
    parser = c_parser.CParser()
    ast = parser.parse(code)

    cond_ast = wrap_cond_ast(ast, removed_count)
    print(cond_ast)

def test_find_parent_condition_line():
    with open("test.c", "r") as f:
        raw_code = f.read()

    code, removed_count = strip_directives(raw_code)
    code = strip_comments(code)
    parser = c_parser.CParser()
    ast = parser.parse(code)
    cond_ast = extract_control_ast(ast, removed_count)

    test_cases = [
        (4, None),
        (6, None),
        (7, 6),
        (8, 6),
        (9, 8),
        (10, 6),
        (11, 10),
        (12, ),
        (13, 12),
        (15, None),
        (16, 15),
        (17, None),
        (18, 17),
        (21, None),
        (22, 21),
        (23, 22),
        (27, None),
        (28, 27),
        (29, 27),
        (30, 29),
        (34, None),
        (35, 37),
        (36, 37),
        (37, None),
        (39, None),
        # switch는 알아서
        (50, None),
        (51, 50),
        (52, 52),
        (53, None),
        (54, 53),
        (55, None),
    ]

    for line, expected in test_cases:
        result = find_parent_condition_line(cond_ast, line)
        print(f"Line {line}: expected {expected}, got {result}")
        assert result == expected, f"Test failed for line {line}: expected {expected}, got {result}"

if __name__ == "__main__":
    main()
    test_find_parent_condition_line()
