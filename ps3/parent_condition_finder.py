import clang.cindex
from settings import SRC_PATH
clang.cindex.Config.set_library_file('/usr/lib/llvm-14/lib/libclang.so.1')  # 시스템에 맞게 수정

def find_parent_control_block(filename, target_line, patch:bool):
    index = clang.cindex.Index.create()
    if patch:
        filename = f"{SRC_PATH}/{filename}_patch.c"
    else:
        filename = f"{SRC_PATH}/{filename}_vuln.c"
    tu = index.parse(filename)

    # 추적할 제어문 종류
    CONTROL_KINDS = {
        clang.cindex.CursorKind.IF_STMT: "if",
        clang.cindex.CursorKind.FOR_STMT: "for",
        clang.cindex.CursorKind.WHILE_STMT: "while",
        clang.cindex.CursorKind.DO_STMT: "do-while",
        clang.cindex.CursorKind.SWITCH_STMT: "switch",
        clang.cindex.CursorKind.CXX_FOR_RANGE_STMT: "range-for",
    }

    def traverse(node, stack):
        # 제어문이면 스택에 추가
        if node.kind in CONTROL_KINDS:
            stack.append((node, CONTROL_KINDS[node.kind]))

            # IF_STMT의 else 블록(및 else if) 특별 처리
            if node.kind == clang.cindex.CursorKind.IF_STMT:
                children = list(node.get_children())
                if len(children) >= 3:
                    else_block = children[2]
                    if else_block.kind == clang.cindex.CursorKind.IF_STMT:
                        # else if면 재귀적으로 더 탐색
                        result = traverse(else_block, stack.copy())
                        if result:
                            return result
                    else:
                        # 진짜 else 블록 범위에 target_line이 포함되는지 확인
                        else_start = else_block.extent.start.line
                        else_end = else_block.extent.end.line
                        if else_start <= target_line <= else_end:
                            print(f"Found else block at line {else_start}")
                            return else_start

        start_line = node.extent.start.line
        end_line = node.extent.end.line

        if start_line <= target_line <= end_line:
            for child in node.get_children():
                result = traverse(child, stack.copy())
                if result:
                    print(f"Found in {node.kind} at line {start_line}")
                    return result
            # 가장 가까운 제어문 반환
            if node.kind not in CONTROL_KINDS and stack:
                parent_node, parent_type = stack[-1]
                print(f"Returning parent {parent_type} at line {parent_node.extent.start.line}")
                return parent_node.extent.start.line
        return None

    return traverse(tu.cursor, [])


# def test_find_parent_control_block():
#     # if문 내부
#     assert find_parent_control_block("t.c", 7) == "if block starts at line 6"
#     # 중첩 if문 내부
#     assert find_parent_control_block("t.c", 9) == "if block starts at line 8"
#     # else if문 내부
#     assert find_parent_control_block("t.c", 11) == "if block starts at line 10"
#     # else문 내부
#     assert find_parent_control_block("t.c", 13) == "else block starts at line 12"
#     # else if (a == 0) 블록
#     assert find_parent_control_block("t.c", 16) == "if block starts at line 15"
#     # else (a < 0) 블록
#     assert find_parent_control_block("t.c", 18) == "else block starts at line 17"
#     # for문 내부
#     assert find_parent_control_block("t.c", 23) == "if block starts at line 22"
#     # while문 내부
#     assert find_parent_control_block("t.c", 30) == "if block starts at line 29"
#     # do-while문 내부
#     assert find_parent_control_block("t.c", 35) == "do-while block starts at line 34"
#     # switch문 내부
#     assert find_parent_control_block("t.c", 41) == "switch block starts at line 39"
#     assert find_parent_control_block("t.c", 44) == "switch block starts at line 39"
#     assert find_parent_control_block("t.c", 47) == "switch block starts at line 39"
#     # 아무 제어문에도 속하지 않는 경우
#     assert find_parent_control_block("t.c", 4) is None
#     assert find_parent_control_block("t.c", 50) is None

# test_find_parent_control_block()