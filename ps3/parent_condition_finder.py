import clang.cindex
from settings import SRC_PATH, CVE_FILE
import jsonlines
import os
import subprocess

clang.cindex.Config.set_library_file('/usr/lib/llvm-14/lib/libclang.so.1')  # 시스템에 맞게 수정

def print_ast(node, indent=0):
    # AST 구조와 라인 번호를 보기 위한 함수
    print('  ' * indent + f"{node.kind.name} | {node.spelling} | Line {node.location.line} ~ {node.extent.start.line}-{node.extent.end.line}")
    for child in node.get_children():
        print_ast(child, indent + 1)

def commit_checkout(commit, project, filename):
    # 1. 해당 프로젝트 디렉토리로 이동
    project_path = os.path.join(SRC_PATH, project)
    if not os.path.exists(project_path):
        print(f"[ERROR] Project path {project_path} does not exist.")
        exit(1)
    os.chdir(project_path)
    # 2. git checkout 명령어 실행
    try:
        subprocess.run(['git', 'checkout', commit], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to checkout commit {commit} in project {project}: {e}")
        exit(1)
    # 3. 파일이 존재하는지 확인
    file_path = os.path.join(project_path, filename)
    if not os.path.exists(file_path):
        print(f"[ERROR] File {file_path} does not exist after checkout.")
        exit(1)
    

def find_parent_control_block(cve, target_line, patch: bool):


    clang.cindex.Config.set_library_file('/usr/lib/llvm-14/lib/libclang.so.1')  # 시스템에 맞게 수정

    index = clang.cindex.Index.create()
    # if patch:
    #     filename = f"{SRC_PATH}/{filename}_patch.c"
    # else:
    #     filename = f"{SRC_PATH}/{filename}_vuln.c"
    
    with jsonlines.open(f"{CVE_FILE}", 'r') as f:
        for line in f:
            if line['CVE'] == cve:
                project = line['project']
                source_file = line['source']
                filename = f"{SRC_PATH}/{project}/{source_file}"
                if patch:
                    commit = line['commit']
                else:
                    commit = line['pre_commit']
                break
        else:
            print(f"[ERROR] CVE {cve} not found in {CVE_FILE}")
            exit(1)
    
    # print(f"[DEBUG] Checking out commit {commit} for project {project} and file {filename}, line# {target_line}, ")
    commit_checkout(commit, project, filename)


    tu = index.parse(filename)
    CONTROL_KINDS = {
        clang.cindex.CursorKind.IF_STMT: "if",
        clang.cindex.CursorKind.FOR_STMT: "for",
        clang.cindex.CursorKind.WHILE_STMT: "while",
        clang.cindex.CursorKind.DO_STMT: "do-while",
        clang.cindex.CursorKind.SWITCH_STMT: "switch",
        clang.cindex.CursorKind.CXX_FOR_RANGE_STMT: "range-for",
    }
    # print(f"Parsing {filename} for target line {target_line}")

    # # AST 전체 출력 (디버깅용)
    # print("=== AST Dump ===")
    # print_ast(tu.cursor)
    # print("================")

    def traverse(node, stack):
        start_line = node.extent.start.line
        end_line = node.extent.end.line

        # 조건 줄에 해당하는 제어문이라면, parent만 반환
        if start_line == target_line and node.kind in CONTROL_KINDS:
            if stack:
                parent_node, _ = stack[-1]
                # print(f"[DEBUG] target_line {target_line} is CONTROL_KINDS, parent at {parent_node.extent.start.line}")
                return parent_node.extent.start.line
            else:
                # print(f"[DEBUG] target_line {target_line} is CONTROL_KINDS, but no parent")
                return None

        # 제어문이면 스택에 push
        if node.kind in CONTROL_KINDS:
            stack.append((node, CONTROL_KINDS[node.kind]))

            # 조건식 내부에 target_line이 있는 경우: 자기 자신은 parent가 아님
            children = list(node.get_children())
            if children:
                cond_node = children[0]
                cond_start = cond_node.extent.start.line
                cond_end = cond_node.extent.end.line
                if cond_start <= target_line <= cond_end:
                    # print(f"[DEBUG] target_line {target_line} is inside condition of {node.kind.name} at {start_line}")
                    return None

            # IF_STMT의 else 처리
            if node.kind == clang.cindex.CursorKind.IF_STMT and len(children) >= 3:
                else_block = children[2]
                if else_block.kind == clang.cindex.CursorKind.IF_STMT:
                    result = traverse(else_block, stack.copy())
                    if result is not None:
                        return result
                else:
                    else_start = else_block.extent.start.line
                    else_end = else_block.extent.end.line
                    if else_start <= target_line <= else_end:
                        # print(f"[DEBUG] target_line {target_line} is inside ELSE block at {else_start}")
                        return else_start

        if start_line <= target_line <= end_line:
            for child in node.get_children():
                result = traverse(child, stack.copy())
                if result is not None:
                    return result

            # 제어문이 아닌데 포함된다면, 가장 가까운 제어문 반환
            if stack:
                parent_node, _ = stack[-1]
                # print(f"[DEBUG] target_line {target_line} is inside {parent_node.kind.name} at {parent_node.extent.start.line}")
                return parent_node.extent.start.line
        return None
    ret = traverse(tu.cursor, [])
    print(f"Parent control block for line {target_line} is at line {ret}")
    return ret

# 디버깅 예시 실행
# print(find_parent_control_block("FFmpeg/fftools/ffmpeg_opt.c", 3264, patch=True))