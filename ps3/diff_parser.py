import logging
from unidiff import PatchSet, PatchedFile, Hunk # type: ignore
from pygments.lexers import get_lexer_by_name
from pygments.token import Token
from debug_parser import DebugParser2
from dataclasses import dataclass
from log import *
from settings import *
from new_line import NewLine
from parent_condition_finder import find_parent_control_block
logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    pattern: str
    name: str = None
    number: int = 0
    wildcard: list[bool] = None


@dataclass
class Patterns:
    patterns: list[Pattern]


@dataclass
class HunkDiff:
    add: list[int]
    remove: list[int]
    type: str  # add, remove, modify
    hunk: Hunk
    add_pattern: Patterns = None
    remove_pattern: Patterns = None


@dataclass
class DiffResult:
    funcname: str
    hunks: list[HunkDiff]


class DiffParser:
    def __init__(self, diff) -> None:
        self.lexer = get_lexer_by_name('c')
        self.parse_result = self._parse_diff(diff)

    @classmethod
    def from_file(cls, file_path: str):
        with open(file_path, 'r') as f:
            diff = f.read()
        return cls(diff)

    # def _get_function_name(self, section_header: str) -> str:
    #     tokens = list(self.lexer.get_tokens(section_header))
    #     # dirty hack to get function name, maybe parse tree is better
    #     deep = 0
    #     for i, token in reversed(list(enumerate(tokens))):
    #         if token[0] == Token.Punctuation and token[1] == ')':
    #             deep += 1
    #         if token[0] == Token.Punctuation and token[1] == '(':
    #             deep -= 1
    #         if token[0] == Token.Name and tokens[i+1][0] == Token.Punctuation and tokens[i+1][1] == '(':
    #             if deep > 0:
    #                 continue
    #             return token[1]
    #     return None

    # Improve the _get_function_name function
    # now whitespace is not considered
    def _get_function_name(self, section_header: str) -> str:
        tokens = list(self.lexer.get_tokens(section_header))
        deep = 0
        for i in reversed(range(len(tokens))):
            token = tokens[i]
            if token[0] == Token.Punctuation and token[1] == ')':
                deep += 1
            elif token[0] == Token.Punctuation and token[1] == '(':
                deep -= 1
            elif token[0] == Token.Name:
                j = i + 1
                while j < len(tokens) and tokens[j][0] == Token.Text.Whitespace:
                    j += 1
                if j < len(tokens) and tokens[j][0] == Token.Punctuation and tokens[j][1] == '(':
                    if deep > 0:
                        continue
                    return token[1]
        return None


    def _parse_patchfile(self, patch_file: PatchedFile) -> dict:
        dic = {}
        dic['path'] = patch_file.path
        dic['functions'] = {}
        for hook in patch_file:
            function_name = self._get_function_name(hook.section_header)
            if function_name is not None:
                if function_name not in dic['functions']:
                    dic['functions'][function_name] = []
                dic['functions'][function_name].append(hook)
        if len(dic['functions'].keys()) == 0:
            return None
        return dic

    def __str__(self) -> str:
        return str(self.parse_result)

    def _parse_diff(self, diff):
        l = []
        patch = PatchSet.from_string(diff)
        # filter not c/c++ run file, support C now, but actually support all binary file compiled
        patch = [file for file in patch if file.path.endswith(
            ('.c', '.cpp', '.cc', '.hpp'))]
        for file in patch:
            parse_res = self._parse_patchfile(file)
            if parse_res is not None:
                l.append(parse_res)
        return l

    # Big Pattern such as whole if statement
    def _decidePattern(self, line_contents: list[str]) -> Pattern:
        line_content = ''.join(line_contents).strip()
        tokens = list(self.lexer.get_tokens(line_content))
        tokens = [token[1]
                  for token in tokens if token[0] != Token.Text.Whitespace]
        if len(tokens) <= 2:
            return None
        # if statement
        if tokens[0] == 'if' and tokens[-1] == '}':
            # sure its a single if statement
            if tokens.count('{') == 1 and tokens.count('}') == 1:
                return Pattern("If")
            # or multi-line if statement
            countl = tokens.count('{')
            countr = tokens.count('}')
            countif = tokens.count('if')
            countelse = tokens.count('else')
            if countl == countr and (countif + countelse) == countl:
                return Pattern("If")
        # TODO: other pattern
        return None

    # Small Pattern such as function call
    def _decidepattern(self, line_content: str) -> list:
        l = []
        if "(" in line_content and ")" in line_content:
            tokens = list(self.lexer.get_tokens(line_content))
            for i, token in enumerate(tokens):
                if token[0] == Token.Name and tokens[i+1][0] == Token.Punctuation and tokens[i+1][1] == '(':
                    name = token[1]
                    arg_number = 1
                    wildcard = []
                    for j in range(i+2, len(tokens)):
                        if tokens[j][0] == Token.Punctuation and tokens[j][1] == ')':
                            if tokens[j-1][0] == Token.Punctuation and tokens[j-1][1] == '(':
                                arg_number -= 1
                            if tokens[j-1][0] == Token.Literal.String:
                                wildcard.append(True)
                            else:
                                wildcard.append(False)
                            break
                        if tokens[j][0] == Token.Punctuation and tokens[j][1] == ',':
                            # check if parameter is string
                            if tokens[j-1][0] == Token.Literal.String:
                                wildcard.append(True)
                            else:
                                wildcard.append(False)
                            arg_number += 1
                    # assert len(wildcard) == arg_number
                    pattern = Pattern("Call", name, arg_number, wildcard)
                    l.append(pattern)
        if len(l) == 0:
            return None
        return l
        return "other"  # TODO: other pattern

    # def get_binarylevel_change(self, debug_parser: DebugParser2, cve) -> list[DiffResult]:
    #     vuln_parser, patch_parser = debug_parser.vuln_parser, debug_parser.patch_parser
    #     result = []

    #     for file in self.parse_result:
    #         for funcname in file['functions']:
    #             hunks = []
    #             for hunk in file['functions'][funcname]:
    #                 # add = []
    #                 add = {}
    #                 add_pattern = []
    #                 # remove = []
    #                 remove = {}
    #                 remove_pattern = []
    #                 hunk: Hunk = hunk
    #                 temp_add = []
    #                 temp_remove = []
    #                 normalized_removes = []
    #                 normalized_adds = []
    #                 # source_lines = list(hunk.source_lines())
    #                 # target_lines = list(hunk.target_lines())
    #                 source_lines = [NewLine(
    #                     line.value,
    #                     line_type=line.line_type,
    #                     source_line_no=line.source_line_no,
    #                     target_line_no=line.target_line_no,
    #                     # TODO: CFG 사용해서 찾기
    #                     parent_line_no=find_parent_control_block(cve, line.source_line_no, False)
    #                     if line.is_removed else None
    #                 ) for line in hunk.source_lines()]
                    
    #                 target_lines = [NewLine(
    #                     line.value,
    #                     line_type=line.line_type,
    #                     source_line_no=line.source_line_no,
    #                     target_line_no=line.target_line_no,
    #                     # TODO: CFG 사용해서 찾기
    #                     parent_line_no=find_parent_control_block(cve, line.target_line_no, True)
    #                     if line.is_added else None
    #                 ) for line in hunk.target_lines()]
    #                 # print(f"source_lines: {source_lines}")

    #                 # 미리 normalize 해서 비교용 셋 만들기
    #                 norm_src_map = {normalize_code_line(line.value): line.source_line_no
    #                                 for line in source_lines if line.is_removed}
    #                 norm_tgt_map = {normalize_code_line(line.value): line.target_line_no
    #                                 for line in target_lines if line.is_added}
    #                 common_keys = set(norm_src_map.keys()) & set(norm_tgt_map.keys())
    #                 for line in source_lines:
    #                     if line.is_removed:
    #                         norm = normalize_code_line(line.value)
    #                         if norm in common_keys:
    #                             continue
    #                         temp_remove.append(line.value)
    #                         normalized_removes.append(norm)
    #                         binary_lines = vuln_parser.line2addr(funcname, line.source_line_no)
    #                         if len(binary_lines) == 0:
    #                             continue
    #                         parent_lines = vuln_parser.line2addr(funcname, line.parent_line_no)
                            
    #                         if len(parent_lines) == 0:
    #                             key = None
    #                         else:
    #                             key = tuple(parent_lines)
    #                         pattern = self._decidepattern(line.value)
    #                         if pattern is not None:
    #                             remove_pattern.extend(pattern)
    #                         # remove.append((parent_lines, binary_lines))
    #                         remove[key] = binary_lines
    #                         # print(f"remove: {remove}")
    #                         # remove.extend(binary_lines)
    #                 for line in target_lines:
    #                     if line.is_added:
    #                         norm = normalize_code_line(line.value)
    #                         if norm in common_keys:
    #                             continue
    #                         temp_add.append(line.value)
    #                         normalized_adds.append(norm)
    #                         binary_lines = patch_parser.line2addr(funcname, line.target_line_no)
    #                         if len(binary_lines) == 0:
    #                             continue
    #                         parent_lines = patch_parser.line2addr(funcname, line.parent_line_no)
    #                         if len(parent_lines) == 0:
    #                             key = "None"
    #                         else:
    #                             key = tuple(parent_lines)
    #                         pattern = self._decidepattern(line.value)
    #                         if pattern is not None:
    #                             add_pattern.extend(pattern)
    #                         # add.append((parent_lines, binary_lines))
    #                         # add.extend(binary_lines)
    #                         add[key] = binary_lines
    #                         # print(f"add: {add}")

    #                 if len(add) == 0 and len(remove) == 0:
    #                     # print(f"[INFO] Skipping hunk in {funcname}: no meaningful binary diff remains")
    #                     continue

    #                 # consider big pattern e.g. whole IF statement
    #                 bigpatternadd = self._decidePattern(temp_add)
    #                 bigpatternremove = self._decidePattern(temp_remove)
    #                 if bigpatternadd is not None:
    #                     add_pattern.append(bigpatternadd)
    #                 if bigpatternremove is not None:
    #                     remove_pattern.append(bigpatternremove)

    #                 if len(add) == 0:
    #                     hunks.append(HunkDiff(add, remove, 'remove', hunk, None, Patterns(remove_pattern)))
    #                 elif len(remove) == 0:
    #                     hunks.append(HunkDiff(add, remove, 'add', hunk, Patterns(add_pattern), None))
    #                 else:
    #                     hunks.append(HunkDiff(add, remove, 'modify', hunk, Patterns(add_pattern), Patterns(remove_pattern)))

    #             result.append(DiffResult(funcname, hunks))
    #     return result
    def get_binarylevel_change(self, debug_parser: DebugParser2) -> list[DiffResult]:
        vuln_parser, patch_parser = debug_parser.vuln_parser, debug_parser.patch_parser
        result = []

        for file in self.parse_result:
            for funcname in file['functions']:
                hunks = []
                for hunk in file['functions'][funcname]:
                    add = []
                    add_pattern = []
                    remove = []
                    remove_pattern = []
                    hunk: Hunk = hunk
                    temp_add = []
                    temp_remove = []
                    normalized_removes = []
                    normalized_adds = []

                    source_lines = list(hunk.source_lines())
                    target_lines = list(hunk.target_lines())

                    # 미리 normalize 해서 비교용 셋 만들기
                    norm_src_map = {normalize_code_line(line.value): line.source_line_no
                                    for line in source_lines if line.is_removed}
                    norm_tgt_map = {normalize_code_line(line.value): line.target_line_no
                                    for line in target_lines if line.is_added}
                    # 옛날 방식
                    # norm_src_map = {line.value: line.source_line_no
                    #                 for line in source_lines if line.is_removed}
                    # norm_tgt_map = {line.value: line.target_line_no
                    #                 for line in target_lines if line.is_added}
                    common_keys = set(norm_src_map.keys()) & set(norm_tgt_map.keys())

                    for line in source_lines:
                        if line.is_removed:
                            norm = normalize_code_line(line.value)
                            if norm in common_keys:
                                # print(f"[SKIP] source line matched in both: {repr(norm)}")
                                continue
                            temp_remove.append(line.value)
                            normalized_removes.append(norm)
                            binary_lines = vuln_parser.line2addr(funcname, line.source_line_no)
                            if len(binary_lines) == 0:
                                continue
                            pattern = self._decidepattern(line.value)
                            if pattern is not None:
                                remove_pattern.extend(pattern)
                            remove.extend(binary_lines)

                    for line in target_lines:
                        if line.is_added:
                            norm = normalize_code_line(line.value)
                            if norm in common_keys:
                                # print(f"[SKIP] target line matched in both: {repr(norm)}")
                                continue
                            temp_add.append(line.value)
                            normalized_adds.append(norm)
                            binary_lines = patch_parser.line2addr(funcname, line.target_line_no)
                            if len(binary_lines) == 0:
                                continue
                            pattern = self._decidepattern(line.value)
                            if pattern is not None:
                                add_pattern.extend(pattern)
                            add.extend(binary_lines)

                    if len(add) == 0 and len(remove) == 0:
                        # print(f"[INFO] Skipping hunk in {funcname}: no meaningful binary diff remains")
                        continue

                    # consider big pattern e.g. whole IF statement
                    bigpatternadd = self._decidePattern(temp_add)
                    bigpatternremove = self._decidePattern(temp_remove)
                    if bigpatternadd is not None:
                        add_pattern.append(bigpatternadd)
                    if bigpatternremove is not None:
                        remove_pattern.append(bigpatternremove)

                    if len(add) == 0:
                        hunks.append(HunkDiff(add, remove, 'remove', hunk, None, Patterns(remove_pattern)))
                    elif len(remove) == 0:
                        hunks.append(HunkDiff(add, remove, 'add', hunk, Patterns(add_pattern), None))
                    else:
                        hunks.append(HunkDiff(add, remove, 'modify', hunk, Patterns(add_pattern), Patterns(remove_pattern)))

                result.append(DiffResult(funcname, hunks))
        return result
    
def normalize_code_line(line: str) -> str:
    import re
    # 주석 제거
    line = line.split("//")[0]
    # 중괄호 제거
    line = line.replace("{", "").replace("}", "")
    # 모든 공백 문자 (탭, 스페이스 등) → 하나의 스페이스로
    line = re.sub(r'\s+', ' ', line)
    # 양쪽 공백 제거
    return line.strip()