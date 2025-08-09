# This file is responsible for parser debug info extracted by gdb or lldb.
import logging
import subprocess
import os
from settings import ADDR2LINE, LOG_PATH
from log import *
import re

VULN = 0
PATCH = 1
logger = get_logger(__name__)
logger.setLevel(INFO)
file_handler = logging.FileHandler(LOG_PATH)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)
ansi_escape = re.compile(r'\x1b\[[0-9;]*m')


class DebugParser:
    def __init__(self, debug_infos: list[list[str]], binary_path: str = None):
        self.parse_result = {}
        self.binary_path = binary_path
        self.debug_infos = debug_infos
        for debug_info in debug_infos:
            debug_info = [line.strip() for line in debug_info]
            # union all debug info
            self.parse_result.update(self._debug_parse(debug_info))

    def _debug_parse(self, debug_info: list[str]) -> dict:
        dic = {}
        addr = []
        i = 0
        funcname = None
        if os.uname().sysname == 'Linux':
            while i < len(debug_info):
                line = debug_info[i]
                if line.startswith('Dump of assembler code for function'):
                    funcname = line.split()[-1]
                    funcname = funcname[:funcname.find(':')]
                    i += 1
                    continue
                if line.startswith('warning: Source file is more recent than executable.'):
                    logger.info('Source file is more recent than executable.')
                    i += 1
                    continue
                if line.startswith('End of assembler dump.'):
                    i += 1
                    continue
                if line.startswith('Address range'):
                    # E.g. Address range: 0x0000000000400b20 - 0x0000000000400b30
                    i += 1
                    continue
                tokens = line.strip().split()
                if len(tokens) != 0:
                    try:
                        addr.append(int(tokens[0], 16))
                    except ValueError:
                        print(f'Unrecognized debug info line: {line}, tokens: {tokens}')
                        print(f"debug_info: {debug_info}")
                        exit(0)
                i += 1
            # print("addr:", addr)
            dic = self._addr_from_lines(addr)
            assert funcname is not None
            dic = {funcname: dic}
            return dic
        elif os.uname().sysname == 'Darwin':
            # print(debug_info)
            # input()
            for line in debug_info:
                if line.startswith('(lldb)'):
                    if line.startswith('(lldb) disassemble -n'):
                        funcname = line.split()[-1]
                # E.g. libcrypto.so_openssl-1.1.1_O0_x86_gcc[0x1270d3] <+1026>: callq  0xd80cd                   ; BN_clear_free
                else:
                    tokens = line.strip().split()
                    if len(tokens) != 0:
                        s = tokens[0]
                        s = s[s.find('[')+1:s.find(']')]
                        try:
                            addr.append(int(s, 16))
                        except ValueError:
                            continue
            assert funcname is not None
            
            dic = self._addr_from_lines(addr)
            dic = {funcname: dic}
            return dic
        else:
            raise NotImplementedError(
                f'Unsupported OS {os.uname().sysname} !!!')

    def _addr_from_lines(self, addr_list):
        assert self.binary_path is not None
        dic = {}
        addr_list = [hex(addr) for addr in addr_list]
        # print("self.binary_path:", self.binary_path)
        # Try to use addr2line to get source file and line number from address
        # if failed, use gdb to get source file and line number
        try:
            p = subprocess.Popen([ADDR2LINE, '-afip', '-e', self.binary_path],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            addr_str = '\n'.join(addr_list)
            output, errors = p.communicate(input=addr_str.encode('utf-8'))
            # print("output:", output)
            if errors:
                print('Error:', errors.decode('utf-8'))
            else:
                for line in output.decode('utf-8').splitlines():
                    l = line.strip()
                    
                    if l.startswith('0x'):
                        # E.g.
                        # 0xffffffc000a7aa9c: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:59
                        # 0xffffffc000a7ab18: wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:77 (discriminator 1)
                        # print("l:", l)
                        try:
                            tokens = l.split(':')
                            addr = int(tokens[0], 16)
                            func = tokens[1].split(' ')[1]
                            lno = int(tokens[2].split(' ')[0])
                            if lno in dic:
                                dic[lno].append(addr)
                            else:
                                dic[lno] = [addr]
                        except ValueError:
                            # logger.warn(f'Unrecognized ADDR2LINE output {l} !!!')
                            raise ValueError(f'Unrecognized ADDR2LINE output {l} !!!')
                            continue
                    elif 'inlined by' in l:
                        # E.g.
                        # (inlined by) wcdcal_hwdep_ioctl_shared at /home/hang/pm/src-angler-20160801/sound/soc/codecs/wcdcal-hwdep.c:66
                        tokens = l.split(':')
                        lno = int(tokens[1].split(' ')[0])
                        func = tokens[0].split(' ')[3]
                        if lno in dic:
                            dic[lno].append(addr)
                        else:
                            dic[lno] = [addr]
                    else:
                        # logger.warn(f'Unrecognized ADDR2LINE output {l} !!!')
                        raise ValueError(f'Unrecognized ADDR2LINE output {l} !!!')
        except ValueError as e:
            bin_name = os.path.basename(self.binary_path)
            # logger.info(f'Failed to execute ADDR2LINE to {bin_name}, using gdb instead')
            # print(f'Failed to execute {ADDR2LINE} with error: {e}')
            dic = {}
           # Fallback to gdb - batch process all addresses at once
            if not addr_list:
                return dic
            # Build gdb command with multiple -ex options
            gdb_commands = [f'gdb', '-batch', '-ex', f'file {self.binary_path}']
            for addr in addr_list:
                gdb_commands.extend(['-ex', f'info line *{addr}'])
            
            try:
                output = subprocess.check_output(gdb_commands).decode('utf-8')
                lines = output.strip().split('\n')
                
                current_addr_idx = 0
                for line in lines:
                    line = line.strip()
                    # print(f'Processing GDB output line: {line}')
                    if line.startswith('Line'):
                        # Parse: Line 103 of "crypto/lhash/lhash.c" starts at address 0x227cde <OPENSSL_LH_flush+158> and ends at 0x227cf0 <OPENSSL_LH_insert>.
                        try:
                            tokens = line.split()
                            lno = int(tokens[1])
                            addr = int(addr_list[current_addr_idx], 16)
                            
                            if lno in dic:
                                dic[lno].append(addr)
                            else:
                                dic[lno] = [addr]
                            current_addr_idx += 1
                        except (ValueError, IndexError):
                            logger.warn(f'Failed to parse GDB output: {line}')
                            current_addr_idx += 1
                    elif 'No line number information available' in line:
                        # Skip addresses with no line info
                        current_addr_idx += 1
                        continue
                    elif line.startswith('(gdb)') or not line:
                        # Skip gdb prompts and empty lines
                        continue
                    else:
                        # Other unrecognized output
                        logger.warn(f'Unrecognized GDB output: {line}')
            
            except subprocess.CalledProcessError as e:
                logger.error(f'Failed to execute gdb batch command with error: {e}')
        return dic

    @classmethod
    def from_binary(cls, binary_path: str, funcnames: list[str]):
        # print("in Debugparser's from_binary: ", binary_path)
        debug_infos = []
        for func_name in funcnames:
            if os.uname().sysname == 'Linux':
                cmd = f'gdb -batch -ex "file {binary_path}" -ex "disassemble {func_name}"'
            elif os.uname().sysname == 'Darwin':
                cmd = f'lldb -b -o "disassemble -n {func_name}" -o quit {binary_path}'
            else:
                raise NotImplementedError(
                    f'Unsupported OS {os.uname().sysname} !!!')
            try:
                # print("cmd:", cmd)
                info = subprocess.check_output(
                    cmd, shell=True).decode('utf-8').splitlines()
            except subprocess.CalledProcessError:
                logger.error(f'Failed to execute {cmd} !!!')
                continue
            debug_infos.append(info)
        return cls(debug_infos, binary_path)

    def exists(self, funcname: str, src_line_number: int) -> bool:
        return funcname in self.parse_result and src_line_number in self.parse_result[funcname]

    def line2addr(self, funcname: str, src_line_number: int) -> list[int]:
        # print(f"funcname: {funcname}, src_line_number: {src_line_number}")
        # print(f"is exists: {self.exists(funcname, src_line_number)}")
        # print(f"is function in parse_result: {funcname in self.parse_result}")
        # print(f"is src_line_number in parse_result[funcname]: {src_line_number in self.parse_result[funcname]}")
        # if not src_line_number in self.parse_result[funcname]:
        #     print(f"self.parse_result[{funcname}]: {self.parse_result[funcname]}")
        if self.exists(funcname, src_line_number):
            return self.parse_result[funcname][src_line_number]
        else:
            return []

    def __str__(self) -> str:
        return str(self.parse_result)


class DebugParser2:

    def __init__(self, vuln_parser: DebugParser, patch_parser: DebugParser):
        self.vuln_parser = vuln_parser
        self.patch_parser = patch_parser

    @classmethod
    def from_files(cls, vuln_diff: str, patch_diff: str):
        return cls(DebugParser.from_file(vuln_diff), DebugParser.from_file(patch_diff))

    @classmethod
    def from_binary(cls, vuln_binary_path: str, patch_binary_path: str, funcnames: list[str]):
        return cls(DebugParser.from_binary(vuln_binary_path, funcnames), DebugParser.from_binary(patch_binary_path, funcnames))
