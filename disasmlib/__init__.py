from __future__ import print_function
import glob
import os
import re
import subprocess
import sys
from .machine import estimate_machine
from .readelf import ReadElf
from .util import OperatorSequenceAutomaton


__version__ = '0.1.0'


class AsmOperator(object):
    def __init__(self, data=None):
        self.rawdata = str()
        self.lineno = None
        self.block = None
        self.addr = None
        self.binops = list()
        self.strops = list()
        self.comment = str()
        self.pseudo = None
        if data is not None:
            self.rawdata = data
            self._split_identifiers()

    @property
    def machine(self):
        return self.block.machine

    @property
    def func(self):
        return self.block.func

    @property
    def binsize(self):
        return len(self.binops) / 2

    @property
    def op(self):
        return self.strops

    @property
    def is_jumps(self):
        return self.machine.is_jumps(self)

    @property
    def is_branchs(self):
        return self.machine.is_branchs(self)

    @property
    def is_calls(self):
        return self.machine.is_calls(self)

    @property
    def is_nops(self):
        return self.machine.is_nops(self)

    @property
    def is_rets(self):
        return self.machine.is_rets(self)

    def _split_comment(self, line):
        sps = ('#', ';', '//', ('/*', '*/'))
        min_idx, min_sp = len(line), None
        for i, sp in enumerate(sps):
            sp = sp[0] if isinstance(sp, tuple) else sp
            idx = line.find(sp)
            if 0 <= idx < min_idx:
                min_idx, min_sp = idx, sp
        if min_sp is None:
            code, comment = line.rstrip(), ''
        else:
            if isinstance(min_sp, tuple):
                code, comment = line.split(min_sp[0], 1)
                code = code.rstrip()
                comment, _ = comment.split(min_sp[1], 1)
            else:
                code, comment = line.split(min_sp, 1)
                code = code.rstrip()
        return code, comment

    def _split_identifiers(self):
        code, comment = self._split_comment(self.rawdata)
        hexno = '[0-9a-fA-F]'
        refmt = r' *({hexno}+):\s+({hexno}{{2}}(?: ?{hexno}{{2}})*)\s\s+(\w.+)'
        refmt = refmt.format(hexno=hexno)
        match = re.match(refmt, code)
        if not match:
            raise ValueError('Unknown asm syntax: "{}"'.format(code))
        addr, binop, strops = match.groups()
        binops = ''.join(binop.split())
        strops = re.sub('[,()]', ' ', strops).rstrip().split()
        self.addr = int(addr, 16)
        self.binops = binops
        self.strops = strops
        self.comment = comment


class AsmBlock(object):
    def __init__(self, **kwargs):
        self.addr = None
        self.label = str()
        self.section = None
        self.func = None
        self.operators = list()
        self.preblocks = list()
        self.postblocks = list()
        self.depth = -1
        self.depth_terminal = -1
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def machine(self):
        return self.section.machine

    def lastop(self, nonop=False):
        idx = len(self.operators) - 1
        if nonop:
            while idx > 0 and self.operators[idx].is_nops:
                idx -= 1
        return self.operators[idx]

    def copy_for_swap_postblocks(self):
        block = AsmBlock()
        block.addr = self.addr
        block.label = self.label
        block.section = self.section
        block.func = self.func
        block.operators = self.operators
        block.preblocks = self.preblocks[:]
        block.postblocks = self.postblocks[:]
        return block

    def add_postblocks(self, blocks):
        blocks = [blocks] if isinstance(blocks, AsmBlock) else blocks
        for block in blocks:
            if block not in self.postblocks:
                self.postblocks.append(block)
        for block in blocks:
            if self not in block.preblocks:
                block.preblocks.append(self)

    def isin_addr(self, addr):
        if len(self.operators) == 0:
            return self.addr == addr
        return self.addr <= addr <= self.operators[-1].addr


class AsmFunc(object):
    def __init__(self):
        self.elf = None
        self.section = None
        self.rawdata = None
        self.bind = 0  # 0:local 1:global 2:weak
        self.addr = -1
        self.size = -1
        self.name = str()
        self.blocks = list()
        self.callerfuncs = list()
        self.calleefuncs = list()

    @property
    def machine(self):
        return self.elf.machine

    @property
    def operators(self):
        ops = list()
        for block in self.blocks:
            ops += block.operators
        return ops

    @property
    def max_depth(self):
        return max([block.depth for block in self.blocks])

    def walk_blocks_by_depth(self):
        def _walk(block, visited):
            visited += [block]
            yield block, True  # go foward
            for child in block.postblocks:
                if child not in visited and child.func == self:
                    for _ in _walk(child, visited): yield _  # noqa
            yield block, False  # go back

        if len(self.blocks) > 0:
            rest = self.blocks[:]
            visited = []
            while len(rest) > 0:
                first = rest[0]
                for _ in _walk(first, visited): yield _  # noqa
                for b in visited:
                    if b in rest:
                        rest.remove(b)

    def walk_blocks_by_rank(self):
        blocks = self.blocks
        blocks = sorted(blocks, key=lambda b: b.depth_terminal)
        blocks = sorted(blocks, key=lambda b: b.depth)
        for block in blocks:
            yield block

    def block_routes_to_terminals(self):
        routes = list()
        route = list()
        prev_foward = True
        for block, gofoward in self.walk_blocks_by_depth():
            if gofoward:
                route.append(block)
            else:
                if prev_foward:
                    routes.append(route[:])
                route.remove(block)
            prev_foward = gofoward
        return routes

    def operators_path(self, start, end):
        path = list()
        block = end
        while True:
            path.append(block)
            if block == start:
                break
            if len(block.preblocks) == 0:
                break
            else:
                block = block.preblocks[0]
        return path

    @property
    def is_leaf(self):
        for op in self.operators:
            if op.is_calls:
                return False
        return True

    @property
    def is_noreturn(self):
        return False

    def add_calleefuncs(self, funcs):
        funcs = [funcs] if isinstance(funcs, AsmFunc) else funcs
        for func in funcs:
            if func not in self.calleefuncs:
                self.calleefuncs.append(func)
        for func in funcs:
            if self not in func.callerfuncs:
                func.callerfuncs.append(self)

    def isin_addr(self, addr):
        if self.size > 0:
            return self.addr <= addr < self.addr + self.size
        elif self.size == 0 or len(self.operators) == 0:
            return self.addr == addr
        return self.addr <= addr <= self.operators[-1].addr


class AsmSection(object):
    def __init__(self, *args):
        self.elf = None
        self.disasm = None
        attrkeys = 'name, tp, addr, off, size, es, flg, lk, inf, al'.split(', ')
        if len(args) != len(attrkeys):
            raise ValueError('too few args in AsmSection.__init__()')
        kvs = zip(attrkeys, args)
        for k, v in kvs:
            v = str(v) if k in ('name', 'tp', 'flg') else int(v)
            setattr(self, k, v)
        self.funcs = list()
        self.blocks = list()

    @property
    def machine(self):
        return self.elf.machine


class DisasmFile(object):
    def __init__(self):
        self.elf = None
        self.sections = list()
        self._machine = None

    @property
    def machine(self):
        if self.elf:
            return self.elf.machine
        return self._machine

    @property
    def funcs(self):
        funcs = list()
        for section in self.sections:
            funcs += section.funcs
        return funcs

    @property
    def blocks(self):
        blocks = list()
        for section in self.sections:
            blocks += section.blocks
        return blocks

    @property
    def operators(self):
        ops = list()
        for block in self.blocks:
            ops += block.operators
        return ops

    def set_machine(self, value):
        if self.elf:
            self.elf.machine = value
        else:
            self._machine = value


class ElfFile(object):
    def __init__(self, path):
        self.elfpath = path
        self._machine = None
        self._toolchain = None
        self._cmd = {
            'readelf': 'readelf',
            'nm': 'nm',
            'objdump': 'objdump',
        }
        self.sections = list()
        self.funcs = list()
        self.disasm = None
        self._rfunc = dict()
        self.readelf = None

    @property
    def machine(self):
        return self._machine

    @property
    def cmd(self):
        return self._cmd

    def set_machine(self, value):
        self._machine = value

    def set_toolchain(self, value):
        self._toolchain = value

    def read(self):
        os.environ['LANG'] = 'C'
        self._check_elfpath()
        self._find_commands()
        self._read_header()
        self._read_disasm()

    def _get_section(self, name):
        for section in self.sections:
            if section.name == name:
                return section
        raise ValueError('not found in section list: %s' % name)

    def _get_func(self, addr):
        if addr not in self._rfunc:
            raise ValueError('not found in func list: %s' % hex(addr))
        return self._rfunc[addr]

    def _get_block(self, addr):
        for block in self.blocks:
            if block.addr == addr:
                return block
        raise ValueError('not found in block list: %s' % hex(addr))

    def _check_elfpath(self):
        self.elfpath_is_elf = False
        try:
            self.readelf = ReadElf(self.elfpath)
            self.readelf.read_elf_header()
            self.elfpath_is_elf = True
        except FileNotFoundError:
            raise FileNotFoundError(self.elfpath)
        except Exception as e:
            raise e
        return self.elfpath_is_elf

    def _find_commands(self):
        cmd_keys = ('readelf', 'nm', 'objdump')
        cmd_dict = dict()
        if self._toolchain is None:
            toolchain_dir, prefix = None, None
        elif os.path.isdir(self._toolchain):
            toolchain_dir, prefix = self._toolchain, None
        else:
            toolchain_dir, prefix = os.path.split(self._toolchain)
        self.set_machine(estimate_machine(self.readelf))
        if prefix is None:
            if self.machine is not None:
                prefix = self.machine.command_prefix
            else:
                prefix = '*'
        if toolchain_dir:
            for k in cmd_keys:
                path = os.path.join(toolchain_dir, prefix + k)
                files = glob.glob(path + '.exe')
                files += glob.glob(path)
                if len(files) > 0:
                    cmd_dict[k] = files[0]
                else:
                    if sys.version_info[0] == 2:
                        FileNotFoundError = IOError
                    raise FileNotFoundError(path)
        self._cmd.update(cmd_dict)

    def _read_header(self):
        self.sections = list()
        self.funcs = list()
        if not self.elfpath_is_elf:
            return
        readelf = self.readelf
        readelf.read_section_headers()
        for sh in readelf.section_headers:
            section = AsmSection(
                sh.name, sh.sh_type, sh.sh_addr, sh.sh_offset,
                sh.sh_size, sh.sh_entsize, sh.sh_flags, sh.sh_link,
                sh.sh_info, sh.sh_addralign)
            section.elf = self
            self.sections.append(section)
        self.sections.sort(key=lambda x: x.addr)
        readelf.read_symbol_tables()
        for i, st in enumerate(readelf.symbol_tables):
            if st.st_type == st.STT.index('FUNC'):
                func = AsmFunc()
                func.elf = self
                func.bind = st.st_bind
                func.addr = st.st_value
                func.size = st.st_size
                func.name = st.name
                self.funcs.append(func)
                # make index for self._get_func(addr)
                if st.st_bind == st.STB.index('WEAK'):
                    self._rfunc.setdefault(func.addr, func)
                else:
                    prefunc = self._rfunc.get(func.addr)
                    if prefunc is None:
                        self._rfunc[func.addr] = func
                    elif prefunc.bind == st.STB.index('WEAK'):
                        self._rfunc[func.addr] = func
            self.funcs.sort(key=lambda x: x.addr)

    def _collect_section_list_by_readelf(self):
        proc = subprocess.Popen(
            [self.cmd['readelf'], '-S', '-W', self.elfpath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, err = proc.communicate()
        out = out.decode()
        # with open(self.elfpath + '.section', 'w') as f:
        #     f.write(out)
        self.sections = list()
        for line in out.splitlines():
            match = re.match(r'  \[ *([0-9]+)\] (.+)', line)
            if not match:
                continue
            data = match.group(2).strip().split()
            if len(data) == 8:
                data.insert(0, '')
            if len(data) == 9:
                data.insert(6, '')
            name, tp, addr, off, size, es, flg, lk, inf, al = data
            addr = int(addr, 16)
            off = int(off, 16)
            size = int(size, 16)
            es = int(es, 16)
            section = AsmSection(name, tp, addr, off, size, es, flg, lk, inf, al)
            section.elf = self
            self.sections.append(section)

    def _collect_func_list_by_nm(self):
        proc = subprocess.Popen(
            [self.cmd['nm'], '-a', self.elfpath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, err = proc.communicate()
        out = out.decode()
        # with open(self.elfpath + '.nm', 'w') as f:
        #     f.write(out)
        self.funcs = list()
        for line in out.splitlines():
            data = line.strip().split()
            if len(data) == 2:
                data.insert(0, None)  # addr
            if len(data) == 3:
                data.insert(1, None)  # size
            addr, size, tp, label = data
            if tp in ('t', 'T', 'w', 'W'):
                bind = 0 if tp == 't' else 1 if tp == 'T' else 2
                func = AsmFunc()
                func.elf = self
                func.bind = bind
                func.addr = int(addr, 16) if addr is not None else None
                func.size = int(size, 16) if size is not None else None
                func.name = label
                self.funcs.append(func)
                # make index for self._get_func(addr)
                if bind == ReadElf.ST.STB.index('WEAK'):
                    self._rfunc.setdefault(func.addr, func)
                else:
                    prefunc = self._rfunc.get(func.addr)
                    if prefunc is None:
                        self._rfunc[func.addr] = func
                    elif prefunc.bind == ReadElf.ST.STB.index('WEAK'):
                        self._rfunc[func.addr] = func

    def _collect_func_list_by_readelf(self):
        proc = subprocess.Popen(
            [self.cmd['readelf'], '-s', '-W', self.elfpath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, err = proc.communicate()
        out = out.decode()
        # with open(self.elfpath + '.symtab', 'w') as f:
        #     f.write(out)
        self.funcs = list()
        for line in out.splitlines():
            match = re.match(r' *([0-9]+): (.+)', line)
            if not match:
                continue
            data = match.group(2).lstrip().split(None, 6)
            if len(data) == 6:
                data.append('')  # name
            val, size, tp, bind, vis, ndx, name = data
            if tp == 'FUNC':
                func = AsmFunc()
                func.elf = self
                func.bind = bind
                func.addr = int(val, 16)
                func.size = int(size)
                func.name = name
                self.funcs.append(func)
                # make index for self._get_func(addr)
                if bind == ReadElf.ST.STB.index('WEAK'):
                    self._rfunc.setdefault(func.addr, func)
                else:
                    prefunc = self._rfunc.get(func.addr)
                    if prefunc is None:
                        self._rfunc[func.addr] = func
                    elif prefunc.bind == ReadElf.ST.STB.index('WEAK'):
                        self._rfunc[func.addr] = func

    def _read_disasm(self):
        if self.elfpath_is_elf:
            proc = subprocess.Popen(
                # [self.cmd['objdump'], '-d', '-M', 'no-aliases', self.elfpath],
                [self.cmd['objdump'], '-d', self.elfpath],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            out, err = proc.communicate()
            if proc.returncode != 0:
                raise Exception('Disassemble error with exitcode %d: %s' % (proc.returncode, out))
            out = out.decode()
            with open(self.elfpath + '.dis', 'w') as f:
                f.write(out)
        else:
            with open(self.elfpath, 'r') as f:
                out = f.read()
        self._build_first_asm_tree(out)
        self._split_block_by_jump_targets()
        if not self.elfpath_is_elf:
            self._collect_func_list_by_tree()
        self._set_pseudo_instructions()

    def _build_first_asm_tree(self, disasmstr):
        re_section = re.compile(r'^Disassembly of section ([^ ]+):')
        re_label_head = re.compile(r'^([0-9a-fA-F]+) <?([^ >]+)>?:$')
        lines = disasmstr.splitlines()
        self.disasm = DisasmFile()
        self.disasm.elf = self
        current_section = None
        current_func = None
        current_block = None
        for i, line in enumerate(lines):
            if line.strip() == '':
                continue
            # section
            match = re_section.match(line)
            if match:
                current_func = None
                current_block = None
                name, = match.groups()
                try:
                    current_section = self._get_section(name)
                except ValueError:
                    current_section = AsmSection(name, '', -1, -1, 0, 0, '', 0, 0, 0)
                    current_section.elf = self
                    self.sections.append(current_section)
                self.disasm.sections.append(current_section)
                continue
            # block label
            match = re_label_head.match(line)
            if match:
                addr, label = match.groups()
                addr = int(addr, 16)
                current_block = AsmBlock(label=label, addr=addr)
                current_block.section = current_section
                self.disasm.blocks.append(current_block)
                current_section.blocks.append(current_block)
                try:
                    current_func = self._get_func(addr)
                    current_func.section = current_section
                    current_section.funcs.append(current_func)
                    current_block.func = current_func
                    current_func.blocks.append(current_block)
                except ValueError:
                    # if file type is disasm, func will not detected here
                    pass
                continue
            # operator
            try:
                op = AsmOperator(data=line)
                op.lineno = i + 1
                op.block = current_block
                current_block.operators.append(op)
                op.block = current_block
            except ValueError:
                pass
        # estimate unconfigured attributes of sections
        for section in self.disasm.sections:
            if section.addr == -1:
                section.addr = section.blocks[0].addr
            if section.size == -1:
                first_addr = section.operators[0].addr
                last_op = section.operators[-1]
                last_addr = last_op.addr + len(last_op.binsize)
                section.size = last_addr - first_addr

    def _collect_func_list_by_tree(self):
        # blocks that do not jump/branch from anywhere are considered func heads
        self.funcs = list()
        for section in self.disasm.sections:
            current_func = None
            for block in section.blocks:
                if current_func is not None:
                    current_func.blocks.append(block)
                if block.label == '':
                    continue
                if len(block.preblocks) == 0:
                    current_func = AsmFunc()
                    current_func.elf = self
                    current_func.section = section
                    section.funcs.append(current_func)
                    block.func = current_func
                    current_func.blocks.append(block)
                    current_func.bind = '1'  # considered as Global
                    current_func.addr = block.addr
                    current_func.name = block.label
                    self.funcs.append(current_func)
                    self._rfunc[block.addr] = current_func

    def _split_block_by_jump_targets(self):
        jump_ops = list()
        jump_addrs = list()
        call_ops = list()
        call_addrs = list()

        def _collect_jump_ops():
            for op in self.disasm.operators:
                addr = self.machine.jump_addr(self.disasm, op)
                if addr is not None:
                    jump_ops.append([op, addr])
                    jump_addrs.append(addr)
                addr = self.machine.call_addr(self.disasm, op)
                if addr is not None:
                    call_ops.append([op, addr])
                    call_addrs.append(addr)
        _collect_jump_ops()
        jump_addrs = list(set(jump_addrs))
        call_addrs = list(set(call_addrs))

        def _split_blocks():
            for section in self.disasm.sections:
                for bidx in range(len(section.blocks))[::-1]:
                    block = section.blocks[bidx]
                    block_len = len(block.operators)
                    for opidx in range(block_len)[::-1]:
                        if opidx == 0:
                            break
                        op0 = block.operators[opidx]
                        op00 = block.operators[opidx - 1]
                        op00_is_branchs = op00.is_branchs

                        def _split_blocks__body():
                            operators0 = block.operators[:opidx]
                            operators1 = block.operators[opidx:]
                            block.operators = operators0
                            newblock = AsmBlock(addr=op0.addr)
                            newblock.section = section
                            newblock.func = block.func
                            newblock.operators = operators1
                            for op1 in operators1:
                                op1.block = newblock
                            section.blocks.insert(bidx + 1, newblock)
                        try:
                            op0_addr_idx = jump_addrs.index(op0.addr)
                        except Exception:
                            op0_addr_idx = -1
                        if op00_is_branchs or op0_addr_idx >= 0:
                            _split_blocks__body()
                            if op0_addr_idx >= 0:
                                jump_addrs.pop(op0_addr_idx)
        _split_blocks()

        def _connect_next_block():
            for bidx in range(len(self.disasm.blocks)):
                if bidx == len(self.disasm.blocks) - 1:
                    break
                block0 = self.disasm.blocks[bidx]
                block1 = self.disasm.blocks[bidx + 1]
                lastop = block0.lastop(nonop=True)
                if not (lastop.is_jumps or lastop.is_rets):
                    block0.add_postblocks(block1)
        _connect_next_block()

        def _connect_jump_destination_block():
            jump_ops.sort(key=lambda x: x[1])
            target_blocks = self.disasm.blocks[:]
            for op, addr in jump_ops:
                for tblock in target_blocks:
                    if tblock.isin_addr(addr) and addr not in call_addrs:
                        op.block.add_postblocks(tblock)
                        break
        _connect_jump_destination_block()

        def _update_func_blocks():
            for section in self.disasm.sections:
                for func in section.funcs:
                    func.blocks = list()
                current_func = None
                for block in section.blocks:
                    try:
                        current_func = self._get_func(block.addr)
                    except ValueError:
                        pass
                    if current_func:
                        block.func = current_func
                        current_func.blocks.append(block)
            call_ops.sort(key=lambda x: x[1])
            for op, addr in call_ops:
                for func in self.funcs:
                    if func.isin_addr(addr) and op.func is not None:
                        op.func.add_calleefuncs(func)
                        break
        _update_func_blocks()

        def _calc_depth():
            for section in self.disasm.sections:
                for func in section.funcs:
                    depth = 0
                    route = list()
                    prev_foward = True
                    for block, gofoward in func.walk_blocks_by_depth():
                        if gofoward:
                            route.append(block)
                            block.depth = depth
                            depth += 1
                        else:
                            depth -= 1
                            route.remove(block)
                            if prev_foward:
                                for rblock in route:
                                    if depth > rblock.depth_terminal:
                                        rblock.depth_terminal = depth
                        prev_foward = gofoward
        _calc_depth()

    def _set_pseudo_instructions(self):
        for section in self.disasm.sections:
            for func in section.funcs:
                automatons_stack = list()
                automatons_stack.append(list())
                for block, gofoward in func.walk_blocks_by_depth():
                    if gofoward:
                        automatons_stack.append(automatons_stack[-1][:])
                        automatons = [a.copy() for a in automatons_stack[-1]]
                        for op in block.operators:
                            def _update_automatons():
                                for item in automatons[:]:
                                    pidx, automaton = item
                                    automaton.update(op)
                            _update_automatons()

                            def _spawn_automatons():
                                for pidx in range(len(self.machine.pseudos)):
                                    sequence = self.machine._pseudos[pidx][1]
                                    automaton = OperatorSequenceAutomaton(sequence)
                                    automaton.update(op)
                                    if automaton.started():
                                        item = (pidx, automaton)
                                        automatons.append(item)
                            _spawn_automatons()

                            def _update_automatons():
                                for item in automatons[:]:
                                    pidx, automaton = item
                                    if automaton.rejected():
                                        automatons.remove(item)
                                        continue
                                    elif automaton.accepted():
                                        dst = self.machine.pseudos[pidx][0]
                                        srcs = automaton.srcs
                                        op.pseudo = (dst[0], srcs)
                                        automatons.remove(item)
                                        continue
                            _update_automatons()
                    else:
                        automatons_stack.pop()
