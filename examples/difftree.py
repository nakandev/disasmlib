from __future__ import print_function
import argparse
import disasmlib
import difflib


class DiffAsmTree(object):
    def __init__(self, elf1, elf2):
        self.elf1 = elf1
        self.elf2 = elf2
        self._correspond_funcs()
        self._correspond_blocks()
        self._generate_diff()

    def _correspond_funcs(self):
        def _get_func(name, funcs):
            for func in funcs:
                if name == func.name:
                    return func
            return disasmlib.AsmFunc()

        funcs1 = self.elf1.disasm.funcs[:]
        funcs2 = self.elf2.disasm.funcs[:]
        funcs = sorted(funcs1 + funcs2, key=lambda fn: fn.addr)
        pairs = list()
        while len(funcs) > 0:
            func = funcs.pop(0)
            if func in funcs1:
                func1 = func
                func2 = _get_func(func.name, funcs2)
            elif func in funcs2:
                func1 = _get_func(func.name, funcs1)
                func2 = func
            pairs.append((func1, func2))
            if func1 in funcs:
                funcs.remove(func1)
            if func2 in funcs:
                funcs.remove(func2)
        self._func_pairs = pairs

    def _correspond_blocks(self):
        self._block_pairs = dict()
        for func_pair in self._func_pairs:
            func1, func2 = func_pair

            def rank_blocks(func):
                ranks = list()
                for block in func.walk_blocks_by_rank():
                    if block.depth >= len(ranks):
                        ranks.append([])
                    ranks[block.depth].append(block)
                blocks = list()
                while len(blocks) != len(func.blocks):
                    for rank in ranks:
                        if len(rank):
                            blocks.append(rank.pop(0))
                return blocks
            # blocks1 = rank_blocks(func1)
            # blocks2 = rank_blocks(func2)
            blocks1 = [b for b in func1.walk_blocks_by_rank()]
            blocks2 = [b for b in func2.walk_blocks_by_rank()]
            pairs = list()
            min_bidx = min(len(blocks1), len(blocks2))
            for bidx in range(min_bidx):
                pairs.append((blocks1[bidx], blocks2[bidx]))
            rests = list()
            for block1 in blocks1[min_bidx:]:
                rests.append((block1, disasmlib.AsmBlock()))
            for block2 in blocks2[min_bidx:]:
                rests.append((disasmlib.AsmBlock(), block2))
            self._block_pairs[func_pair] = pairs
            self._block_pairs[func_pair] += rests

    def _generate_diff(self):
        def generate_difflines(sm, block1, block2):
            difflines = list()
            _lines1 = [op.rawdata for op in block1.operators]
            _lines2 = [op.rawdata for op in block2.operators]
            for sm_opcode in sm.get_opcodes():
                tag, i1, i2, j1, j2 = sm_opcode
                if tag == 'delete':
                    for offset in range(i2 - i1):
                        dline1 = _lines1[i1 + offset]
                        dline2 = ''
                        difflines.append((tag, dline1, dline2))
                elif tag == 'insert':
                    for offset in range(j2 - j1):
                        dline1 = ''
                        dline2 = _lines2[j1 + offset]
                        difflines.append((tag, dline1, dline2))
                elif tag == 'replace':
                    minlen = min(i2 - i1, j2 - j1)
                    for offset in range(minlen):
                        dline1 = _lines1[i1 + offset]
                        dline2 = _lines2[j1 + offset]
                        difflines.append((tag, dline1, dline2))
                    for offset in range((i2 - i1) - minlen):
                        dline1 = _lines1[i1 + offset + minlen]
                        dline2 = ''
                        difflines.append((tag, dline1, dline2))
                    for offset in range((j2 - j1) - minlen):
                        dline1 = ''
                        dline2 = _lines2[j1 + offset + minlen]
                        difflines.append((tag, dline1, dline2))
                else:  # 'replace' or 'equal'
                    for offset in range(i2 - i1):
                        dline1 = _lines1[i1 + offset]
                        dline2 = _lines2[j1 + offset]
                        difflines.append((tag, dline1, dline2))
            return difflines

        self._difflines = dict()
        for func_pair in self._func_pairs:
            func1, func2 = func_pair
            for block_pair in self._block_pairs[func_pair]:
                block1, block2 = block_pair
                lines1 = [op.op[0] for op in block1.operators]
                lines2 = [op.op[0] for op in block2.operators]
                sm = difflib.SequenceMatcher(None, lines1, lines2)
                difflines = generate_difflines(sm, block1, block2)
                self._difflines[block_pair] = difflines

    def print_html(self, fpath):
        with open(fpath, 'w') as _f:
            print('<html>', file=_f)
            print('<head>', file=_f)
            print('<style type="text/css">', file=_f)
            print('h3 {margin: 10 5 5 5;}', file=_f)
            print('tt {margin: 0 20 0 10;}', file=_f)
            print('.eq {}', file=_f)
            print('.del {background-color: #ccc;}', file=_f)
            print('.mod {background-color: #ff4;}', file=_f)
            print('</style>', file=_f)
            print('</head>', file=_f)
            print('<body>', file=_f)
            print('<table border="1" rules="groups">', file=_f)
            for func_pair in self._func_pairs:
                func1, func2 = func_pair
                print('<tr><td colspan="2">', file=_f)
                print('<h3>%s : %s</h3>' % (func1.name, func2.name), file=_f)
                print('</td></tr>', file=_f)
                for block_pair in self._block_pairs[func_pair]:
                    print('<tbody>', file=_f)
                    for diffline in self._difflines[block_pair]:
                        tag = {
                            'equal': ('eq', 'eq'),
                            'delete': ('mod', 'del'),
                            'insert': ('del', 'mod'),
                            'replace': ('mod', 'mod'),
                        }
                        print('<tr>', file=_f)
                        print('<td class="%s"><tt>%s</tt></td>' % (tag[diffline[0]][0], diffline[1]), file=_f)
                        print('<td class="%s"><tt>%s</tt></td>' % (tag[diffline[0]][1], diffline[2]), file=_f)
                        print('</tr>', file=_f)
                    print('</tbody>', file=_f)
            print('</table>', file=_f)
            print('</body></html>', file=_f)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('--outpath', '-o', default=None)
    argparser.add_argument('elf1')
    argparser.add_argument('elf2')
    args = argparser.parse_args()
    elf1path = args.elf1
    elf2path = args.elf2
    outpath = 'diff.html' if args.outpath is None else args.outpath

    def elf_read(elfpath):
        elf = disasmlib.ElfFile(elfpath)
        elf.set_toolchain(args.toolchain)
        elf.read()
        return elf

    elf1 = elf_read(elf1path)
    elf2 = elf_read(elf2path)
    diffasm = DiffAsmTree(elf1, elf2)
    diffasm.print_html(outpath)


if __name__ == '__main__':
    main()
