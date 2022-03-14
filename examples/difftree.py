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
        funcs1 = self.elf1.disasm.funcs[:]
        funcs2 = self.elf2.disasm.funcs[:]
        pairs = list()
        for func1 in funcs1[:]:
            for func2 in funcs2[:]:
                if func1.name == func2.name:
                    pairs.append((func1, func2))
                    funcs1.remove(func1)
                    funcs2.remove(func2)
                    break
        rests = list()
        for func1 in funcs1:
            rests.append((func1, None))
        for func2 in funcs2:
            rests.append((None, func2))
        self._func_pairs = pairs
        self._func_rests = rests

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
                return ranks
            # ranks1 = rank_blocks(func1)
            # ranks2 = rank_blocks(func1)
            # self._block_pairs[func_pair] = (ranks1, ranks2)
            blocks1 = [b for b in func1.walk_blocks_by_rank()]
            blocks2 = [b for b in func2.walk_blocks_by_rank()]
            pairs = list()
            min_bidx = min(len(blocks1), len(blocks2))
            for bidx in range(min_bidx):
                pairs.append((blocks1[bidx], blocks2[bidx]))
            rests = list()
            for block1 in blocks1[min_bidx:]:
                rests.append((block1, None))
            for block2 in blocks2[min_bidx:]:
                rests.append((None, block2))
            self._block_pairs[func_pair] = pairs

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
            print('<html><body>', file=_f)
            for func_pair in self._func_pairs:
                func1, func2 = func_pair
                print('<h3>%s : %s</h3>' % (func1.name, func2.name), file=_f)
                print('<table border="1" rules="groups">', file=_f)
                for block_pair in self._block_pairs[func_pair]:
                    print('<tbody>', file=_f)
                    for diffline in self._difflines[block_pair]:
                        tag = {
                            'equal': '&nbsp;',
                            'delete': '-',
                            'insert': '+',
                            'replace': '*',
                        }
                        print('<tr>', file=_f)
                        print('<td>%s</td>' % tag[diffline[0]], file=_f)
                        print('<td>%s</td>' % diffline[1], file=_f)
                        print('<td>%s</td>' % diffline[2], file=_f)
                        print('</tr>', file=_f)
                    print('</tbody>', file=_f)
                print('</table>', file=_f)
            print('</body></html>', file=_f)


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('elf1')
    argparser.add_argument('elf2')
    args = argparser.parse_args()
    elf1path = args.elf1
    elf2path = args.elf2

    def elf_read(elfpath):
        elf = disasmlib.ElfFile(elfpath)
        elf.set_toolchain(args.toolchain)
        elf.read()
        return elf

    elf1 = elf_read(elf1path)
    elf2 = elf_read(elf2path)
    diffasm = DiffAsmTree(elf1, elf2)
    diffasm.print_html('diff.html')


if __name__ == '__main__':
    main()
