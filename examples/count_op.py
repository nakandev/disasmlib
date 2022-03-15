from __future__ import print_function
import argparse
import disasmlib


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('elf')
    args = argparser.parse_args()
    elfpath = args.elf

    elf = disasmlib.ElfFile(elfpath)
    elf.set_toolchain(args.toolchain)
    elf.read()

    count = 0
    for op in elf.disasm.operators:
        if op.op[0] in ('mv', 'mov'):
            count += 1
    mov_num = count
    print('sections=%d, funcs=%d, blocks=%d, ops=%s' % (
        len(elf.disasm.sections),
        len(elf.disasm.funcs),
        len(elf.disasm.blocks),
        len(elf.disasm.operators)))
    print('mv|mov=%d' % (mov_num))


if __name__ == '__main__':
    main()
