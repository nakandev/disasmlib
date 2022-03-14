from __future__ import print_function
import argparse
import disasmlib


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--elf', default=None)
    argparser.add_argument('--toolchain', default=None)
    args = argparser.parse_args()
    elfpath = args.elf

    elf = disasmlib.ElfFile(elfpath)
    elf.set_toolchain(args.toolchain)
    elf.read()

    print('elf: sections=%d, funcs=%d' % (
        len(elf.sections),
        len(elf.funcs),))
    print('dis: sections=%d, funcs=%d, blocks=%d, ops=%s' % (
        len(elf.disasm.sections),
        len(elf.disasm.funcs),
        len(elf.disasm.blocks),
        len(elf.disasm.operators),))


if __name__ == '__main__':
    main()
