from __future__ import print_function
import argparse
import time
import disasmlib


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('elf')
    args = argparser.parse_args()
    elfpath = args.elf

    elf = disasmlib.ElfFile(elfpath)
    elf.set_toolchain(args.toolchain)
    print('reading elf...')
    start = time.time()
    elf.read()
    end = time.time()
    cputime = end - start
    print('cpu time=%f sec' % cputime)

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
