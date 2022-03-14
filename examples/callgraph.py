from __future__ import print_function
import argparse
import disasmlib
import subprocess
import sys
if sys.version_info < (3,):
    from StringIO import StringIO
else:
    from io import StringIO


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--elf', default=None)
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('--target', '-T', choices=('dot', 'png', 'svg'), default='dot')
    argparser.add_argument('--hide-alone', default=False, action='store_true')
    args = argparser.parse_args()
    elfpath = args.elf

    elf = disasmlib.ElfFile(elfpath)
    elf.set_toolchain(args.toolchain)
    elf.read()

    def print_cfg(f):
        print('digraph test {', file=f)
        for func in elf.disasm.funcs:
            jumpfuncs = list()
            past = list()
            for block in func.blocks:
                for postblock in block.postblocks:
                    if postblock.func not in past and postblock.func != func:
                        jumpfuncs.append(postblock.func)
                    if postblock.func not in past:
                        past.append(postblock.func)
            if len(jumpfuncs) + len(func.calleefuncs) == 0:
                print('"%s";' % (func.name), file=f)
                continue
            for callee in func.calleefuncs:
                print('"%s" -> "%s";' % (func.name, callee.name),  file=f)
            for jump in jumpfuncs:
                print('"%s" -> "%s" [style="dashed"];' % (func.name, jump.name),  file=f)
        print('}', file=f)

    if args.target == 'dot':
        f = open(elfpath + '.cfg.dot', 'w')
    else:
        f = StringIO()
        print_cfg(f)
        p = subprocess.Popen(
            ['dot', '-T', args.target, '-o', elfpath + '.cfg.dot.' + args.target],
            stdin=subprocess.PIPE)
        p.communicate(input=f.getvalue().encode())


if __name__ == '__main__':
    main()
