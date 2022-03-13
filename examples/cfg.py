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
    argparser.add_argument('--vertical', default=False, action='store_true')
    argparser.add_argument('--max-depth', '-d', default=20, type=int)
    argparser.add_argument('--func', '-f',  default=None)
    args = argparser.parse_args()
    elfpath = args.elf

    try:
        readelf = disasmlib.ReadElf(elfpath)
        eh = readelf.read_elf_header()
    except Exception:
        pass

    if eh.e_machine == 0xf3:
        if args.toolchain is None:
            raise Exception('In RISC-V ELF format, --toolchain option must set')
        elf = disasmlib.ElfFile(elfpath)
        elf.set_machine(disasmlib.RISCVMachine())
        elf.set_toolchain(dir=args.toolchain)
    else:
        elf = disasmlib.ElfFile(elfpath)
    elf.read()

    vertical = args.vertical
    max_depth = args.max_depth
    if args.func is None:
        func = args.func
    else:
        for fn in elf.disasm.funcs:
            if fn.name == args.func:
                func = fn
                break
        else:
            raise ValueError('funcion not found: "%s"' % args.func)

    def print_cfg(f, _func=None):
        print('digraph test {', file=f)
        funcs = elf.disasm.funcs if _func is None else [_func]
        if vertical:
            print('rankdir = RL', file=f)
            funcs = funcs[::-1]
        else:
            print('ranksep = 0.02', file=f)
            funcs = funcs[:]
        for func in funcs:
            print('subgraph "cluster_%x" {' % (func.addr), file=f)
            print('label = "%s"' % (func.name), file=f)
            if _func is None and func.max_depth > max_depth:
                block0 = func.blocks[0]
                label = '...'
                print('"%x" [shape=box, label="%s"]' % (block0.addr, label), file=f)
                print('}', file=f)
                continue
            for bidx in range(len(func.blocks)):
                block0 = func.blocks[bidx]
                lines = ['%x  %s' % (op.addr, ','.join(op.op)) for op in block0.operators]
                label = '\\l'.join(lines) + '\\l'
                print('"%x" [shape=box, label="%s"]' % (block0.addr, label), file=f)
            addrs = ['"%x"' % (b.addr) for b in func.blocks]
            if vertical:
                print('{rank = same; %s}' % ('; '.join(addrs)), file=f)
            print('}', file=f)
            if vertical:
                print('edge [dir=back]', file=f)
            for bidx in range(len(func.blocks)):
                block0 = func.blocks[bidx]
                for block1 in block0.postblocks:
                    if block1.func == func:
                        if vertical:
                            print('"%x" -> "%x"' % (block1.addr, block0.addr), file=f)
                        else:
                            print('"%x" -> "%x"' % (block0.addr, block1.addr), file=f)
        print('}', file=f)

    if args.target == 'dot':
        f = open(elfpath + '.cfg.dot', 'w')
        print_cfg(f, func)
    else:
        f = StringIO()
        print_cfg(f, func)
        p = subprocess.Popen(
            ['dot', '-T', args.target, '-o', elfpath + '.cfg.dot.' + args.target],
            stdin=subprocess.PIPE)
        p.communicate(input=f.getvalue().encode())


if __name__ == '__main__':
    main()
