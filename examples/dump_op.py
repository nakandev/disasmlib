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

    with open(elfpath + '.dis2', 'w') as f:
        for section in elf.disasm.sections:
            print('section: %s' % section.name, file=f)
            for block in section.blocks:
                func = block.func
                if func and func.addr == block.addr:
                    opt = []
                    if func.is_leaf:
                        opt += ['leaf']
                    if func.is_noreturn:
                        opt += ['noreturn']
                    opt = str(opt)
                    print(' func: %x %s %s' % (func.addr, func.name, opt), file=f)
                if True:
                    opt = []
                    opt += ['depth:%d' % block.depth]
                    opt += ['depth-t:%d' % block.depth_terminal]
                    opt += [[hex(b.addr) for b in block.postblocks]]
                    print('  block: %x %s %s' % (block.addr, block.label, opt), file=f)
                for op in block.operators:
                    opt = []
                    if op.pseudo is not None:
                        opt += ['pseudo:%s' % str([
                            op.pseudo[0], [o.op[0] for o in op.pseudo[1]]
                        ])]
                    opt = str(opt)
                    print('   %d %x    %s %s' % (op.lineno, op.addr, ' '.join(op.op), opt), file=f)


if __name__ == '__main__':
    main()
