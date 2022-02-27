from __future__ import print_function
import argparse
import elflib


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--elf', default=None)
    argparser.add_argument('--toolchain', default=None)
    argparser.add_argument('--hide-alone', default=False, action='store_true')
    args = argparser.parse_args()
    elfpath = args.elf

    try:
        readelf = elflib.ReadElf(elfpath)
        eh = readelf.read_elf_header()
    except Exception:
        pass

    if eh.e_machine == 0xf3:
        if args.toolchain is None:
            raise Exception('In RISC-V ELF format, --toolchain option must set')
        elf = elflib.ElfFile(elfpath)
        elf.set_machine(elflib.RISCVMachine())
        elf.set_toolchain(dir=args.toolchain)
    else:
        elf = elflib.ElfFile(elfpath)
    elf.read()

    with open(elfpath + '.dot', 'w') as f:
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


if __name__ == '__main__':
    main()
