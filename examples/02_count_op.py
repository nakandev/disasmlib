from __future__ import print_function
import argparse
import elflib


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--elf', default=None)
    argparser.add_argument('--toolchain', default=None)
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
