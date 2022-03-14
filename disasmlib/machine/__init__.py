from .x86 import X86Machine
from .riscv import RISCVMachine


def estimate_machine(readelf):
    eh = readelf.read_elf_header()
    if False:
        pass
    elif eh.e_machine == 0xf3:
        return RISCVMachine()
    else:
        return X86Machine()
