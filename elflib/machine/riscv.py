from .machine import AsmMachine


class RISCVMachine(AsmMachine):
    command_prefix = 'riscv*'

    jumps = ('j', 'jr', 'c.j', 'c.jr',)
    branchs = (
            'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
            'beqz', 'bnez', 'bltz', 'bgtz', 'blez', 'bgez',
            'c.beq', 'c.bne', 'c.blt', 'c.bgt', 'c.ble', 'c.bge',
            'c.beqz', 'c.bnez', 'c.bltz', 'c.bgtz', 'c.blez', 'c.bgez',
            )
    calls = ('call', 'jal', 'jalr', 'c.jal', 'c.jalr')
    rets = ('ret', 'c.ret',)

    def jump_addr(self, disasm, op):
        addr = None
        if op.op[0] in ('j', 'c.j') + self.branchs:
            addr = int(op.op[-2], 16)
        elif op.op[0] in ('jr', 'c.jr'):
            pass
        return addr

    def call_addr(self, disasm, op):
        addr = None
        if op.op[0] in ('jal', 'c.jal'):
            # jal offset <label> / jal x1,offset <label>
            addr = int(op.op[-2], 16)
        elif op.op[0] in ('jalr', 'c.jalr'):
            try:
                addr = int(op.comment.lstrip().split()[0], 16)
            except Exception:
                addr = None
        return addr