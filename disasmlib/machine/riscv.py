from .machine import AsmMachine


class RISCVMachine(AsmMachine):
    command_prefix = 'riscv*'

    jumps = ('j', 'jr', 'c.j', 'c.jr',)
    branchs = (
            'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
            'bltu', 'bgtu', 'bleu', 'bgeu',
            'beqz', 'bnez', 'bltz', 'bgtz', 'blez', 'bgez',
            'c.beq', 'c.bne', 'c.blt', 'c.bgt', 'c.ble', 'c.bge',
            'c.beqz', 'c.bnez', 'c.bltz', 'c.bgtz', 'c.blez', 'c.bgez',
            )
    calls = ('call', 'jal', 'jalr', 'c.jal', 'c.jalr')
    rets = ('ret', 'c.ret',)

    pseudos = (
        (('call',), (('auipc', '(x1|ra)'), ('jalr', '(x1|ra)', '((0x)?[0-9a-f]+)', '(x0|zero)'))),
        (('call',), (('auipc', '(x1|ra)'), ('jalr', '(x1|ra)', '(x0|zero)', '((0x)?[0-9a-f]+)'))),
        (('ret',), (('jalr', '(x0|zero)', '(x1|ra)', '0'),)),
        (('ret',), (('jalr', '(x0|zero)', '0', '(x1|ra)'),)),
    )

    def jump_addr(self, disasm, op):
        addr = None
        if op.op[0] in (('j', 'c.j') + self.branchs):
            addr = int(op.op[-2], 16)
        elif op.op[0] in ('jr', 'c.jr'):
            pass
        elif op.op[0] in ('jalr', 'c.jalr') and op.op[1] in ('x0', 'zero') and len(op.op) > 2:
            addr = int(op.op[-2], 16)
        return addr

    def call_addr(self, disasm, op):
        addr = None
        if op.op[0] in ('jal', 'c.jal'):
            # jal offset <label> / jal x1,offset <label>
            addr = int(op.op[-2], 16)
            if op.func.isin_addr(addr):
                addr = None
        elif op.op[0] in ('jalr', 'c.jalr'):
            try:
                addr = int(op.comment.lstrip().split()[0], 16)
            except Exception:
                addr = None
        return addr
