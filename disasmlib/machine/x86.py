from .machine import AsmMachine


class X86Machine(AsmMachine):
    jumps = ('jmp', 'jmpq',)
    branchs = (
            'ja', 'jae', 'jna', 'jnae', 'jb', 'jbe', 'jnb', 'jnbe',
            'jc', 'jnc', 'jcxz', 'jecxz',
            'je', 'jne', 'jz', 'jnz',
            'jg', 'jge', 'jng', 'jnge', 'jl', 'jle', 'jnl', 'jnle',
            'jo', 'jno', 'jp', 'jpe', 'jpo', 'jnp', 'js', 'jns',)
    calls = ('call', 'callq',)
    rets = ('ret', 'retq',)

    def jump_addr(self, disasm, op):
        addr = None
        if op.op[0] in self.jumps + self.branchs:
            try:
                addr = int(op.op[1], 16)
            except ValueError:
                # maybe *0123(indirect offset) or register
                pass
        return addr

    def call_addr(self, disasm, op):
        addr = None
        if op.op[0] in self.calls:
            try:
                addr = int(op.op[1], 16)
            except ValueError:
                # maybe *0123(indirect offset) or register
                pass
        return addr
