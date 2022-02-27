class AsmMachine(object):
    cmd_prefix = '*'

    jumps = ('jmp', 'jmpq',)
    branchs = ('je', 'jne',)
    calls = ('call',)
    rets = ('ret',)
    _classes = list()

    def __init__(self):
        AsmMachine._classes.append(self.__class__)

    def jump_addr(self, disasm, op):
        return None

    def call_addr(self, disasm, op):
        return None

    def is_jumps(self, op):
        return op.op[0] in self.jumps

    def is_branchs(self, op):
        return op.op[0] in self.branchs

    def is_calls(self, op):
        return op.op[0] in self.calls

    def is_rets(self, op):
        return op.op[0] in self.rets
