import re


class AsmMachine(object):
    _classes = list()

    cmd_prefix = '*'

    jumps = ('jmp', 'jmpq',)
    branchs = ('je', 'jne',)
    calls = ('call',)
    rets = ('ret',)
    pseudos = ()

    def __init__(self):
        if self.__class__ not in AsmMachine._classes:
            AsmMachine._classes.append(self.__class__)
        _pseudos = list()
        for dst, srcs in self.pseudos:
            _dst = re.compile(' '.join(dst))
            _srcs = [re.compile(' '.join(src)) for src in srcs]
            _pseudo = (_dst, _srcs)
            _pseudos.append(_pseudo)
        self._pseudos = _pseudos

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
