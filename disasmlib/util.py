import re


def s2i(value, base=10):
    if value[0:2] == '0b':
        value = value[2:]
        if base != 2:
            raise ValueError('\'0b\' is a prefix of binary number: %s' % value)
    elif value[0:2] == '0x':
        value = value[2:]
        if base != 16:
            raise ValueError('\'0x\' is a prefix of binary number: %s' % value)
    return int(value, base)


def i2s(value, base=10):
    if base == 2:
        s = bin(value)
    elif base == 8:
        s = oct(value)
    elif base == 10:
        s = int(value)
    elif base == 16:
        s = hex(value)
    return s


def region(src, start=0, end=-1):
    if end < 0:
        end = len(src) + end + 1
    return [(i, src[i]) for i in range(start, end)]


def revregion(src, start=0, end=-1):
    return reversed(region(src, start, end))


class OperatorSequenceAutomaton(object):
    def __init__(self, sequence):
        self.sequence = sequence
        self.srcs = list()
        self.state = None

    def update(self, operator):
        seqidx = len(self.srcs)
        opstr = ' '.join(operator.op)
        match = re.match(self.sequence[seqidx], opstr)
        if match:
            self.srcs.append(operator)
            self.state = len(self.srcs)
        else:
            self.state = False

    def started(self):
        return self.state > 0

    def rejected(self):
        return self.state is False

    def accepted(self):
        return self.state == len(self.sequence)
