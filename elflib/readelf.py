import struct


class ElfHeader(object):
    CLASS_NONE, CLASS_32, CLASS_64 = 0, 1, 2
    ei_key = (
        'ei_mag',
        'ei_class',
        'ei_data',
        'ei_version',
        'ei_osabi',
        'ei_abiversion',
        'ei_pad',
        'ei_nindent',
    )
    e_key = (
        'e_type',
        'e_machine',
        'e_version',
        'e_entry',
        'e_phoff',
        'e_shoff',
        'e_flags',
        'e_ehsize',
        'e_phentsize',
        'e_phnum',
        'e_shentsize',
        'e_shnum',
        'e_shstrndx',
    )

    def __init__(self):
        pass


class SectionHeader(object):
    SHT = ('NULL', 'PROGBITS', 'SYMTAB', 'STRTAB', 'RELA', 'HASH', 'DYNAMIC',
           'NOTE', 'NOTIBS', 'REL', 'SHLIB', 'DYNSYM', 'LOPROC', 'HIPROC',
           'LOUSER', 'HIUSER')
    SHF = ('WRITE', 'ALLOC', 'EXECINSTR', 'MASKPROC')
    sh_key = (
        'sh_name',
        'sh_type',
        'sh_flags',
        'sh_addr',
        'sh_offset',
        'sh_size',
        'sh_link',
        'sh_info',
        'sh_addralign',
        'sh_entsize',
    )

    def __init__(self):
        self.name = str()


class SymbolTable(object):
    STT = ('NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'LOPROC', 'HIPROC')
    STB = ('LOCAL', 'GLOBAL', 'WEAK', 'LOPROC', 'HIPROC')
    STV = ('DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED')
    st_key_32 = (
        'st_name',
        'st_value',
        'st_size',
        'st_info',
        'st_other',
        'st_shndx',
    )
    st_key_64 = (
        'st_name',
        'st_info',
        'st_other',
        'st_shndx',
        'st_value',
        'st_size',
    )

    def __init__(self):
        self.sh = None
        self.name = str()

    @property
    def st_type(self):
        return self.st_info % 16

    @property
    def st_bind(self):
        return self.st_info // 16


class ReadElf(object):
    EH = ElfHeader
    SH = SectionHeader
    ST = SymbolTable

    def __init__(self, f):
        if isinstance(f, str):
            f = open(f, 'rb')
        self.f = f
        self.elf_header = None
        self.section_headers = list()

    def read_elf_header(self):
        self.f.seek(0)
        binary = self.f.read(64)
        e_indent = struct.unpack('<4sBBBBBBBBBBBB', binary[0:16])
        elf_header = ElfHeader()
        for i, k in enumerate(elf_header.ei_key):
            setattr(elf_header, k, e_indent[i])
        if elf_header.ei_mag != b'\x7fELF':
            raise ValueError('binary is not ELF file: %s' % elf_header.ei_mag)
        if elf_header.ei_class == elf_header.CLASS_32:
            e_values = struct.unpack('<HHLLLLLHHHHHH', binary[16:52])
        elif elf_header.ei_class == elf_header.CLASS_64:
            e_values = struct.unpack('<HHLQQQLHHHHHH', binary[16:64])
        else:
            raise ValueError('ELF file is invalid class')
        for i, k in enumerate(elf_header.e_key):
            setattr(elf_header, k, e_values[i])
        self.elf_header = elf_header
        return self.elf_header

    def read_section_headers(self):
        elf_header = self.elf_header
        self.f.seek(elf_header.e_shoff)
        shs = list()
        for sh_idx in range(elf_header.e_shnum):
            binary = self.f.read(elf_header.e_shentsize)
            if elf_header.ei_class == elf_header.CLASS_32:
                sh_values = struct.unpack('<LLLLLLLLLL', binary)
            elif elf_header.ei_class == elf_header.CLASS_64:
                sh_values = struct.unpack('<LLQQQQLLQQ', binary)
            sh = SectionHeader()
            for i, k in enumerate(sh.sh_key):
                setattr(sh, k, sh_values[i])
            shs.append(sh)
        # read 'section name table' section, and set true name
        shstrtab_sh = shs[elf_header.e_shstrndx]
        self.f.seek(shstrtab_sh.sh_offset)
        binary = self.f.read(shstrtab_sh.sh_size)
        for sh in shs:
            offset = sh.sh_name
            for i in range(offset, len(binary)):
                if binary[i] == b'\x00':
                    break
            sh.name = binary[offset:i]
        self.section_headers = shs
        return self.section_headers

    def read_symbol_tables(self):
        elf_header = self.elf_header
        shs = self.section_headers
        st_shs = list()
        for i, sh in enumerate(shs):
            if sh.sh_type == SectionHeader.SHT.index('SYMTAB'):
                st_shs.append(sh)
                break
        sts = list()
        for sh in st_shs:
            self.f.seek(sh.sh_offset)
            for sti in range(sh.sh_size // sh.sh_entsize):
                binary = self.f.read(sh.sh_entsize)
                if elf_header.ei_class == elf_header.CLASS_32:
                    st_values = struct.unpack('<LLLBBH', binary)
                    st_key = SymbolTable.st_key_32
                elif elf_header.ei_class == elf_header.CLASS_64:
                    st_values = struct.unpack('<LBBHQQ', binary)
                    st_key = SymbolTable.st_key_64
                st = SymbolTable()
                for i, k in enumerate(st_key):
                    setattr(st, k, st_values[i])
                st.sh = sh
                sts.append(st)
        # read 'symbol name table' section, and set true name
        for st in sts:
            ststrtab_sh = shs[st.sh.sh_link]
            self.f.seek(ststrtab_sh.sh_offset)
            binary = self.f.read(ststrtab_sh.sh_size)
            offset = st.st_name
            if offset == 0:
                st.name = ''
            else:
                for i in range(offset, len(binary)):
                    if binary[i] == b'\x00':
                        break
                st.name = binary[offset:i]
        self.symbol_tables = sts
        return self.symbol_tables
