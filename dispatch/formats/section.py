class Section(object):
    '''
    Represents a section from an executable. All common executable formats have nearly the exact same idea of a
    section, so we just put it into a unified class for easy, consistent access
    '''
    def __init__(self):
        self.name = ''
        self.vaddr = 0
        self.offset = 0
        self.size = 0
        self.raw = None

        self.readable = False
        self.writable = False
        self.executable = False

        self.orig_section = None

    def __repr__(self):
        return '<Section {} at vaddr {}>'.format(self.name, hex(self.vaddr))

    def contains_vaddr(self, vaddr):
        return self.vaddr <= vaddr < self.vaddr + self.size

def section_from_elf_section(elf_section):
    s = Section()
    s.name = elf_section.name
    s.vaddr = elf_section['sh_addr']
    s.offset = elf_section['sh_offset']
    s.size = elf_section['sh_size']
    s.raw = elf_section.data()

    s.writable = bool(elf_section['sh_flags'] & 0x1)
    s.readable = bool(elf_section['sh_flags'] & 0x2)
    s.executable = bool(elf_section['sh_flags'] & 0x4)

    s.orig_section = elf_section

    return s

def section_from_macho_section(macho_section, macho_segment):
    s = Section()
    s.name = macho_section.sectname.rstrip('\x00')
    s.vaddr = macho_section.addr
    s.offset = macho_section.offset
    s.size = macho_section.size
    if hasattr(macho_section, 'section_data'):
        s.raw = macho_section.section_data
    else:
        s.raw = ''
    s.readable = bool(macho_segment.initprot & 0x1)
    s.writable = bool(macho_segment.initprot & 0x2)
    s.executable = bool(macho_segment.initprot & 0x4)

    s.orig_section = macho_section

    return s

def section_from_pe_section(pe_section, pe):
    s = Section()
    s.name = pe_section.Name.strip('\x00')
    s.vaddr = pe_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
    s.offset = pe_section.PointerToRawData
    s.size = pe_section.SizeOfRawData
    s.raw = pe_section.get_data()

    s.writable = bool(pe_section.Characteristics & 0x80000000)
    s.readable = bool(pe_section.Characteristics & 0x40000000)
    s.executable = bool(pe_section.Characteristics & 0x20000000)

    s.orig_section = pe_section

    return s



