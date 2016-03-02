class Section(object):
    '''
    Represents a section from an executable. All common executable formats have nearly the exact same idea of a
    section, so we just put it into a unified class for easy, consistent access
    '''

    name = ''
    vaddr = 0
    offset = 0
    size = 0
    raw = None

    writable = False
    executable = False

    orig_section = None

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
    s.executable = bool(elf_section['sh_flags'] & 0x4)

    s.orig_section = elf_section

    return s

def section_from_macho_section(macho_section, macho_segment):
    s = Section()
    s.name = macho_section.sectname
    s.vaddr = macho_section.addr
    s.offset = macho_section.offset
    s.size = macho_section.size

    s.writable = bool(macho_segment.initprot & 0x2)
    s.executable = bool(macho_segment.initprot & 0x4)

    s.orig_section = macho_section

    return s

def section_from_pe_section(pe_section, pe):
    s = Section()
    s.name = pe_section.Name
    s.vaddr = pe_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
    s.offset = pe_section.get_file_offset()
    s.size = pe_section.SizeOfRawData
    s.raw = pe_section.get_data()

    s.writable = bool(pe_section.Characteristics & 0x80000000)
    s.executable = bool(pe_section.Characteristics & 0x20000000)

    s.orig_section = pe_section

    return s



