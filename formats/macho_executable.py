import logging
import struct
import pymacho
from pymacho.MachO import MachO
from pymacho.MachOSection import MachOSection
from pymacho.MachOSegment import MachOSegment
from pymacho.MachOMainCommand import MachOMainCommand

from base_executable import *
from section import *

INJECTION_SEGMENT_NAME = 'INJECT'
INJECTION_SECTION_NAME = 'inject'

class MachOExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(MachOExecutable, self).__init__(file_path)

        self.helper = MachO(self.fp)

        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

        self.pack_endianness = '<'

        self.sections = []
        for segment in self.helper.segments:
            for section in segment.sections:
                self.sections.append(section_from_macho_section(section, segment))

        self.executable_segment = [s for s in self.helper.segments if s.initprot & 0x4][0]

        self.next_injection_vaddr = 0

    def _identify_arch(self):
        machine = self.helper.header.display_cputype()
        if machine == 'i386':
            return ARCHITECTURE.X86
        elif machine == 'x86_64':
            return ARCHITECTURE.X86_64
        else:
            return None

    def executable_segment_vaddr(self):
        return self.executable_segment.vmaddr

    def executable_segment_size(self):
        return self.executable_segment.vmszie

    def _extract_symbol_table(self):
        ordered_symbols = []

        for cmd in self.helper.commands:
            # NOTE: Is it safe to assume to the symtab command always comes before the dysymtab command?
            if isinstance(cmd, pymacho.MachOSymtabCommand.MachOSymtabCommand):
                for i in range(len(cmd.syms)):
                    symbol = cmd.syms[i]

                    self.binary.seek(cmd.stroff)
                    symbol_strings = self.binary.read(cmd.strsize)

                    is_ext = symbol.n_type & 0x1 and symbol.n_value == 0

                    symbol_name = symbol_strings[symbol.n_strx:].split('\x00')[0]

                    # Ignore Apple's hack for radar bug 5614542
                    if not is_ext and symbol_name != 'radr://5614542':
                        size = 0
                        logging.debug('Adding function {} from the symtab at vaddr {} with size {}'
                                      .format(symbol_name, hex(symbol.n_value), hex(size)))
                        f = Function(symbol.n_value, size, symbol_name, self)
                        self.functions[symbol.n_value] = f

                    ordered_symbols.append(symbol_name)

            if isinstance(cmd, pymacho.MachODYSymtabCommand.MachODYSymtabCommand):
                self.binary.seek(cmd.indirectsymoff)
                indirect_symbols = self.binary.read(cmd.nindirectsyms*4)

                sym_offsets = struct.unpack('<' + 'I'*cmd.nindirectsyms, indirect_symbols)

                for section in self.executable_segment.sections:
                    if section.flags & pymacho.Constants.S_NON_LAZY_SYMBOL_POINTERS \
                        or section.flags & pymacho.Constants.S_LAZY_SYMBOL_POINTERS \
                        or section.flags & pymacho.Constants.S_SYMBOL_STUBS:

                        if section.flags & pymacho.Constants.S_SYMBOL_STUBS:
                            stride = section.reserved2
                        else:
                            stride = (64 if self.is_64_bit() else 32)

                        count = section.size / stride

                        for i in range(count):
                            addr = self.executable_segment.vmaddr + section.offset + (i * stride)
                            symbol_name = ordered_symbols[sym_offsets[i + section.reserved1]]
                            logging.debug('Adding function {} from the dynamic symtab at vaddr {} with size {}'
                                          .format(symbol_name, hex(addr), hex(stride)))
                            f = Function(addr, stride, symbol_name, self, type=Function.DYNAMIC_FUNC)
                            self.functions[addr] = f

    def iter_string_sections(self):
        STRING_SECTIONS = ['__const', '__cstring', '__objc_methname', '__objc_classname']
        for s in self.sections:
            if s.name in STRING_SECTIONS:
                yield s

    def _prepare_for_injection(self):
        # Total size of the stuff we're going to be adding in the middle of the binary
        offset = 72+80 if self.is_64_bit() else 56+68  # 1 segment header + 1 section header

        fileoff = (self.binary.len & ~0xfff) + 0x1000

        logging.debug('Creating new MachOSegment at vaddr {}'.format(hex(0x100000000 + fileoff)))
        new_segment = MachOSegment(arch=64 if self.is_64_bit() else 32)
        new_segment.segname = INJECTION_SEGMENT_NAME
        new_segment.fileoff = fileoff
        new_segment.filesize = 0
        new_segment.vmaddr = 0x100000000 + fileoff
        new_segment.vmsize = 0x1000
        new_segment.maxprot = 0x7 #RWX
        new_segment.initprot = 0x5 # RX
        new_segment.flags = 0
        new_segment.nsects = 1

        logging.debug('Creating new MachOSection at vaddr {}'.format(hex(0x100000000 + fileoff)))
        new_section = MachOSection(arch=64 if self.is_64_bit() else 32)
        new_section.sectname = INJECTION_SECTION_NAME
        new_section.segname = new_segment.segname
        new_section.addr = new_segment.vmaddr
        new_section.size = 0
        new_section.offset = new_segment.fileoff
        new_section.align = 4
        new_section.flags = 0x80000400
        new_section.data = ''
        new_section.relocs = []
        if self.is_64_bit():
            new_section.reserved3 = 0

        new_segment.sections = [new_section]

        self.helper.segments.append(new_segment)

        self.helper.header.ncmds += 1
        self.helper.header.sizeofcmds += offset

        return new_segment

    def inject(self, asm, update_entry=False):
        found = [s for s in self.helper.segments if s.segname == INJECTION_SEGMENT_NAME]
        if found:
            injection_vaddr = found[0].vmaddr
        else:
            inject_seg = self._prepare_for_injection()
            injection_vaddr = inject_seg.vmaddr


        if update_entry:
            for command in self.helper.commands:
                if isinstance(command, MachOMainCommand):
                    command.entryoff = injection_vaddr


        self.binary = StringIO()
        self.helper.header.write(self.binary)
        for segment in self.helper.segments:
            if segment.segname == INJECTION_SEGMENT_NAME:
                segment.filesize += len(asm)
                if segment.filesize + len(asm) > segment.vmsize:
                    segment.vmsize += 0x1000
                for section in segment.sections:
                    if section.sectname == INJECTION_SECTION_NAME:
                        section.size += len(asm)
                        section.data += asm

                        self.next_injection_vaddr = section.addr + section.size
                        break

            segment.write(self.binary)
        for command in self.helper.commands:
            command.write(self.binary)

        return injection_vaddr

    def replace_instruction(self, old_ins, new_asm):
        if len(new_asm) > old_ins.size:
            # TODO: make this automatically call inject so that any instruction can be replaced
            raise ValueError('Length of new assembly must be <= size of old instruction')

        self.binary.seek(self.vaddr_binary_offset(old_ins.address))
        self.binary.write(new_asm)

        # TODO: Update function instruction lists
        # TODO: Add function in analyzer to return a NOP so this can be used on all archs
        self.binary.write('\x90' * (old_ins.size - len(new_asm)))