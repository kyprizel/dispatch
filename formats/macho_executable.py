import logging
import struct
import pymacho
from pymacho.MachO import MachO

from base_executable import *
from section import *

class MachOExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(MachOExecutable, self).__init__(file_path)
        
        self.helper = MachO(self.fp)
        
        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        self.executable_segment = [s for s in self.helper.segments if s.initprot & 0x4][0]
    
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

    def iter_sections(self):
        for segment in self.helper.segments:
            for section in segment.sections:
                yield section_from_macho_section(section, segment)

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
                        f = Function(symbol.n_value, 0, symbol_name, self)
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
                            f = Function(addr, stride, symbol_name, self, type=Function.DYNAMIC_FUNC)
                            self.functions[addr] = f

    def iter_string_sections(self):
        STRING_SECTIONS = ['__const', '__cstring', '__objc_methname', '__objc_classname']
        for s in self.iter_sections():
            if s.name in STRING_SECTIONS:
                yield s

    def inject(self, asm, update_entry=False):
        raise NotImplementedError()

    def replace_instruction(self, old_ins, new_asm):
        raise NotImplementedError()