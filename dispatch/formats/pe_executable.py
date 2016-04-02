import pefile
from .SectionDoubleP import SectionDoubleP

from .base_executable import *
from .section import *

class PEExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(PEExecutable, self).__init__(file_path)

        self.helper = pefile.PE(self.fp)

        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

        self.pack_endianness = '<'

        self.sections = [section_from_pe_section(s, self.helper) for s in self.helper.sections]
    
    def _identify_arch(self):
        machine = pefile.MACHINE_TYPE[self.helper.FILE_HEADER.Machine]
        if machine == 'IMAGE_FILE_MACHINE_I386':
            return ARCHITECTURE.X86
        elif machine == 'IMAGE_FILE_MACHINE_AMD64':
            return ARCHITECTURE.X86_64
        elif machine == 'IMAGE_FILE_MACHINE_ARM':
            return ARCHITECTURE.ARM
        elif machine in ('IMAGE_FILE_MACHINE_MIPS16', 'IMAGE_FILE_MACHINE_MIPSFPU', 'IMAGE_FILE_MACHINE_MIPSFPU16'):
            return ARCHITECTURE.MIPS
        else:
            return None

    def get_binary(self):
        return self.helper.write()

    def iter_string_sections(self):
        # TODO
        return []

    def _extract_symbol_table(self):
        # Load in stuff from the IAT
        for dll in self.helper.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                if imp.name:
                    name = imp.name + '@' + dll.dll
                else:
                    name = 'ordinal_' + str(imp.ordinal) + '@' + dll.dll

                self.functions[imp.address] = Function(imp.address,
                                                       self.address_length(),
                                                       name,
                                                       self)

        # Load in information from the EAT if it exists
        if hasattr(self.helper, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.helper.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.address not in self.functions:
                    # TODO: Get size of function through CFG analysis or something similar
                    self.functions[symbol.address] = Function(symbol.address,
                                                              0,
                                                              symbol.name,
                                                              self)
                else:
                    self.functions[symbol.address].name = symbol.name

    def inject(self, asm, update_entry=False):
        SECTION_SIZE = 0x1000

        has_injection_section = [s for s in self.helper.sections if s.Name == '.aio_inj']

        if not has_injection_section:
            sdp = SectionDoubleP(self.helper)
            to_inject = asm + '\x00' * (SECTION_SIZE - len(asm))
            self.helper = sdp.push_back(Name='.aio_inj', Characteristics=0x60000020, Data=to_inject)
            inject_rva = self.helper.sections[-1].VirtualAddress
        else:
            section = has_injection_section[0]
            inject_rva = section.VirtualAddress + len(section.get_data().rstrip('\x00'))
            section.set_bytes_at_rva(inject_rva, asm)

        if update_entry:
            self.helper.OPTIONAL_HEADER.AddressOfEntryPoint = inject_rva

        return inject_rva + self.helper.OPTIONAL_HEADER.ImageBase

    def replace_instruction(self, old_ins, new_asm):
        if len(new_asm) > old_ins.size:
            raise ValueError('Length of new assembly must be <= size of old instruction')

        self.helper.set_bytes_at_rva(old_ins.address - self.helper.OPTIONAL_HEADER.ImageBase,
                                     str(new_asm) + '\x90' * (old_ins.size - len(new_asm)))