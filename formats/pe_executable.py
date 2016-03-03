import pefile

from base_executable import *
from section import *

class PEExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(PEExecutable, self).__init__(file_path)
        
        self.helper = pefile.PE(self.fp)
        
        self.architecture = self._identify_arch()

        if self.architecture is None:
            raise Exception('Architecture is not recognized')
    
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

    def iter_sections(self):
        for pe_section in self.helper.sections:
            yield section_from_pe_section(pe_section, self.helper)

    def _extract_symbol_table(self):
        # Load in stuff from the IAT
        for dll in self.helper.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                if imp.name:
                    name = imp.name + '@' + dll.dll
                else:
                    name = 'ordinal_' + str(imp.ordinal) + '@' + dll.dll

                self.functions[imp.address] = Function(imp.address, 8 if self.is_64_bit() else 4, name)

        # Load in information from the EAT if it exists
        if hasattr(self.helper, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.helper.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.address not in self.functions:
                    # TODO: Get size of function through CFG analysis or something similar
                    self.functions[symbol.address] = Function(symbol.address, 0, symbol.name)
                else:
                    self.functions[symbol.address].name = symbol.name

    def inject(self, asm, update_entry=False):
        raise NotImplementedError()

    def replace_instruction(self, old_ins, new_asm):
        raise NotImplementedError()