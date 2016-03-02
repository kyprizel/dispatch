import pefile

from base_executable import *

class PEExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(PEExecutable, self).__init__(file_path)
        
        self.helper = pefile.PE(self.fp, fast_load=True)
        
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

    def _get_text_section(self):
        return [x for x in self.helper.sections if '.text' in x.Name][0]

    def text_vaddr(self):
        return self.helper.OPTIONAL_HEADER.ImageBase + self._get_text_section().VirtualAddress

    def text_size(self):
        return self._get_text_section().SizeOfRawData

    def text_section(self):
        return self._get_text_section().get_data()

    def vaddr_binary_offset(self, vaddr):
        vaddr -= self.helper.OPTIONAL_HEADER.ImageBase

        for section in self.helper.sections:
            if section.VirtualAddress <= vaddr <= section.VirtualAddress+section.SizeOfRawData:
                return self.helper.OPTIONAL_HEADER.ImageBase + section.get_file_offset + \
                       (vaddr - section.VirtualAddress)

    def inject(self, asm, update_entry=False):
        raise NotImplementedError()

    def replace_instruction(self, old_ins, new_asm):
        raise NotImplementedError()