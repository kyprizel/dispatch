from capstone import *

from base_analyzer import BaseAnalyzer

class MIPS_Analyzer(BaseAnalyzer):
    def _create_disassembler(self):
        self._disassembler = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 if self.executable.is_64_bit() else CS_MODE_MIPS32)
        self._disassembler.detail = True
        