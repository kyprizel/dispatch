from capstone import *
import capstone.arm_const
import capstone.arm64_const

from enums import *
from base_analyzer import BaseAnalyzer

class ARM_Analyzer(BaseAnalyzer):
    def _create_disassembler(self):
        self._disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self._disassembler.detail = True
        

class ARM_64_Analyzer(BaseAnalyzer):
    def _create_disassembler(self):
        self._disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self._disassembler.detail = True