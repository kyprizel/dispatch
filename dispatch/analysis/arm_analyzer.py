import capstone
from capstone import *
from capstone.arm_const import *
from Queue import Queue
import struct

from ..constructs import *
from .base_analyzer import BaseAnalyzer

class ARM_Analyzer(BaseAnalyzer):
    def __init__(self, executable):
        super(ARM_Analyzer, self).__init__(executable)

        if self.executable.entry_point() & 0x1:
            self._disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        else:
            self._disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        self._disassembler.detail = True
        self._disassembler.skipdata = True

        self.REG_NAMES = dict([(v,k[8:].lower()) for k,v in capstone.arm_const.__dict__.iteritems() if k.startswith('ARM_REG')])
        self.IP_REGS = set([11])
        self.SP_REGS = set([12])

    def _gen_ins_map(self):
        # Again, since ARM binaries can have code using both instruction sets, we basically have to make a CFG and
        # disassemble each BB as we find them.

        # vaddr -> disassembly type
        bb_disasm_mode = {}

        # If we find a constants table (used for pc-relative ld's), mark it as a known end because it always comes after
        # the end of a BB/function
        known_ends = set()

        entry = self.executable.entry_point()

        if entry & 0x1:
            initial_mode = CS_MODE_THUMB
        else:
            initial_mode = CS_MODE_ARM

        entry &= ~0b1

        to_analyze = Queue()
        to_analyze.put((entry, initial_mode, ))

        bb_disasm_mode[entry] = initial_mode

        # TODO: make this much cleaner, not use raw mnemonic checks, etc
        while not to_analyze.empty():
            start_vaddr, mode = to_analyze.get()

            self._disassembler.mode = mode

            logging.debug('Analyzing code at address {} in {} mode'
                          .format(hex(start_vaddr), 'thumb' if mode == CS_MODE_THUMB else 'arm'))

            # Stop at either the next BB listed or the end of the section
            cur_section = self.executable.section_containing_vaddr(start_vaddr)
            section_end_vaddr = cur_section.vaddr + cur_section.size
            end_vaddr = min([a for a in bb_disasm_mode if a > start_vaddr] or [section_end_vaddr])

            # Force the low bit 0
            start_vaddr &= ~0b1

            code = self.executable.get_binary_vaddr_range(start_vaddr, end_vaddr)

            for ins in self._disassembler.disasm(code, start_vaddr):
                if ins.id == 0:  # We hit a data byte, so we must have gotten to the end of this bb/function
                    break
                elif ins.address in known_ends:  # At a constants table, so we know we're at the end of a bb/function
                    break

                # TODO: epilogue detection

                # Branch immediate
                elif 'b' in ins.mnemonic and ins.operands[-1].type == CS_OP_IMM:
                    jump_dst = ins.operands[-1].imm

                    if self.executable.vaddr_is_executable(jump_dst) and jump_dst not in bb_disasm_mode:
                        if 'x' in ins.mnemonic:
                            next_mode = CS_MODE_THUMB if jump_dst & 0x1 else CS_MODE_ARM
                        else:
                            next_mode = mode

                        jump_dst &= ~0b1

                        logging.debug('Found branch to address {} in instruction at {}'
                                      .format(hex(int(jump_dst)), hex(int(ins.address))))
                        bb_disasm_mode[jump_dst] = next_mode
                        to_analyze.put((jump_dst, next_mode, ))

                # load/move function address as in the case of libc_start_main
                elif ins.mnemonic.startswith('ld') or ins.mnemonic.startswith('mov'):
                    # load/move immediate
                    if ins.operands[-1].type == CS_OP_IMM and self.executable.vaddr_is_executable(ins.operands[-1].imm):
                        referenced_addr = ins.operands[-1].imm
                        if referenced_addr not in bb_disasm_mode:
                            logging.debug('Found reference to address {} in instruction at {}'
                                          .format(hex(int(jump_dst)), hex(int(ins.address))))

                            next_mode = CS_MODE_THUMB if referenced_addr & 0x1 else CS_MODE_ARM
                            referenced_addr &= ~0b1
                            bb_disasm_mode[referenced_addr] = next_mode
                            to_analyze.put((referenced_addr, next_mode, ))

                    # load/move PC-relative entry
                    elif ins.operands[-1].type == CS_OP_MEM and ins.operands[-1].mem.base == ARM_REG_PC:
                        '''
                        ARM THUMB Instruction Set sec. 5.6.1:

                        Note: The value specified by #Imm is a full 10-bit address, but must always be word-aligned
                        (ie with bits 1:0 set to 0), since the assembler places #Imm >> 2 in field Word8.

                        Note: The value of the PC will be 4 bytes greater than the address of this instruction, but bit
                        1 of the PC is forced to 0 to ensure it is word aligned.
                        '''
                        ptr = (ins.address + 4 + ins.operands[-1].mem.disp) & (~0b11)

                        known_ends.add(ptr)

                        referenced_bytes = self.executable.get_binary_vaddr_range(ptr, ptr + self.executable.address_length())
                        referenced_addr = struct.unpack(self.executable.pack_endianness + self.executable.address_pack_type,
                                                        referenced_bytes)[0]

                        if self.executable.vaddr_is_executable(referenced_addr):
                            logging.debug('Found reference to address {} through const table at {} in instruction at {}'
                                              .format(hex(int(referenced_addr)), hex(int(ptr)), hex(int(ins.address))))

                            if referenced_addr not in bb_disasm_mode:
                                next_mode = CS_MODE_THUMB if referenced_addr & 0x1 else CS_MODE_ARM
                                referenced_addr &= ~0b1
                                bb_disasm_mode[referenced_addr] = next_mode
                                to_analyze.put((referenced_addr, next_mode, ))

        bb_vaddrs = sorted(bb_disasm_mode.keys())

        for bb_start, bb_end in zip(bb_vaddrs[:-1], bb_vaddrs[1:]):
            code = self.executable.get_binary_vaddr_range(bb_start, bb_end)

            self._disassembler.mode = bb_disasm_mode[bb_start]

            for ins in self._disassembler.disasm(code, bb_start):
                if ins.id: # .byte "instructions" have an id of 0
                    self.ins_map[ins.address] = instruction_from_cs_insn(ins, self.executable)
        

class ARM_64_Analyzer(ARM_Analyzer):
    def __init__(self, executable):
        super(ARM_64_Analyzer, self).__init__(executable)

        if self.executable.entry_point() & 0x1:
            self._disassembler = Cs(CS_ARCH_ARM64, CS_MODE_THUMB)
        else:
            self._disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        self._disassembler.detail = True
        self._disassembler.skipdata = True

        self.REGISTER_NAMES = dict([(v,k[10:].lower()) for k,v in capstone.arm64_const.__dict__.iteritems() if k.startswith('ARM64_REG')])
        self.IP_REGS = set()
        self.SP_REGS = set([4, 5])
