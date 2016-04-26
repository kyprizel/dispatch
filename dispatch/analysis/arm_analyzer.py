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
        self.NOP_INSTRUCTION = '\x00\x00\x00\x00'

    def _gen_ins_map(self):
        # Again, since ARM binaries can have code using both instruction sets, we basically have to make a CFG and
        # disassemble each BB as we find them.

        # vaddr -> disassembly type
        bb_disasm_mode = {}

        # If we find a constants table (used for pc-relative ld's), mark it as a known end because it always comes after
        # the end of a BB/function
        known_ends = set()

        entry = self.executable.entry_point()

        if entry & 0b1:
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

                our_ins = instruction_from_cs_insn(ins, self.executable)
                self.ins_map[ins.address] = our_ins

                if self._insn_is_epilogue(our_ins):
                    break

                # Branch immediate
                if ins.mnemonic.startswith('b') and ins.operands[-1].type == CS_OP_IMM:
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
                            logging.debug('Found reference to executable address {} in instruction at {}'
                                          .format(hex(int(referenced_addr)), hex(int(ins.address))))

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

        self._disasm_mode = bb_disasm_mode

    def disassemble_range(self, start_vaddr, end_vaddr):
        if start_vaddr & 0x1:
            self._disassembler.mode = CS_MODE_THUMB
        else:
            self._disassembler.mode = CS_MODE_ARM

        start_vaddr &= ~0b1

        size = end_vaddr - start_vaddr
        self.executable.binary.seek(self.executable.vaddr_binary_offset(start_vaddr))

        instructions = []

        for ins in self._disassembler.disasm(self.executable.binary.read(size), start_vaddr):
            if ins.id:
                instructions.append(instruction_from_cs_insn(ins, self.executable))

        return instructions

    def _insn_is_epilogue(self, ins):
        """
        Determines whether the instruction is a typical function epilogue
        :param ins: Instruction to test
        :return: True if the instruction is an epilogue
        """

        # b** {..., lr}
        if ins.mnemonic.startswith('b') and ins.operands[0].type == Operand.REG and \
            ins.operands[0].reg == ARM_REG_LR:
            return True

        # pop {..., pc}
        elif ins.mnemonic == 'pop' and \
            any(o.reg == ARM_REG_PC for o in ins.operands if o.type == Operand.REG):
            return True

        return False

    def _identify_functions(self):
        STATE_NOT_IN_FUNC, STATE_IN_FUNCTION = 0, 1

        state = STATE_NOT_IN_FUNC

        cur_func = None

        for cur_ins in self.ins_map:
            if cur_ins.address in self.executable.functions:
                state = STATE_IN_FUNCTION
                cur_func = self.executable.functions[cur_ins.address]

                logging.debug('Analyzing function {} with pre-populated size {}'.format(cur_func, cur_func.size))

                if not cur_func.size:
                    # Function from symtab has no size, so start to keep track of it
                    cur_func.size += cur_ins.size

            elif cur_func and cur_func.contains_address(cur_ins.address):
                # ARM sometimes stores pointers to various things after the function body, but this data is included in
                # ELF's (and maybe others) symbol size, so we have to actively look for the actual end of the function.

                if self._insn_is_epilogue(cur_ins):
                    state = STATE_NOT_IN_FUNC
                    logging.debug('Identified function epilogue at {}'.format(hex(cur_ins.address)))
                    cur_func.size -= (cur_func.address + cur_func.size) - (cur_ins.address + cur_ins.size)
                    cur_func = None

            elif state == STATE_NOT_IN_FUNC and cur_ins.mnemonic == 'push' and \
                    any(o.reg == ARM_REG_LR for o in cur_ins.operands if o.type == Operand.REG):

                state = STATE_IN_FUNCTION
                logging.debug(
                    'Identified function by prologue at {} with prologue instruction {}'.format(hex(cur_ins.address),
                                                                                                cur_ins))

                cur_func = Function(cur_ins.address,
                                    cur_ins.size,
                                    'sub_' + hex(cur_ins.address)[2:],
                                    self.executable)

            elif state == STATE_IN_FUNCTION and self._insn_is_epilogue(cur_ins):
                state = STATE_NOT_IN_FUNC
                cur_func.size += cur_ins.size

                logging.debug('Identified function epilogue at {}'.format(hex(cur_ins.address)))

                self.executable.functions[cur_func.address] = cur_func

                cur_func = None

            elif state == STATE_IN_FUNCTION:
                cur_func.size += cur_ins.size

    def cfg(self):
        pass


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
        self.NOP_INSTRUCTION = '\x1F\x20\x03\xD5'
