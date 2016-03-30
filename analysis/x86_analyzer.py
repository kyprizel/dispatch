from capstone import *
from capstone.x86_const import *
import struct

from constructs import *
from base_analyzer import BaseAnalyzer

class X86_Analyzer(BaseAnalyzer):
    def __init__(self, executable):
        super(X86_Analyzer, self).__init__(executable)

        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self._disassembler.detail = True
        self._disassembler.skipdata = True

        self.REG_NAMES = dict([(v,k[8:].lower()) for k,v in capstone.x86_const.__dict__.iteritems() if k.startswith('X86_REG')])
        self.IP_REGS = [26, 34, 41]
        self.SP_REGS = [30, 44, 47]

    def _gen_ins_map(self):
        for section in self.executable.sections_to_disassemble():
            for ins in self._disassembler.disasm(section.raw, section.vaddr):
                if ins.id: # .byte "instructions" have an id of 0
                    self.ins_map[ins.address] = instruction_from_cs_insn(ins, self.executable)

    def ins_modifies_esp(self, instruction):
        return 'pop' in instruction.mnemonic or 'push' in instruction.mnemonic \
                or instruction.operands[0] in self.SP_REGS

    def _identify_functions(self):
        STATE_NOT_IN_FUNC, STATE_IN_PROLOGUE, STATE_IN_FUNCTION = 0,1,2

        state = STATE_NOT_IN_FUNC

        ops = []

        for addr in self.ins_map:
            cur_ins = self.ins_map[addr]

            # Windows sometimes puts `mov edi, edi` as the first instruction in a function for hot patching, so we check
            # for this case to make sure the function we detect starts at the correct address.
            #  https://blogs.msdn.microsoft.com/oldnewthing/20110921-00/?p=9583
            if state == STATE_NOT_IN_FUNC and cur_ins.mnemonic == 'mov' and \
                    cur_ins.operands[0].type == Operand.REG and \
                    cur_ins.operands[0].reg == X86_REG_EDI and \
                    cur_ins.operands[1].type == Operand.REG and \
                    cur_ins.operands[1].reg == X86_REG_EDI:

                state = STATE_IN_PROLOGUE
                ops.append(cur_ins)

            elif state in (STATE_NOT_IN_FUNC, STATE_IN_PROLOGUE) and cur_ins.mnemonic == 'push' and \
                    cur_ins.operands[0].type == Operand.REG and \
                    cur_ins.operands[0].reg in (X86_REG_EBP, X86_REG_RBP):

                state = STATE_IN_PROLOGUE
                ops.append(cur_ins)

            elif state == STATE_IN_PROLOGUE and \
                            cur_ins.mnemonic == 'mov' and \
                            cur_ins.operands[0].type == Operand.REG and \
                            cur_ins.operands[0].reg in (X86_REG_EBP, X86_REG_RBP) and \
                            cur_ins.operands[1].type == Operand.REG and \
                            cur_ins.operands[1].reg in self.SP_REGS:

                state = STATE_IN_FUNCTION
                ops.append(cur_ins)

            elif state == STATE_IN_FUNCTION and cur_ins.mnemonic.startswith('ret'):
                state = STATE_NOT_IN_FUNC
                ops.append(cur_ins)

                if ops[0].address not in self.executable.functions:
                    f = Function(ops[0].address,
                                 ops[-1].address + ops[-1].size - ops[0].address,
                                 'sub_'+hex(ops[0].address)[2:],
                                 self.executable)
                    self.executable.functions[f.address] = f

                ops = []

            elif state == STATE_IN_FUNCTION:
                ops.append(cur_ins)


    def cfg(self):
        edges = set()

        for f in self.executable.iter_functions():
            if f.type == Function.NORMAL_FUNC:
                for ins in f.instructions:
                    #TODO: understand non-immediates here
                    if ins.is_call() and ins.operands[-1].type == Operand.IMM:
                        call_addr = ins.operands[-1].imm
                        if self.executable.vaddr_is_executable(call_addr):
                            edge = CFGEdge(ins.address, call_addr, CFGEdge.DEFAULT)
                            edges.add(edge)

                for cur_bb in f.bbs:
                    last_ins = cur_bb.instructions[-1]

                    if last_ins.is_jump():
                        if last_ins.operands[-1].type == Operand.IMM:
                            jmp_addr = last_ins.operands[-1].imm

                            if self.executable.vaddr_is_executable(jmp_addr):
                                if last_ins.mnemonic == 'jmp':
                                    edge = CFGEdge(last_ins.address, jmp_addr, CFGEdge.DEFAULT)
                                    edges.add(edge)
                                else:  # Conditional jump
                                    # True case
                                    edge = CFGEdge(last_ins.address, jmp_addr, CFGEdge.COND_JUMP, True)
                                    edges.add(edge)

                                    # Default/fall-through case
                                    next_addr = last_ins.address + last_ins.size
                                    edge = CFGEdge(last_ins.address, next_addr, CFGEdge.COND_JUMP, False)
                                    edges.add(edge)
                    elif last_ins != f.instructions[-1]:
                        # Otherwise, if we're just at the end of a BB that's not the end of the function, just fall
                        # through to the next of the instruction
                        edge = CFGEdge(last_ins.address, last_ins.address + last_ins.size, CFGEdge.DEFAULT)
                        edges.add(edge)


                # Jump table detection.
                # Looking for:
                #  cmp {something}, {num_cases}
                #  cond_jmp {default_case}
                #  mov {reg}, {some_var}
                #  mov {reg2}, [disp+{reg}*addr_size]
                #  jmp {reg2}

                ins_sets = [f.instructions[i:i + 5] for i in range(len(f.instructions) - 4)]
                for instructions in ins_sets:
                    if instructions[0].mnemonic == 'cmp' and \
                        instructions[1].is_jump() and instructions[1].mnemonic != 'jmp' and \
                        instructions[3].mnemonic == 'mov' and\
                            instructions[3].operands[0].type == Operand.REG and \
                            instructions[3].operands[1].type == Operand.MEM and \
                        instructions[4].mnemonic == 'jmp' and \
                            instructions[4].operands[0].type == Operand.REG and \
                            instructions[4].operands[0].reg ==  instructions[3].operands[0].reg:

                        num_cases = instructions[0].operands[1].imm
                        addr_size = instructions[3].operands[1].scale
                        jmp_table_offset = instructions[3].operands[1].disp

                        self.executable.binary.seek(self.executable.vaddr_binary_offset(jmp_table_offset))
                        table = self.executable.binary.read(num_cases*addr_size)

                        entries = struct.unpack(self.executable.pack_endianness + (self.executable.address_pack_type*num_cases), table)

                        for idx, addr in enumerate(entries):
                            edge = CFGEdge(instructions[4].address, addr, CFGEdge.SWITCH, idx)
                            edges.add(edge)


        return edges

class X86_64_Analyzer(X86_Analyzer):
    def __init__(self, executable):
        super(X86_64_Analyzer, self).__init__(executable)

        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self._disassembler.detail = True
        self._disassembler.skipdata = True
