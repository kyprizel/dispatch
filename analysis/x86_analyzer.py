from capstone.x86_const import *
import struct

from constructs import *
from base_analyzer import BaseAnalyzer

class X86_Analyzer(BaseAnalyzer):
    def _create_disassembler(self):
        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

    def ins_uses_address_register(self, instruction):
        return 'ip' in instruction.op_str or 'sp' in instruction.op_str

    def _identify_functions(self):
        STATE_NOT_IN_FUNC, STATE_IN_PROLOGUE, STATE_IN_FUNCTION = 0,1,2

        state = STATE_NOT_IN_FUNC

        ops = []

        for addr in self.ins_map:
            cur_ins = self.ins_map[addr]

            if state == STATE_NOT_IN_FUNC and cur_ins.mnemonic == 'push' and cur_ins.capstone_inst.operands[0].type == CS_OP_REG and \
                cur_ins.capstone_inst.operands[0].reg in (X86_REG_EBP, X86_REG_RBP):

                state = STATE_IN_PROLOGUE
                ops.append(cur_ins)

            elif state == STATE_IN_PROLOGUE and \
                            cur_ins.mnemonic == 'mov' and \
                            cur_ins.capstone_inst.operands[0].type == CS_OP_REG and \
                            cur_ins.capstone_inst.operands[0].reg in (X86_REG_EBP, X86_REG_RBP) and \
                            cur_ins.capstone_inst.operands[1].type == CS_OP_REG and \
                            cur_ins.capstone_inst.operands[1].reg in (X86_REG_ESP, X86_REG_RSP):

                state = STATE_IN_FUNCTION
                ops.append(cur_ins)

            elif state == STATE_IN_FUNCTION and cur_ins.mnemonic.startswith('ret'):
                state = STATE_NOT_IN_FUNC
                ops.append(cur_ins)

                if ops[0].address not in self.executable.functions:
                    f = Function(ops[0].address, ops[-1].address + ops[-1].size - ops[0].address, 'sub_'+hex(ops[0].address))
                    self.executable.functions[f.address] = f

                ops = []

            elif state == STATE_IN_FUNCTION:
                ops.append(cur_ins)


    def cfg(self):
        edges = set()

        for f in self.executable.iter_functions():
            if f.type == Function.NORMAL_FUNC:
                for ins in f.instructions:
                    if CS_GRP_CALL in ins.capstone_inst.groups:
                        call_addr = ins.capstone_inst.operands[-1].imm
                        if self.executable.vaddr_is_executable(call_addr):
                            edges.add((ins.address, call_addr))

                for cur_bb in f.bbs:
                    last_ins = cur_bb.instructions[-1]

                    if CS_GRP_JUMP in last_ins.capstone_inst.groups:
                        if last_ins.capstone_inst.operands[-1].type == CS_OP_IMM:
                            jmp_addr = last_ins.capstone_inst.operands[-1].imm
                            if self.executable.vaddr_is_executable(jmp_addr):
                                edges.add((last_ins.address, jmp_addr))
                            if last_ins.mnemonic != 'jmp':
                                # Only add the "fall-through" case if the jump is conditional
                                # TODO: opcode checking instead of mnemonic comparisons
                                edges.add((last_ins.address, last_ins.address + last_ins.size))
                    elif last_ins != f.instructions[-1]:
                        # Otherwise, if we're just at the end of a BB that's not the end of the function, just fall
                        # through to the next of the instruction
                        edges.add((last_ins.address, last_ins.address + last_ins.size))

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
                        CS_GRP_JUMP in instructions[1].groups and instructions[1].mnemonic != 'jmp' and \
                        instructions[3].mnemonic == 'mov' and\
                            instructions[3].capstone_inst.operands[0].type == CS_OP_REG and \
                            instructions[3].capstone_inst.operands[1].type == CS_OP_MEM and \
                        instructions[4].mnemonic == 'jmp' and \
                            instructions[4].capstone_inst.operands[0].type == CS_OP_REG and \
                            instructions[4].capstone_inst.operands[0].reg ==  instructions[3].capstone_inst.operands[0].reg:

                        num_cases = instructions[0].capstone_inst.operands[1].imm
                        addr_size = instructions[3].capstone_inst.operands[1].mem.scale
                        jmp_table_offset = instructions[3].capstone_inst.operands[1].mem.disp

                        self.executable.binary.seek(self.executable.vaddr_binary_offset(jmp_table_offset))
                        table = self.executable.binary.read(num_cases*addr_size)

                        entries = struct.unpack(self.executable.pack_endianness + (self.executable.address_pack_type*num_cases), table)

                        for addr in entries:
                            edges.add((instructions[4].address, addr))


        return edges

class X86_64_Analyzer(X86_Analyzer):
    def _create_disassembler(self):
        self._disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
