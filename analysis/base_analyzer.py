import logging
from capstone import *
from collections import OrderedDict

from constructs import *

class BaseAnalyzer(object):
    '''
    The analyzers are responsible for taking raw instructions from the executable and transforming them
    into higher-level constructs. This includes identifying functions, basic blocks, etc.

    The analyzers also provide some helper methods (ins_*) which are quick ways to determine what an instruction does.
    This can include determining if a instruction is sensitive to location, is a call/jump, etc.
    '''
    def __init__(self, executable):
        self.executable = executable
        
        # Dictionary of vaddr: instruction for quick lookups.
        # We use an OrderedDict so we can just `for addr in ins_map` and not have to worry about sorting
        self.ins_map = OrderedDict()

        self._create_disassembler()
    
    def __repr__(self):
        return '<{} for {} {} \'{}\'>'.format(self.__class__.__name__,
                                              self.executable.architecture,
                                              self.executable.__class__.__name__,
                                              self.executable.fp)

    def _create_disassembler(self):
        '''
        Creates a capstone disassembler instance for this architecture
        :return: None
        '''
        raise NotImplementedError()

    def _gen_ins_map(self):
        '''
        Generates the instruction lookup dictionary
        :return: None
        '''
        for section in self.executable.iter_sections():
            if section.executable:
                for ins in self._disassembler.disasm(section.raw, section.vaddr):
                    self.ins_map[ins.address] = Instruction(ins)
    
    def _is_jump(self, instruction):
        '''
        Determines if the given instruction is a jump
        :param instruction: The instruction to test
        :return: Whether or not the given instruction is a jump
        '''
        return CS_GRP_JUMP in instruction.groups
    
    def _is_call(self, instruction):
        '''
        Determines if the given instruction is a call
        :param instruction: The instruction to test
        :return: Whether or not the given instruction is a call
        '''
        return CS_GRP_CALL in instruction.groups

    def ins_redirects_flow(self, instruction):
        '''
        Determines if the given instruction redirects program flow
        :param instruction: The instruction to test
        :return: Whether or not the given instruction redirects flow
        '''
        return self._is_jump(instruction) or self._is_call(instruction)

    def ins_uses_address_register(self, instruction):
        '''
        Determines if the given instruction uses a register sensitive to location
        E.g. if an x86 instruction uses eip or esp, the instruction is said to be sensitive to location
        :param instruction: The instruction to test
        :return: Whether or not the given instruction references a register sensitive to location
        '''
        return NotImplementedError()

    def ins_is_replacement_candidate(self, instruction):
        '''
        Determines if the given instruction is a candidate for replacement
        :param instruction: The instruction to test
        :return: Whether or not the given instruction could be replaced
        '''
        return not (self.ins_redirects_flow(instruction) or self.ins_uses_address_register(instruction))

    def _identify_functions(self):
        '''
        Iterates through instructions and identifies functions by prologues and epilogues
        :return: None
        '''
        raise NotImplementedError()

    def _populate_func_instructions(self):
        '''
        Iterates through all found functions and add instructions inside that function to the Function object
        :return: None
        '''
        for f in self.executable.iter_functions():
            for addr in self.ins_map:
                if f.contains_address(addr):
                    f.instructions.append(self.ins_map[addr])

    def _identify_bbs(self):
        for func in self.executable.iter_functions():
            if func.instructions:
                bbs = set([func.instructions[0].address, func.instructions[-1].address + func.instructions[-1].size])

                for cur, next in zip(func.instructions[:-1], func.instructions[1:]):
                    if CS_GRP_JUMP in cur.groups and cur.capstone_inst.operands[0].type == CS_OP_IMM:
                        bbs.add(cur.capstone_inst.operands[0].imm)
                        bbs.add(next.address)

                bbs = sorted(list(bbs))

                for start, end in zip(bbs[:-1], bbs[1:]):
                    bb_instructions = []

                    for ins in func.instructions:
                        if start <= ins.address < end:
                            bb_instructions.append(ins)

                    if bb_instructions:
                        bb = BasicBlock(func,
                                        bb_instructions[0].address,
                                        bb_instructions[-1].address + bb_instructions[-1].size - bb_instructions[0].address)
                        bb.instructions = bb_instructions

                        func.bbs.append(bb)

    def _prettify_operands(self):
        for func in self.executable.iter_functions():
            for insn in func.instructions:
                insn.prettify_operands(self)
    
    def analyze(self):
        '''
        Run the analysis subroutines.
        Generates the instruction map and runs radare2 to get functions/BBs
        :return: None
        '''
        self._gen_ins_map()

        self.executable._extract_symbol_table()
        self._identify_functions()
        self._populate_func_instructions()

        self._identify_bbs()

        self._prettify_operands()

    def cfg(self):
        '''
        Creates a control flow graph for the binary
        :return: List of tuples that describe the edges of the graph.
        '''
        raise NotImplementedError()
