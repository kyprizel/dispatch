import logging
import re
import string
from collections import OrderedDict

from ..constructs import *

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
        raise NotImplementedError()

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
        insn_addrs = sorted(self.ins_map.keys())

        for f in self.executable.iter_functions():
            try:
                i = insn_addrs.index(f.address)

                while i < len(insn_addrs) and insn_addrs[i] < f.address + f.size:
                    f.instructions.append(self.ins_map[insn_addrs[i]])
                    i += 1
            except ValueError:
                logging.debug('Function {} starts at code outside any executable section.'.format(f))

    def _identify_strings(self):
        '''
        Extracts all strings from the executable and stores them in the strings dict (addr -> string)
        :return: None
        '''
        # https://stackoverflow.com/questions/6804582/extract-strings-from-a-binary-file-in-python
        chars = string.printable
        shortest_run = 2
        regexp = '[%s]{%d,}' % (chars, shortest_run)
        pattern = re.compile(regexp)

        for section in self.executable.iter_string_sections():
            for found_string in pattern.finditer(section.raw):
                vaddr = section.vaddr + found_string.start()
                self.executable.strings[vaddr] = String(found_string.group(), vaddr, self.executable)

    def _identify_bbs(self):
        '''
        Extracts all basic blocks from the executable and stores them in the associated function's bbs list
        :return: None
        '''
        for func in self.executable.iter_functions():
            if func.instructions:
                bb_ends = set([func.instructions[-1].address + func.instructions[-1].size])

                for i in range(len(func.instructions) - 1):
                    cur = func.instructions[i]
                    next = func.instructions[i+1]

                    if cur.is_jump() and cur.operands[0].type == Operand.IMM:
                        bb_ends.add(cur.operands[0].imm)
                        bb_ends.add(next.address)

                bb_ends = sorted(list(bb_ends))
                bb_instructions = []

                for ins in func.instructions:
                    if ins.address == bb_ends[0] and bb_instructions:
                        bb = BasicBlock(func,
                                        bb_instructions[0].address,
                                        bb_instructions[-1].address + bb_instructions[-1].size - bb_instructions[0].address)
                        bb.instructions = bb_instructions
                        func.bbs.append(bb)

                        bb_ends = bb_ends[1:]
                        bb_instructions = [ins]
                    else:
                        bb_instructions.append(ins)

                # There will always be one BB left over which "ends" at the first address of the next function, so be
                # sure to add it

                bb = BasicBlock(func,
                                bb_instructions[0].address,
                                bb_instructions[-1].address + bb_instructions[-1].size - bb_instructions[0].address)
                bb.instructions = bb_instructions
                func.bbs.append(bb)


    def _mark_xrefs(self):
        for addr, ins in self.ins_map.iteritems():
            for operand in ins.operands:
                if operand.type == Operand.IMM and self.executable.vaddr_binary_offset(operand.imm) is not None:
                    if operand.imm in self.executable.xrefs:
                        self.executable.xrefs[operand.imm].add(addr)
                    else:
                        self.executable.xrefs[operand.imm] = set([addr])

    def analyze(self):
        '''
        Run the analysis subroutines.
        Generates the instruction map, extracts symbol tables, identifies functions/BBs, and "prettifies" instruction op_str's
        :return: None
        '''
        logging.info('Generating instruction map')
        self._gen_ins_map()

        logging.info('Extracting symbol table')
        self.executable._extract_symbol_table()

        logging.info('Identifying functions')
        self._identify_functions()

        # TODO: CFA

        logging.info('Populating function instructions')
        self._populate_func_instructions()
        logging.info('Identifying basic blocks')
        self._identify_bbs()
        logging.info('Marking XRefs')
        self._mark_xrefs()

        logging.info('Identifying strings')
        self._identify_strings()

    def cfg(self):
        '''
        Creates a control flow graph for the binary
        :return: List of tuples that describe the edges of the graph.
        '''
        raise NotImplementedError()
