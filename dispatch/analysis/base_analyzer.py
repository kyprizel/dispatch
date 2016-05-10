import logging
import re
import string
from ..util.trie import Trie

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

        self.ins_map = Trie()
    
    def __repr__(self):
        return '<{} for {} {} \'{}\'>'.format(self.__class__.__name__,
                                              self.executable.architecture,
                                              self.executable.__class__.__name__,
                                              self.executable.fp)

    def _gen_ins_map(self):
        '''
        Generates the instruction lookup dictionary
        :return: None
        '''
        raise NotImplementedError()

    def disassemble_range(self, start_vaddr, end_vaddr):
        '''
        Return an array of instructions disassembled between start and end
        :param start_vaddr: The virtual address to start disassembly at
        :param end_vaddr: The last virtual address to disassemble
        :return: Array of disassembled instructions
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
        for f in self.executable.iter_functions():
            # some formats (such as macho) have special functions
            # that don't actually exist in the binary, so we ignore them
            if f.address in self.ins_map:
                f.instructions = self.ins_map[f.address : f.address+f.size]
            else:
                f.instructions = []

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


    def _mark_xrefs(self):
        '''
        Identify all the xrefs from the executable and store them in the xrefs dict (addr -> set of referencing addrs)
        :return: None
        '''
        for ins in self.ins_map:
            for operand in ins.operands:
                if operand is not None and operand.type == Operand.IMM and self.executable.vaddr_binary_offset(operand.imm) is not None:
                    if operand.imm in self.executable.xrefs:
                        self.executable.xrefs[operand.imm].add(ins.address)
                    else:
                        self.executable.xrefs[operand.imm] = set([ins.address])

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
        for func in self.executable.iter_functions():
            func.do_bb_analysis()
        logging.info('Marking XRefs')
        self._mark_xrefs()

        logging.info('Identifying strings')
        self._identify_strings()

    def cfg(self):
        '''
        Creates a control flow graph for the binary
        :return: List of CFGEdges that describe the edges of the graph.
        '''
        raise NotImplementedError()
