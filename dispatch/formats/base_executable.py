import os
import logging
from StringIO import StringIO

from ..analysis.x86_analyzer import *
from ..analysis.arm_analyzer import *

from ..enums import *

class BaseExecutable(object):
    '''
    The executable classes expose the raw binary in higher-level chunks.
    They automatically lift the .text segment (or equiv.) for quick use, keep a map of offset->vaddrs for lookups in
    the rewriting process, and more. You can think of them as the middle-man that sits between the disassembly and the
    underlying binary.
    '''
    def __init__(self, file_path):
        if not os.path.exists(file_path):
            raise Exception('No such file')

        self.fp = file_path
        self.binary = StringIO(open(self.fp).read())

        self.architecture = None
        self.pack_endianness = None

        self.helper = None

        self.analyzer = None
        self.libraries = []
        self.functions = {} # Vaddr: Function
        self.strings = {}
        self.xrefs = {}

    def __repr__(self):
        return '<{} {} \'{}\'>'.format(self.architecture, self.__class__.__name__, self.fp)
    
    def _identify_arch(self):
        '''
        Identifies the architecture that the executable is compiled for.
        :return: None
        '''
        raise NotImplementedError()
    
    def is_64_bit(self):
        '''
        Determines if the executable is 64 bit or 32 bit.
        :return: True if the executable is 64 bit, otherwise false.
        '''
        return self.architecture in (ARCHITECTURE.X86_64, ARCHITECTURE.ARM_64)

    def address_length(self):
        '''
        :return: Number of bytes an address in this executable will have (i.e. 4 for 32 bit, 8 for 64 bit)
        '''
        return 8 if self.is_64_bit() else 4

    def entry_point(self):
        '''
        Gets the entry point of the executable.
        :return: The entry point of the executable.
        '''
        raise NotImplementedError()

    def sections_to_disassemble(self):
        '''
        Iterates through each section in the executable that is supposed to be disassembled.
        :return: Iterator
        '''
        for s in self.sections:
            if s.executable:
                yield s

    def iter_string_sections(self):
        '''
        Returns the section(s) with strings in this executable
        :return: Section(s) with strings.
        '''
        raise NotImplementedError()

    def vaddr_is_executable(self, vaddr):
        '''
        Determine if the given virtual address is in a mapped executable memory segment.
        :param vaddr: Virtual address to check
        :return: True if the vaddr is in an executable segment, False otherwise
        '''
        for section in self.sections:
            if section.executable and section.contains_vaddr(vaddr):
                return True

        return False

    def section_containing_vaddr(self, vaddr):
        for section in self.sections:
            if section.contains_vaddr(vaddr):
                return section

        return None

    def function_containing_vaddr(self, vaddr):
        for f in self.iter_functions():
            if f.contains_address(vaddr):
                return f

        return None

    def bb_containing_vaddr(self, vaddr):
        for f in self.iter_functions():
            for bb in f.bbs:
                if bb.address <= vaddr < bb.address + bb.size:
                    return bb

        return None

    def vaddr_binary_offset(self, vaddr):
        '''
        Gets the offset in the binary file for a given virtual address.
        :param vaddr: The virtual address to get the offset for.
        :return: The offset in the binary of the virtual address.
        '''
        for section in self.sections:
            if section.contains_vaddr(vaddr):
                return section.offset + vaddr - section.vaddr

        return None

    def _extract_symbol_table(self):
        '''
        Extracts the symbol table from the binary and creates named functions as appropriate.
        Called from the analyzer in the main analysis function.
        :return: None
        '''
        raise NotImplementedError()

    def get_binary(self):
        '''
        Gets the entire binary.
        :return: The raw bytes of the entire binary.
        '''
        return self.binary.getvalue()

    def get_binary_vaddr_range(self, start, end):
        '''
        Gets the raw bytes from the binary within a virtual address range
        :param start: Starting virtual address
        :param end: Ending virtual address
        :raises: KeyError if either the start or end virtual addresses do not actually exist in the binary
        :return: The bytes in the binary between the two virtual addresses
        '''
        start_offset = self.vaddr_binary_offset(start)
        end_offset = self.vaddr_binary_offset(end)
        # if either of these returns None we don't want to slice up -- raise an error
        if start_offset and end_offset:
            return self.get_binary()[start_offset:end_offset]

        bad_addr = start if not start_offset else end # which address triggered our error
        raise KeyError("Vaddr is not in binary: {:x}".format(bad_addr))
    
    def analyze(self):
        '''
        Creates an analyzer for the binary and then runs the initial analysis routine.
        :return: The created analyzer object.
        '''
        if self.architecture == ARCHITECTURE.X86:
            self.analyzer = X86_Analyzer(self)
        elif self.architecture == ARCHITECTURE.X86_64:
            self.analyzer = X86_64_Analyzer(self)
        elif self.architecture == ARCHITECTURE.ARM:
            self.analyzer = ARM_Analyzer(self)
        elif self.architecture == ARCHITECTURE.ARM_64:
            self.analyzer = ARM_64_Analyzer(self)

        if self.analyzer:
            self.analyzer.analyze()
        else:
            logging.error('Could not create analyzer for {}'.format(self))

        return self.analyzer

    def prepare_for_injection(self):
        '''
        Prepares the binary for code injection, creating sections/segments where needed.
        This should *always* be called before inject() is called, as it provides the initial values for
        next_injection_vaddr which may be required to do certain IP-relative computations.
        :return: None
        '''
        raise NotImplementedError()

    def inject(self, asm, update_entry=False):
        '''
        Injects the given assembly into the binary, optionally updating the entry point if the injected code is to run
        before initialization.
        :param asm: The assembly to inject.
        :param update_entry: Whether or not to update the binary entry point to point to the injected code.
        :return: (offset of injected assembly in binary, virtual address of injected assembly)
        '''
        raise NotImplementedError()

    def iter_functions(self):
        '''
        Iterates over the functions in this executable
        :return: Iterator
        '''
        return iter(self.functions.values())

    def function_named(self, name):
        '''
        Finds a function with a given name if it exists.
        :param name: The name of the function to search for.
        :return: The function if it is found, else None.
        '''
        for func in self.iter_functions():
            if func.name == name or func.name == 'sub_'+name or func.name == name+'@PLT':
                return func

        return None

    def replace_instruction(self, old_ins, new_asm):
        '''
        Replaces an instruction with the given assembly.
        :param old_ins: The existing instruction to overwrite.
        :param new_asm: The new assembly that will be written over the old instruction.
        :return: None
        '''
        raise NotImplementedError()

    def save(self, file_name):
        with open(file_name, 'wb') as f:
            f.write(self.get_binary())
