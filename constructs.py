from capstone import *

class Function(object):
    NORMAL_FUNC = 0
    DYNAMIC_FUNC = 1

    def __init__(self, address, size, name, executable, type=NORMAL_FUNC):
        self.address = address
        self.size = size
        self.name = name
        self.type = type
        self._executable = executable

        # BELOW: Helpers used to explore the binary.
        # NOTE: These should *not* be directly modified at this time.
        # Instead, executable.replace_instruction should be used.
        self.instructions = [] # Sequential list of instructions
        self.bbs = [] # Sequential list of basic blocks. BB instructions are auto-populated from our instructions
    
    def __repr__(self):
        return '<Function \'{}\' at {}>'.format(self.name, hex(self.address))
    
    def contains_address(self, address):
        return self.address <= address < self.address + self.size

    def iter_bbs(self):
        for bb in self.bbs:
            yield bb

    def print_disassembly(self):
        for i in self.instructions:
            print hex(i.address) + ' ' + str(i)


class BasicBlock(object):
    def __init__(self, parent_func, address, size):
        self.parent = parent_func
        self.address = address
        self.size = size
        self.offset = self.parent.address - self.address
        self.instructions = [i for i in self.parent.instructions if self.address <= i.address < self.address + self.size]
    
    def __repr__(self):
        return '<Basic block at {}>'.format(hex(self.address))
    
    def print_disassembly(self):
        for i in self.instructions:
            print hex(i.address) + ' ' + str(i)

class Instruction(object):
    def __init__(self, capstone_inst, executable):
        self.capstone_inst = capstone_inst
        self.address = int(self.capstone_inst.address)
        self.op_str = self.capstone_inst.op_str
        self.mnemonic = self.capstone_inst.mnemonic
        self.size = int(self.capstone_inst.size)
        self.groups = self.capstone_inst.groups
        self.bytes = self.capstone_inst.bytes

        self.comment = ''

        self._executable = executable

    def __repr__(self):
        return '<Instruction at {}>'.format(hex(self.address))

    def __str__(self):
        s = self.mnemonic + ' ' + self.nice_op_str()
        if self.comment:
            s += '; "{}"'.format(self.comment)
        if self.address in self._executable.xrefs:
            s += '; XREF={}'.format(', '.join(hex(a)[:-1] for a in self._executable.xrefs[self.address]))
            # TODO: Print nice function relative offsets if the xref is in a function

        return s

    def nice_op_str(self):
        '''
        Returns the operand string "nicely formatted." I.e. replaces addresses with function names (and function
        relative offsets) if appropriate.
        :return: The nicely formatted operand string
        '''
        op_strings = self.op_str.split(', ')

        # If this is an immediate call or jump, try to put a name to where we're calling/jumping to
        if CS_GRP_CALL in self.capstone_inst.groups or CS_GRP_JUMP in self.capstone_inst.groups:
            # jump/call destination will always be the last operand (even with conditional ARM branch instructions)
            operand = self.capstone_inst.operands[-1]
            if operand.imm in self._executable.functions:
                op_strings[-1] = self._executable.functions[operand.imm].name
            elif self._executable.vaddr_is_executable(operand.imm):
                func_addrs = self._executable.functions.keys()
                func_addrs.sort(reverse=True)
                for func_addr in func_addrs:
                    if func_addr < operand.imm:
                        break
                diff = operand.imm - func_addr
                op_strings[-1] = self._executable.functions[func_addr].name+'+'+hex(diff)
        else:
            for i, operand in enumerate(self.capstone_inst.operands):
                if operand.type == CS_OP_IMM and operand.imm in self._executable.strings:
                    referenced_string = self._executable.strings[operand.imm]
                    op_strings[i] = referenced_string.short_name
                    self.comment = referenced_string.string

        return ', '.join(op_strings)

class String(object):
    def __init__(self, string, vaddr, executable):
        self.string = string
        self.short_name = self.string.replace(' ','')[:8]
        self.vaddr = vaddr
        self._executable = executable

    def __repr__(self):
        return '<String \'{}\' at {}>'.format(self.string, self.vaddr)

    def __str__(self):
        return self.string

class CFGEdge(object):
    # Edge with no special information. Could be from a default fall-through, unconditional jump, etc.
    DEFAULT = 0

    # Edge from a conditional jump. Two of these should be added for each cond. jump, one for the True, and one for False
    COND_JUMP = 1

    # Edge from a switch/jump table. One edge should be added for each entry, and the corresponding key set as the value
    SWITCH = 2

    def __init__(self, src, dst, type, value=None):
        self.src = src
        self.dst = dst
        self.type = type
        self.value = value

    def __eq__(self, other):
        if isinstance(other, CFGEdge) and self.src == other.src and self.dst == other.dst and self.type == other.type:
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return '<CFGEdge from {} to {}>'.format(self.src, self.dst)