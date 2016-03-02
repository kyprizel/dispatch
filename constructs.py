from capstone import *

class Function(object):
    NORMAL_FUNC = 0
    DYNAMIC_FUNC = 1

    def __init__(self, address, size, name, type=NORMAL_FUNC):
        self.address = address
        self.size = size
        self.name = name
        self.type = type

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
            print str(i.address) + ' ' + i.mnemonic + ' ' + i.op_str


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
            print i.mnemonic + ' ' + i.op_str

class Instruction(object):
    def __init__(self, capstone_inst):
        self.capstone_inst = capstone_inst
        self.address = int(self.capstone_inst.address)
        self.op_str = self.capstone_inst.op_str
        self.mnemonic = self.capstone_inst.mnemonic
        self.size = int(self.capstone_inst.size)
        self.groups = self.capstone_inst.groups
        self.bytes = self.capstone_inst.bytes

    def __repr__(self):
        return '<Instruction at {}>'.format(hex(self.address))

    def __str__(self):
        return self.mnemonic + ' ' + self.op_str

    def prettify_operands(self, analyzer):
        if CS_GRP_CALL in self.capstone_inst.groups or CS_GRP_JUMP in self.capstone_inst.groups:
            operand = self.capstone_inst.operands[-1]
            if operand.imm in analyzer.executable.functions:
                name = analyzer.executable.functions[operand.imm].name
            elif analyzer.executable.vaddr_is_executable(operand.imm):
                func_addrs = analyzer.executable.functions.keys()
                func_addrs.sort(reverse=True)
                for func_addr in func_addrs:
                    if func_addr < operand.imm:
                        break
                diff = operand.imm - func_addr
                name = analyzer.executable.functions[func_addr].name+'+'+hex(diff)
            else:
                name = self.op_str
            self.op_str = name
