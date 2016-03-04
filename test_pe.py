from formats import *

import logging, struct, sys

logging.basicConfig(level=logging.DEBUG)

# Load in the executable with read_executable (pass filename)
executable = read_executable(sys.argv[1])

# Invoke the analyzer to find functions
executable.analyze()

# For tests/ftp.exe
executable.function_named('sub_1004187').name = 'print_help'

help_func = executable.function_named('print_help')


# calc shellcode
instrumentation = "\x31\xdb\x64\x8b\x7b\x30\x8b\x7f" + \
        "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b" + \
        "\x77\x20\x8b\x3f\x80\x7e\x0c\x33" + \
        "\x75\xf2\x89\xc7\x03\x78\x3c\x8b" + \
        "\x57\x78\x01\xc2\x8b\x7a\x20\x01" + \
        "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6" + \
        "\x45\x81\x3e\x43\x72\x65\x61\x75" + \
        "\xf2\x81\x7e\x08\x6f\x63\x65\x73" + \
        "\x75\xe9\x8b\x7a\x24\x01\xc7\x66" + \
        "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7" + \
        "\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9" + \
        "\xb1\xff\x53\xe2\xfd\x68\x63\x61" + \
        "\x6c\x63\x89\xe2\x52\x52\x53\x53" + \
        "\x53\x53\x53\x53\x52\x53\xff\xd7"

# JMP to the back to the function's address + 2 (to hop over the jmp -5)
instrumentation += '\xe9' + struct.pack('<i', help_func.address + 2 - (0x1012000 + len(instrumentation) + 5))

injected_vaddr = executable.inject(instrumentation)

print "Injected code @ {}".format(hex(injected_vaddr))

# Windows graciously gives us a perfect jmp/call trampoline to inject into for their hot patching.
# First, we jump -7 bytes backwards (2 bytes for the jmp itself and 5 because that's how many bytes they give us)
# Then we can just inject a full 5 byte far call to our instrumentation (which is put into a new section in the PE)
executable.replace_instruction(help_func.instructions[0], '\xeb\xf9') # jmp -5

injected_rva = injected_vaddr - executable.helper.OPTIONAL_HEADER.ImageBase
ins_rva = help_func.instructions[0].address - 5 - executable.helper.OPTIONAL_HEADER.ImageBase
call_len = 5

executable.helper.set_bytes_at_rva(ins_rva,
                                   '\xe9' + struct.pack('<i', injected_rva - ins_rva - call_len))

f = open('mod.exe','wb')
f.write(executable.get_binary())
f.close()

cfg = executable.analyzer.cfg()