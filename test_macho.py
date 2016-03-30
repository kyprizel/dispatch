from formats import *

import logging, struct, sys

logging.basicConfig(level=logging.DEBUG)

# Load in the executable with read_executable (pass filename)
executable = read_executable(sys.argv[1])

# Invoke the analyzer to find functions
executable.analyze()

executable.functions[4294974093].print_disassembly()