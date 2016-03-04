from formats import *

import logging, struct, sys

logging.basicConfig(level=logging.DEBUG)

# Load in the executable with read_executable (pass filename)
executable = read_executable(sys.argv[1])

# Invoke the analyzer to find functions
executable.analyze()

executable.function_named('main').print_disassembly()