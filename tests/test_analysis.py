from dispatch.formats import *

import logging, sys

logging.basicConfig(level=logging.DEBUG)

executable = read_executable(sys.argv[1])

executable.analyze()