import dispatch

import logging, sys

logging.basicConfig(level=logging.DEBUG)

executable = dispatch.read_executable(sys.argv[1])

executable.analyze()