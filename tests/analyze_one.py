from dispatch import *
import logging, sys
logging.basicConfig(level=logging.INFO)

exe = read_executable(sys.argv[1])
exe.analyze()
exe.analyzer.cfg()
print "passed"
