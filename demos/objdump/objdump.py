from dispatch import *
from sys import argv

def main():
    if len(argv) < 2:
        print "Usage: python objdump.py [binary]"
        return

    exe = read_executable(argv[1])
    exe.analyze()

    for function in exe.iter_functions():
        print "{:08x} <{}>:".format(function.address, function.name)
        for ins in function.instructions:
            ins_bytes = ' '.join(["{:02x}".format(x) for x in ins.raw])
            print "    {:08x}\t{:<20}\t{!s}".format(ins.address, ins_bytes, ins)
        print "" # newline for space

if __name__ == '__main__':
    main()
