import dispatch
import logging,glob

logging.basicConfig(level=logging.INFO)
binary_types = ['macho', 'elf', 'pe']
for bin_type in binary_types:
    print("~~ Testing binary type: {} ~~".format(bin_type))
    for f in glob.glob('binaries/*/*.{}'.format(bin_type)):
        print("Testing {}...".format(f))
        executable = dispatch.read_executable(f)
        executable.analyze()
        executable.analyzer.cfg()
        print("Passed {}!".format(f))
        print('')
    print('')
