import os
from dispatch import *

exe = read_executable('thing')
exe.analyze()

main = exe.function_named('_main')

ins = None

for i in main.instructions:
    if i.mnemonic == 'jne':
        ins = i
        break

exe.replace_instruction(ins, '')

exe.save('patched')

os.system("chmod +x patched")
