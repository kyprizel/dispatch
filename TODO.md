* Store read/written registers in Instruction
    * Use these to properly implement references_ip() and references_sp()
* Change MachO and PE replace_instructions() to the new format (args: vaddr, asm)
* Load binary from stream
* Stop CFG flow after call to exit()
* ARM analysis
* Improve x86 function analysis with flow analysis
* Generators for common instructions for all platforms (jump, call)
* Shift to having a single mmap backed instance of the binary with everything providing views into that data
