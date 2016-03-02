# The All-In-One Disassembler

## Overview
The AIO disassembler is an attempt to bridge the gap between raw binary disassemblers (e.g. capstone), more 'full-featured' disassemblers/decompilers (e.g. IDA, Hopper), and post-mortem debugging tools.

The goal is to create a single product that can be given any common executable format (currently ELF, PE, and MachO are supported with varying levels of support for x86[-64], ARM[64], and MIPS in each) and to be able to immediately traverse the program quickly and efficiently.

## Implementation
Currently there are 3 main problems that have to be solved in the implementation:

1. Reading and parsing various executable formats into a single generic structure
2. Doing the actual code analysis to break the binary up into basic blocks, generate higher level constructs (e.g. automatic loop detection), generate CFGs, etc.
3. Reading in a trace (from PIN) and being able to break that trace up by the basic blocks and other constructs created in (2) so that it can be easily analyzed. For instance, this could be used to look for commonly (or, alternatively, never) hit functions that appear/don't appear in a trace so that the focus of manual analysis could be better targeted.

