Dispatch
========

Programmatic binary disassembly and patching

## Features
* Support for all 3 common executable formats (ELF, MachO, PE)
* Support for x86(-64) and ARM (including AArch64)
    * MIPS eventually

## Quick Example
```python
import dispatch
ex = dispatch.read_executable('/bin/cat')
print ex.functions
```