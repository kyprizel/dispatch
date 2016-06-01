# dispatch Docs

Though this code is reasonably well commented/logged (esp. the base classes), I wanted to write up some basic theory and broad docs to make contributing easier.

So here we go.

## Class breakdown

Larger classes (i.e. Executable and Analyzer) have a single base class which defines required functions for the subclasses and also provides basic implementations for a few helper functions.

### Executable

The executable class should be subclassed for each file format to be supported. Currently, we provide executable parsers for the 3 most common binary types:

* [ELF](./dispatch/formats/elf_executable.py) (used by Linux, Solaris, the BSDs, etc.)
* [PE](./dispatch/formats/pe_executable.py) (used by Windows)
* [MachO](./dispatch/formats/macho_executable.py) (used by OS X)

It is preferred to use existing (license compatible) libraries to do the low-level executable parsing to reduce errors that we could make and keep the codebase small.

#### Purpose

The executable classes are responsible for parsing the executable, handing off the "chunks" of the binary to the analyzer, and doing the binary rewriting part of the patching.

The executable classes currently extract and keep the following:

* Segments/sections
* Referenced libraries
* Symbol table(s)
* Strings

The executable classes also keep an array for the functions of the binary, however it is up to the analyzer to identify and store those.

### Analyzer

The analyzer class should be subclassed for each architecture to be supported. If two architectures are very similar (e.g. x86/i386 and x86\_64), they should be put into one file. Also if possible, a superset architecture (e.g. x86\_64) should subclass the "simpler" subset architecture (e.g. x86).

We currently provide analysis classes for 4 architectures:

* [x86](./dispatch/analysis/x86_analyzer.py)
* [x86\_64](./dispatch/analysis/x86_analyzer.py)
* [ARM](./dispatch/analysis/arm_analyzer.py)
* [AArch64](./dispatch/analysis/arm_analyzer.py) (a.k.a. ARM64)

Currently, all of these analyzers are based around the [capstone engine](https://github.com/aquynh/capstone), but any disassembler could be used with minimal effort required to switch.

#### Purpose

The analyzer classes are responsible for doing the actual analysis of binaries:

* Disassembling the binary
* Identifying constructs in a binary (e.g. functions, basic blocks, jump tables)
* Generating CFGs

The analyzer also provides architecture-specific helper methods and constants for use in patching (e.g. `REG_NAMES`, `IP_REGS`, `SP_REGS`, `NOP_INSTRUCTION`)

## Loading & Analysis Flow

The following is a breakdown of what happens when a binary is loaded and analyzed:

1. `read_executable` (in [\_\_init\_\_.py](./dispatch/__init__.py)) identifies the binary format based on starting magic bytes.
2. The initializer for the found format is called which loads the binary into its helper (e.g. [pyelftools](https://github.com/eliben/pyelftools)) for parsing
3. The format initializer parses out some basic information from the loaded binary and stores it for further use (e.g. the sections/segments of the binary, which segment is the main read&executable segment, etc.)
4. `analyze()` (defined in [base\_analyzer.py](./dispatch/analysis/base_analyzer.py) is called by a script on the returned executable instance, which...
5. Disassembles the binary into a Trie for quick lookups
6. Asks the executable to parse and store the symbol table
7. Identifies functions through a couple of methods (see below)
8. Populates the (empty) functions with Instructions
9. Does basic block analysis on the (now populated) Functions
10. Marks cross-references
11. Marks strings

Once this is done, everything in the binary has been setup and can be used.

## Implementation Notes

### Function analysis

Currently, functions are marked in two ways:

1. Through symbol tables (if applicable)
2. Through prologue/epilogue matching

Since symbol tables and prologue/epilogue matching occur at different times, the binaries' `.functions` array is filled with what are essentially placeholder functions (i.e. functions without instructions stored) until the functions are formally populated (step 8 above).

The need for this two-step find and fill processs will be completely removed soon when a single structure represents all bytes in the binary along with what they represent.
Basically instead of a Function having a normal array, the array will actually just be a view into this backing datastructure (since the offset and size is already known).
This will fix a lot of potential issues stemming from arrays not being synchronized and whatnot, and will allow for something like the following to work:

```python
main = executable.function_named('main')
main.bbs[0].instructions[0] = '\xcc'
main.save('modified')
```


### Patching

#### ELF

As noted, we use a method derived from [http://vxheavens.com/lib/vsc01.html](http://vxheavens.com/lib/vsc01.html).

#### MachO

MachO's are very kind and provide us with room to just drop in a new section because of the large amount of padding after the headers and before the rest of the binary.
All we have to do as create the new load command and have it point to the end of the executable where we drop our (address aligned) injected code.

#### PE

Since we are already using [pefile](https://github.com/erocarrera/pefile), we are able to let [SectionDoubleP](http://git.n0p.cc/?p=SectionDoubleP.git;a=summary) do the heavy lifting of adding a new section.


### Why a Trie?

Because it gives us a quick way to do fast (i.e. non-linear time) lookups, while also providing a way to get ranges of the binary without a linear search.

### X-Ref detection

Currently we do _very_ simplistic x-ref detection by finding any instruction operands that happen to be immediates (i.e. set values) and that happen to land in mapped virtual memory.
While this is potentially error-prone, it seems to work very well in practice, and so we haven't seen a need to improve it yet.

### String detection

Similar to x-ref detection, string detection is very simplistic: any time 3 or more printable characters appear in a row in certain sections, it is marked as a string.
Again, while this is definitely error-prone, it seems to end up working just fine in almost all cases so far, so we haven't seen a need to improve it.