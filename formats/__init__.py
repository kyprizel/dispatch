from .elf_executable import ELFExecutable
from .pe_executable import PEExecutable
from .macho_executable import MachOExecutable

from enums import *

MAGICS = {'\x7f\x45\x4c\x46': FORMAT.ELF,
          '\x4d\x5a': FORMAT.PE,
          '\x50\x45\x00\x00': FORMAT.PE,
          '\xCE\xFA\xED\xFE': FORMAT.MACH_O,
          '\xCF\xFA\xED\xFE': FORMAT.MACH_O}

def _identify_format(fh):
    maxlen = max([len(m) for m in MAGICS])

    fh.seek(0)
    header = fh.read(maxlen)

    for m in MAGICS:
        if header.startswith(m):
            return MAGICS[m]

    return None

def read_executable(file_path):
    fmt = _identify_format(open(file_path, 'rb'))
    if fmt == FORMAT.ELF:
        return ELFExecutable(file_path)
    elif fmt == FORMAT.PE:
        return PEExecutable(file_path)
    elif fmt == FORMAT.MACH_O:
        return MachOExecutable(file_path)
    else:
        raise Exception('Could not determine executable format.')