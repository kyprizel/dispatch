from elftools.elf.elffile import ELFFile
from elftools.construct import Container
from elftools.elf.enums import *
from elftools.elf.constants import *
import logging
import struct

from base_executable import *
from section import *

INJECTION_SIZE = 0x1000

INJECTION_SECTION_NAME = 'inject0'

E_HALF_SIZE = 2
E_WORD_SIZE = 4
WORD_PACK_TYPE = 'I'


class ELFExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(ELFExecutable, self).__init__(file_path)
        
        self.helper = ELFFile(self.binary)
        
        self.architecture = self._identify_arch()
        self.pack_endianness = '<' if self.helper.little_endian else '>'
        self.address_pack_type = 'I' if self.helper.elfclass == 32 else 'Q'

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        self.executable_segment = [s for s in self.helper.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 0x1][0]

        self.next_injection_vaddr = 0

    def _identify_arch(self):
        machine = self.helper.get_machine_arch()
        if machine == 'x86':
            return ARCHITECTURE.X86
        elif machine == 'x64':
            return ARCHITECTURE.X86_64
        elif machine == 'ARM':
            return ARCHITECTURE.ARM
        elif machine == 'AArch64':
            return ARCHITECTURE.ARM_64
        elif machine == 'MIPS':
            return ARCHITECTURE.MIPS
        else:
            return None

    def entry_point(self):
        return self.helper['e_entry']

    def executable_segment_vaddr(self):
        return self.executable_segment['p_vaddr']

    def executable_segment_size(self):
        return self.executable_segment['p_memsz']

    def iter_sections(self):
        for e_section in self.helper.iter_sections():
            yield section_from_elf_section(e_section)

    def iter_string_sections(self):
        STRING_SECTIONS = ['.rodata', '.data', '.bss']
        for s in self.iter_sections():
            if s.name in STRING_SECTIONS:
                yield s

    def _extract_symbol_table(self):
        # Add in symbols from the PLT/rela.plt
        # .rela.plt contains indexes to reference both .dynsym (symbol names) and .plt (jumps to GOT)
        if self.is_64_bit():
            reloc_section = self.helper.get_section_by_name('.rela.plt')
        else:
            reloc_section = self.helper.get_section_by_name('.rel.plt')

        if reloc_section:
            dynsym = self.helper.get_section(reloc_section['sh_link']) # .dynsym
            plt = self.helper.get_section_by_name('.plt')
            for idx, reloc in enumerate(reloc_section.iter_relocations()):
                # Get the symbol's name from dynsym
                symbol_name = dynsym.get_symbol(reloc['r_info_sym']).name

                # The address of this function in the PLT is the base PLT offset + the index of the relocation.
                # However, since there is the extra "trampoline" entity at the top of the PLT, we need to add one to the
                # index to account for it.
                plt_addr = plt['sh_addr'] + ((idx+1) * plt['sh_entsize'])

                f = Function(plt_addr,
                             plt['sh_entsize'],
                             symbol_name + '@PLT',
                             self,
                             type=Function.DYNAMIC_FUNC)
                self.functions[plt_addr] = f



        # Some things in the symtab have st_size = 0 which confuses analysis later on. To solve this, we keep track of
        # where each address is in the `function_vaddrs` set and go back after all symbols have been iterated to compute
        # size by taking the difference between the current address and the next recorded address.

        # We do this for each executable section so that the produced functions cannot span multiple sections.

        for section in self.helper.iter_sections():
            if self.executable_segment.section_in_segment(section):
                name_for_addr = {}

                function_vaddrs = set([section['sh_addr'] + section['sh_size']])

                symbol_table = self.helper.get_section_by_name('.symtab')
                if symbol_table:
                    for symbol in symbol_table.iter_symbols():
                        if symbol['st_info']['type'] == 'STT_FUNC':
                            if section['sh_addr'] <= symbol['st_value'] < section['sh_addr'] + section['sh_size']:
                                name_for_addr[symbol['st_value']] = symbol.name
                                function_vaddrs.add(symbol['st_value'])

                                if symbol['st_size']:
                                    f = Function(symbol['st_value'],
                                                 symbol['st_size'],
                                                 symbol.name,
                                                 self)
                                    self.functions[symbol['st_value']] = f


                function_vaddrs = sorted(list(function_vaddrs))

                for cur_addr, next_addr in zip(function_vaddrs[:-1], function_vaddrs[1:]):
                    # If st_size was set, we already added the function above, so don't add it again.
                    if cur_addr not in self.functions:
                        f = Function(cur_addr,
                                     next_addr - cur_addr,
                                     name_for_addr[cur_addr],
                                     self,
                                     type=Function.DYNAMIC_FUNC)
                        self.functions[cur_addr] = f

        # TODO: Automatically find and label main from call to libc_start_main

    def _prepare_for_injection(self):
        E_XWORD_SIZE = 4 if self.helper.elfclass == 32 else 8
        E_ADDR_SIZE = E_XWORD_SIZE
        E_OFFSET_SIZE = E_ADDR_SIZE

        OFFSET_PACK_TYPE = 'I' if self.helper.elfclass == 32 else 'Q'

        # TODO: 64 bit ELF differences

        modified = StringIO(self.binary.getvalue())

        # Update number of section headers
        e_shnum = self.helper['e_shnum']
        e_shnum += 1
        logging.debug('Changing number of section headers to {}'.format(e_shnum))

        modified.seek((16 +            # e_ident
                       E_HALF_SIZE +   # e_type
                       E_HALF_SIZE +   # e_machine
                       E_WORD_SIZE +   # e_version
                       E_ADDR_SIZE +   # e_entry
                       E_OFFSET_SIZE + # e_phoff
                       E_OFFSET_SIZE + # e_shoff
                       E_WORD_SIZE +   # e_flags
                       E_HALF_SIZE +   # e_ehsize
                       E_HALF_SIZE +   # e_phentsize
                       E_HALF_SIZE +   # e_phnum
                       E_HALF_SIZE))   # e_shentsize
        modified.write(struct.pack(self.pack_endianness + 'H', e_shnum))

        # Update size of section header string table to fit new section name
        for i in range(self.helper.num_sections()):
            section = self.helper.get_section(i)
            if section.name == '.shstrtab':
                section_hdr_offset = self.helper._section_offset(i)

                shstrtab_size = section['sh_size']
                shstrtab_size += len(INJECTION_SECTION_NAME) + 1

                modified.seek((section_hdr_offset +
                               E_WORD_SIZE + # sh_name
                               E_WORD_SIZE + # sh_type
                               E_WORD_SIZE + # sh_flags
                               E_ADDR_SIZE + # sh_addr
                               E_OFFSET_SIZE)) # sh_offset
                modified.write(struct.pack(self.pack_endianness + WORD_PACK_TYPE, shstrtab_size))


        # Some constants that will be used to determine if offsets need to be adjusted:

        # End offset of section headers (i.e. where we'll inject our new section header)
        sec_hdr_end = self.helper['e_shoff'] + self.helper['e_shentsize'] * self.helper['e_shnum']

        # End of the section header string table (i.e. where we'll inject our new section header's name)
        shstrtab_end = self.helper.get_section_by_name('.shstrtab')['sh_offset'] + self.helper.get_section_by_name('.shstrtab')['sh_size']



        # Change program header offset if necessary
        e_phoff = self.helper['e_phoff']
        if e_phoff >= sec_hdr_end:
            e_phoff += self.helper['e_shentsize'] # Make room for a new section header

            if self.helper['e_phoff'] >= shstrtab_end:
                e_phoff += len(INJECTION_SECTION_NAME) + 1 # Also make room for section name and null byte

            logging.debug('Changing program header offset to {}'.format(e_phoff))

            modified.seek((16 +          # e_ident
                           E_HALF_SIZE + # e_type
                           E_HALF_SIZE + # e_machine
                           E_WORD_SIZE + # e_version
                           E_ADDR_SIZE)) # e_entry
            modified.write(struct.pack(self.pack_endianness + OFFSET_PACK_TYPE, e_phoff))


        # Adjust offsets for any sections after the section header we're about to add
        for i in range(self.helper.num_sections()):
            section = self.helper.get_section(i)
            if section['sh_offset'] >= sec_hdr_end:
                section_hdr_offset = self.helper._section_offset(i)

                sh_offset = section['sh_offset'] + self.helper['e_shentsize']

                if section['sh_offset'] >= shstrtab_end:
                    sh_offset += len(INJECTION_SECTION_NAME) + 1

                logging.debug('Adjusting section {}\'s offset to {}'.format(i, sh_offset))

                modified.seek((section_hdr_offset +
                               E_WORD_SIZE + # sh_name
                               E_WORD_SIZE + # sh_type
                               E_WORD_SIZE + # sh_flags
                               E_ADDR_SIZE)) # sh_addr

                modified.write(struct.pack(self.pack_endianness + OFFSET_PACK_TYPE, sh_offset))

        # Adjust offsets for any segments after the section header we're about to add
        for i in range(self.helper.num_segments()):
            segment = self.helper.get_segment(i)
            if segment['p_offset'] >= sec_hdr_end:
                segment_hdr_offset = self.helper._segment_offset(i)

                p_offset = segment['p_offset'] + self.helper['e_shentsize']

                if segment['p_offset'] >= shstrtab_end:
                    p_offset += len(INJECTION_SECTION_NAME) + 1

                logging.debug('Adjusting segment {}\'s offset to {}'.format(i, p_offset))

                modified.seek(segment_hdr_offset + E_WORD_SIZE)

                modified.write(struct.pack(self.pack_endianness + OFFSET_PACK_TYPE, p_offset))

        if shstrtab_end > sec_hdr_end:
            # Section header string table comes after the section headers themselves (seems to be non-standard)
            shstrtab_end += self.helper['e_shentsize'] # Account for the section we will splice in
        else:
            # Section header string table comes before the section headers (seems to be standard)
            # Update e_shoff taking into account the string that we're going to insert
            e_shoff = self.helper['e_shoff']
            e_shoff += len(INJECTION_SECTION_NAME) + 1

            modified.seek((16 +            # e_ident
                           E_HALF_SIZE +   # e_type
                           E_HALF_SIZE +   # e_machine
                           E_WORD_SIZE +   # e_version
                           E_ADDR_SIZE +   # e_entry
                           E_OFFSET_SIZE)) # e_phoff
            modified.write(struct.pack(self.pack_endianness + OFFSET_PACK_TYPE, e_shoff))

        # Splice in the actual section header
        hdr = self.helper.structs.Elf_Shdr.build(Container(sh_name=self.helper.get_section_by_name('.shstrtab')['sh_size'],
                                                           sh_type=ENUM_SH_TYPE['SHT_PROGBITS'],
                                                           sh_flags=SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR,
                                                           sh_addr=0x700000,
                                                           sh_offset=len(self.get_binary()) + self.helper['e_shentsize'] + len(INJECTION_SECTION_NAME) + 1,
                                                           sh_size=0,
                                                           sh_link=0,
                                                           sh_info=0,
                                                           sh_addralign=0,
                                                           sh_entsize=0))

        logging.debug('Adding in new section header at offset {}'.format(sec_hdr_end))
        modified = StringIO(modified.getvalue()[:sec_hdr_end] + hdr + modified.getvalue()[sec_hdr_end:])

        # Add section name to shstrtab
        logging.debug('Adding section header string table entry at offset {}'.format(shstrtab_end))
        modified = StringIO(modified.getvalue()[:shstrtab_end] + INJECTION_SECTION_NAME + '\x00' + modified.getvalue()[shstrtab_end:])

        self.binary = modified
        self.helper = ELFFile(self.binary)

    def inject(self, asm, update_entry=False):
        E_XWORD_SIZE = 4 if self.helper.elfclass == 32 else 8
        E_ADDR_SIZE = E_XWORD_SIZE
        E_OFFSET_SIZE = E_ADDR_SIZE

        if self.helper.get_section_by_name(INJECTION_SECTION_NAME) is None:
            self._prepare_for_injection()

        section_idx = [i for i in range(self.helper.num_sections()) if self.helper.get_section(i).name == INJECTION_SECTION_NAME][0]

        section_hdr_offset = self.helper._section_offset(section_idx)

        section_to_inject = self.helper.get_section(section_idx)

        # Update the section's size
        sh_size = section_to_inject['sh_size']
        sh_size += len(asm)
        self.binary.seek((section_hdr_offset +
                          E_WORD_SIZE + # sh_name
                          E_WORD_SIZE + # sh_type
                          E_WORD_SIZE + # sh_flags
                          E_ADDR_SIZE + # sh_addr
                          E_OFFSET_SIZE)) # sh_offset

        self.binary.write(struct.pack(self.pack_endianness + WORD_PACK_TYPE, sh_size))

        injection_vaddr = section_to_inject['sh_addr'] + section_to_inject['sh_size']

        # Write the new asm to the end of the file (i.e. the end of the inject section)
        self.binary.seek(0, 2)
        self.binary.write(asm)

        if update_entry:
            logging.debug('Rewriting ELF entry address to {}'.format(injection_vaddr))
            self.binary.seek(16 + E_HALF_SIZE + E_HALF_SIZE + E_WORD_SIZE)
            self.binary.write(struct.pack(self.pack_endianness + self.address_pack_type, injection_vaddr))

        self.helper = ELFFile(self.binary)

        self.next_injection_vaddr = injection_vaddr + len(asm)

        return injection_vaddr

    def replace_instruction(self, old_ins, new_asm):
        if len(new_asm) > old_ins.size:
            # TODO: make this automatically call inject so that any instruction can be replaced
            raise ValueError('Length of new assembly must be <= size of old instruction')

        self.binary.seek(self.vaddr_binary_offset(old_ins.address))
        self.binary.write(new_asm)

        # TODO: Update function instruction lists
        # TODO: Add function in analyzer to return a NOP so this can be used on all archs
        self.binary.write('\x90' * (old_ins.size - len(new_asm)))
