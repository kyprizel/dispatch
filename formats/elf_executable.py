from elftools.elf.elffile import ELFFile
from elftools.construct import Container
from elftools.elf.enums import *
from elftools.elf.constants import *
import logging
import struct

from base_executable import *
from section import *

INJECTION_SECTION_NAME = 'inject0'


class ELFExecutable(BaseExecutable):
    def __init__(self, file_path):
        super(ELFExecutable, self).__init__(file_path)
        
        self.helper = ELFFile(self.binary)
        
        self.architecture = self._identify_arch()
        self.pack_endianness = '<' if self.helper.little_endian else '>'
        self.address_pack_type = 'I' if self.helper.elfclass == 32 else 'Q'

        if self.architecture is None:
            raise Exception('Architecture is not recognized')

        logging.debug('Initialized {} {} with file \'{}\''.format(self.architecture, type(self).__name__, file_path))

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
        # TODO: Maybe limit this because we use this as part of our injection method?
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

                # While sh_entsize is sometimes defined, it appears to be incorrect in some cases so we just ignore that
                # and calculate it based off of the total size / num_relocations (plus the trampoline entity)
                entsize = (plt['sh_size'] / (reloc_section.num_relocations() + 1))

                plt_addr = plt['sh_addr'] + ((idx+1) * entsize)

                logging.debug('Directly adding PLT function {} at vaddr {}'.format(symbol_name, hex(plt_addr)))

                f = Function(plt_addr,
                             entsize,
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
                        if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':
                            if section['sh_addr'] <= symbol['st_value'] < section['sh_addr'] + section['sh_size']:
                                name_for_addr[symbol['st_value']] = symbol.name
                                function_vaddrs.add(symbol['st_value'])

                                if symbol['st_size']:
                                    logging.debug('Eagerly adding function {} from .symtab at vaddr {} with size {}'
                                                  .format(symbol.name, hex(symbol['st_value']), hex(symbol['st_size'])))
                                    f = Function(symbol['st_value'],
                                                 symbol['st_size'],
                                                 symbol.name,
                                                 self)
                                    self.functions[symbol['st_value']] = f


                function_vaddrs = sorted(list(function_vaddrs))

                for cur_addr, next_addr in zip(function_vaddrs[:-1], function_vaddrs[1:]):
                    # If st_size was set, we already added the function above, so don't add it again.
                    if cur_addr not in self.functions:
                        func_name = name_for_addr[cur_addr]
                        size = next_addr - cur_addr
                        logging.debug('Lazily adding function {} from .symtab at vaddr {} with size {}'
                                      .format(func_name, hex(cur_addr), hex(size)))
                        f = Function(cur_addr,
                                     next_addr - cur_addr,
                                     name_for_addr[cur_addr],
                                     self,
                                     type=Function.DYNAMIC_FUNC)
                        self.functions[cur_addr] = f

        # TODO: Automatically find and label main from call to libc_start_main

    def _prepare_for_injection(self):
        """
        Overview of how this works:
            We expand the main R/X LOAD segment to basically map all of the executable into memory including a new section
            that we add to the very end of the binary. We can't create a new R/X LOAD segment because the segment header
            table sits near the top of the executable and virtual addresses within the program are calculated based off
            of the offset to the top of the binary (which would obviously change if we added in a segment header).

        NOTES:
            This is technically limited in the amount of data we can inject (since we'll eventually start clobbering
            the PLT or things around there), but there's a generally around 0x200000 bytes between the main binary and
            that so this shouldn't be an issue.
        """

        modified = StringIO(self.binary.getvalue())

        # Some constants that will be used to determine if offsets need to be adjusted:

        # End offset of section headers (i.e. where we'll inject our new section header)
        sec_hdr_end = self.helper['e_shoff'] + self.helper['e_shentsize'] * self.helper['e_shnum']

        # End of the section header string table (i.e. where we'll inject our new section header's name)
        shstrtab_end = self.helper.get_section_by_name('.shstrtab')['sh_offset'] + self.helper.get_section_by_name('.shstrtab')['sh_size']

        # Binary offset where the actual data will be
        injection_offset = self.binary.len + self.helper['e_shentsize'] + len(INJECTION_SECTION_NAME) + 1


        # Update number of section headers
        elf_hdr = self.helper.header.copy()
        elf_hdr.e_shnum += 1
        logging.debug('Changing number of section headers to {}'.format(elf_hdr.e_shnum))

        modified.seek(0)
        modified.write(self.helper.structs.Elf_Ehdr.build(elf_hdr))


        # Adjust offsets for any sections after what we're about to add
        for i in range(self.helper.num_sections()):
            section = self.helper.get_section(i)
            section_hdr = section.header.copy()
            section_hdr_offset = self.helper._section_offset(i)

            if section.header.sh_offset >= sec_hdr_end:
                section_hdr.sh_offset += self.helper['e_shentsize']

            if section.header.sh_offset >= shstrtab_end:
                section_hdr.sh_offset += len(INJECTION_SECTION_NAME) + 1

            if section.header.sh_offset != section_hdr.sh_offset:
                logging.debug('Adjusting section {}\'s offset to {}'.format(i, section_hdr.sh_offset))

            # Also update the shstrtab size if we find it
            if section.name == '.shstrtab':
                logging.debug('Found shstrtab at section index {} (offset {})'.format(i, section_hdr_offset))

                section_hdr.sh_size += len(INJECTION_SECTION_NAME) + 1

                logging.debug('Changing shstrtab size to {}'.format(section_hdr.sh_size))

            modified.seek(section_hdr_offset)
            modified.write(self.helper.structs.Elf_Shdr.build(section_hdr))


        # Adjust offsets for any segments after what we're about to add
        for i in range(self.helper.num_segments()):
            segment = self.helper.get_segment(i)
            segment_hdr = segment.header.copy()
            segment_hdr_offset = self.helper._segment_offset(i)

            if segment_hdr.p_type == 'PT_LOAD' and segment_hdr.p_flags & P_FLAGS.PF_R and segment_hdr.p_flags & P_FLAGS.PF_X:
                logging.debug('Found main R/X LOAD segment at index {}. Setting memsz and filesz to {}'.format(i, injection_offset))
                segment_hdr.p_memsz = injection_offset
                segment_hdr.p_filesz = injection_offset

            if segment.header.p_offset >= sec_hdr_end:
                segment_hdr.p_offset += self.helper['e_shentsize']

            if segment.header.p_offset >= shstrtab_end:
                segment_hdr.p_offset += len(INJECTION_SECTION_NAME) + 1

            if segment.header.p_offset != segment_hdr.p_offset:
                logging.debug('Adjusting segment {}\'s offset to {}'.format(i, segment_hdr.p_offset))

            modified.seek(segment_hdr_offset)
            modified.write(self.helper.structs.Elf_Phdr.build(segment_hdr))

        # At this point, the size of the file itself hasn't changed (i.e. nothing has been spliced in),
        # offsets have just been incremented

        new_sec_hdr = self.helper.structs.Elf_Shdr.build(
            Container(sh_name=self.helper.get_section_by_name('.shstrtab')['sh_size'],
                      sh_type=ENUM_SH_TYPE['SHT_PROGBITS'],
                      sh_flags=SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR,
                      sh_addr=self.executable_segment_vaddr() + injection_offset,
                      sh_offset=injection_offset,
                      sh_size=0,
                      sh_link=0,
                      sh_info=0,
                      sh_addralign=16,
                      sh_entsize=0))

        if shstrtab_end > sec_hdr_end:
            # If the section header string table comes after the section headers themselves (seems to be non-standard)...

            # Splice in section header
            logging.debug('Adding in new section header at offset {}'.format(sec_hdr_end))
            modified = StringIO(modified.getvalue()[:sec_hdr_end] + new_sec_hdr + modified.getvalue()[sec_hdr_end:])

            # Account for the section we just added
            shstrtab_end += self.helper['e_shentsize'] # Account for the section we will splice in

            # And add section name to shstrtab
            logging.debug('Adding section header string table entry at offset {}'.format(shstrtab_end))
            modified = StringIO(modified.getvalue()[:shstrtab_end] + INJECTION_SECTION_NAME + '\x00' + modified.getvalue()[shstrtab_end:])

        else:
            # If the section header string table comes before the section headers (seems to be standard)

            # Add section name to shstrtab
            logging.debug('Adding section header string table entry at offset {}'.format(shstrtab_end))
            modified = StringIO(modified.getvalue()[:shstrtab_end] + INJECTION_SECTION_NAME + '\x00' + modified.getvalue()[shstrtab_end:])

            # Account for the section name we just added
            sec_hdr_end += len(INJECTION_SECTION_NAME) + 1

            # Update e_shoff taking into account the string that we're going to insert
            elf_hdr.e_shoff += len(INJECTION_SECTION_NAME) + 1
            modified.seek(0)
            modified.write(self.helper.structs.Elf_Ehdr.build(elf_hdr))

            # And splice in section header
            logging.debug('Adding in new section header at offset {}'.format(sec_hdr_end))
            modified = StringIO(modified.getvalue()[:sec_hdr_end] + new_sec_hdr + modified.getvalue()[sec_hdr_end:])

        self.binary = modified
        self.helper = ELFFile(self.binary)

    def inject(self, asm, update_entry=False):
        if self.helper.get_section_by_name(INJECTION_SECTION_NAME) is None:
            self._prepare_for_injection()

        # Update the main LOAD segment's memsz/filesz
        for i in range(self.helper.num_segments()):
            segment = self.helper.get_segment(i)
            segment_hdr = segment.header.copy()
            segment_hdr_offset = self.helper._segment_offset(i)

            if segment_hdr.p_type == 'PT_LOAD' and segment_hdr.p_flags & P_FLAGS.PF_R and segment_hdr.p_flags & P_FLAGS.PF_X:
                segment_hdr.p_memsz += len(asm)
                segment_hdr.p_filesz += len(asm)

                self.binary.seek(segment_hdr_offset)
                self.binary.write(self.helper.structs.Elf_Phdr.build(segment_hdr))

                break

        # Update the section's size
        section_idx = [i for i in range(self.helper.num_sections()) if self.helper.get_section(i).name == INJECTION_SECTION_NAME][0]
        section_hdr_offset = self.helper._section_offset(section_idx)
        section_to_inject = self.helper.get_section(section_idx)

        section_hdr = section_to_inject.header.copy()
        section_hdr.sh_size += len(asm)

        self.binary.seek(section_hdr_offset)
        self.binary.write(self.helper.structs.Elf_Shdr.build(section_hdr))


        injection_vaddr = section_to_inject['sh_addr'] + section_to_inject['sh_size']

        # Write the new asm to the end of the file (i.e. the end of the inject section)
        self.binary.seek(0, 2)
        self.binary.write(asm)

        if update_entry:
            logging.debug('Rewriting ELF entry address to {}'.format(injection_vaddr))
            elf_hdr = self.helper.header.copy()
            elf_hdr.e_entry = injection_vaddr

            self.binary.seek(0)
            self.binary.write(self.helper.structs.Elf_Ehdr.build(elf_hdr))

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
