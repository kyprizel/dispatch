from elftools.elf.elffile import ELFFile
import logging
import struct

from base_executable import *
from section import *


INJECTION_SIZE = 0x1000

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
        self.section_to_inject = None
        self.next_injection_offset = 0
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
        reloc_section = self.helper.get_section_by_name('.rela.plt')
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

                f = Function(plt_addr, plt['sh_entsize'], symbol_name + '@PLT', type=Function.DYNAMIC_FUNC)
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
                                    f = Function(symbol['st_value'], symbol['st_size'], symbol.name)
                                    self.functions[symbol['st_value']] = f


                function_vaddrs = sorted(list(function_vaddrs))

                for cur_addr, next_addr in zip(function_vaddrs[:-1], function_vaddrs[1:]):
                    # If st_size was set, we already added the function above, so don't add it again.
                    if cur_addr not in self.functions:
                        f = Function(cur_addr, next_addr - cur_addr, name_for_addr[cur_addr], type=Function.DYNAMIC_FUNC)
                        self.functions[cur_addr] = f

        # TODO: Automatically find and label main from call to libc_start_main

    def _prepare_for_injection(self):
        E_XWORD_SIZE = 4 if self.helper.elfclass == 32 else 8
        E_ADDR_SIZE = E_XWORD_SIZE
        E_OFFSET_SIZE = E_ADDR_SIZE


        modified = StringIO(self.binary.getvalue())

        # Update e_shoff (elf section header offset)
        e_shoff = self.helper['e_shoff'] + INJECTION_SIZE
        logging.debug('Rewriting section header offset to {}'.format(e_shoff))

        modified.seek(16 + E_HALF_SIZE + E_HALF_SIZE + E_WORD_SIZE + E_ADDR_SIZE + E_OFFSET_SIZE)
        modified.write(struct.pack(self.pack_endianness + WORD_PACK_TYPE, e_shoff))


        # Update p_filesz and p_memsz for the executable segment, and also
        # update p_offset for all program headers after the executable segment
        executable_segment = None
        for segment_idx, segment in enumerate(self.helper.iter_segments()):
            segment_header_offset = self.helper._segment_offset(segment_idx)

            if executable_segment is not None:
                # Already past the executable segment, so just update the offset
                modified.seek(segment_header_offset + E_WORD_SIZE)

                # ELF64 has an additional p_flags word
                if self.helper.elfclass == 64:
                    modified.seek(E_WORD_SIZE, 1)

                modified.write(struct.pack(self.pack_endianness + self.address_pack_type, segment['p_offset'] + INJECTION_SIZE))

            if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 0x1: # Segment is a LOAD segment and is executable
                logging.debug('Found executable LOAD segment at index {}'.format(segment_idx))
                executable_segment = segment

                seg_filesz = segment['p_filesz'] + INJECTION_SIZE
                seg_memsz = segment['p_memsz'] + INJECTION_SIZE
                logging.debug('Rewriting segment filesize and memsize to {} and {}'.format(seg_filesz, seg_memsz))


                modified.seek(segment_header_offset + E_WORD_SIZE + E_OFFSET_SIZE + E_ADDR_SIZE + E_ADDR_SIZE)

                # Again, account for the p_flags word
                if self.helper.elfclass == 64:
                    modified.seek(E_WORD_SIZE, 1)

                modified.write(struct.pack(self.pack_endianness + (self.address_pack_type*2), seg_filesz, seg_memsz))


        if executable_segment is None:
            logging.error("Could not locate an executable LOAD segment. Cannot continue injection.")
            return False

        last_exec_section_idx = max([idx for idx in range(self.helper.num_sections()) if executable_segment.section_in_segment(self.helper.get_section(idx))])
        last_exec_section = self.helper.get_section(last_exec_section_idx)

        logging.debug('Last section in executable LOAD segment is at index {} ({})'.format(last_exec_section_idx, last_exec_section.name))


        # Update sh_size for the section we grew
        section_header_offset = self.helper._section_offset(last_exec_section_idx)
        modified.seek(section_header_offset + E_WORD_SIZE + E_WORD_SIZE + E_XWORD_SIZE + E_ADDR_SIZE + E_OFFSET_SIZE)
        modified.write(struct.pack(self.pack_endianness + self.address_pack_type, last_exec_section['sh_size'] + INJECTION_SIZE))


        # Update sh_offset for each section past the last section in the executable segment
        for section_idx in range(last_exec_section_idx + 1, self.helper.num_sections()):
            section_header_offset = self.helper._section_offset(section_idx)
            section = self.helper.get_section(section_idx)

            sec_offset = section['sh_offset'] + INJECTION_SIZE
            logging.debug('Rewriting section {} ({}) offset to {}'.format(section_idx, section.name, sec_offset))

            modified.seek(section_header_offset + E_WORD_SIZE + E_WORD_SIZE + E_XWORD_SIZE + E_ADDR_SIZE)
            modified.write(struct.pack(self.pack_endianness + self.address_pack_type, sec_offset))

        self.section_to_inject = last_exec_section

        self.binary = modified

        return True

    def inject(self, asm, update_entry=False):
        if self.section_to_inject is None:
            if not self._prepare_for_injection():
                logging.error("Failed to prepare the binary for asm injection.")
                return
            else:
                self.next_injection_offset = self.section_to_inject['sh_offset'] + self.section_to_inject['sh_size']
                self.next_injection_vaddr = self.section_to_inject['sh_addr'] + self.section_to_inject['sh_size']

                self.binary = StringIO(self.binary.getvalue()[:self.next_injection_offset] + \
                                       '\x00'*INJECTION_SIZE + \
                                       self.binary.getvalue()[self.next_injection_offset:])

        self.binary.seek(self.next_injection_offset)
        self.binary.write(asm)

        if update_entry:
            logging.debug('Rewriting ELF entry address to {}'.format(self.next_injection_vaddr))
            self.binary.seek(16 + E_HALF_SIZE + E_HALF_SIZE + E_WORD_SIZE)
            self.binary.write(struct.pack(self.pack_endianness + self.address_pack_type, self.next_injection_vaddr))

        self.helper = ELFFile(self.binary)

        insert_vaddr = self.next_injection_vaddr

        self.next_injection_offset += len(asm)
        self.next_injection_vaddr += len(asm)

        return insert_vaddr

    def replace_instruction(self, old_ins, new_asm):
        if len(new_asm) > old_ins.size:
            # TODO: make this automatically call inject so that any instruction can be replaced
            raise ValueError('Length of new assembly must be <= size of old instruction')

        self.binary.seek(self.vaddr_binary_offset(old_ins.address))
        self.binary.write(new_asm)

        # TODO: Update function instruction lists
        # TODO: Add function in analyzer to return a NOP so this can be used on all archs
        self.binary.write('\x90' * (old_ins.size - len(new_asm)))
