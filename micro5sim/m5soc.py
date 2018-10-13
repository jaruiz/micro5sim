#!/usr/bin/env python

import argparse
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

import m5cpu


DEFAULT_ROM_ADDR =  0x00000000
DEFAULT_ROM_WORDS = 256*1024
DEFAULT_RAM_ADDR =  0x40000000
DEFAULT_RAM_WORDS = 64*1024


class SoC(object):

    def __init__(self, rom=None, ram=None):
        self.rom = rom
        self.ram = ram
        self.rom_bot = DEFAULT_ROM_ADDR
        self.rom_top = DEFAULT_ROM_ADDR + len(rom)
        self.ram_bot = DEFAULT_RAM_ADDR
        self.ram_top = DEFAULT_RAM_ADDR + len(ram)
        self.cpu = m5cpu.CPU(self._load, self._store, self._log_delta, self._log_asm)
        self.delta_log_file = None
        self.asm_log_file = None
        self.rom_writeable = False

    def reset(self):
        self.cpu.reset()


    def run(self, num=None):
        self.cpu.run(num)


    def read_elf(self, filename):
        """ Read all sections into the memory area they're contained in.
            Ignore any section that is fully outside all memory areas but 
            fail if any section is part in part out.
            Assume no section straddles two memory areas and areas don't overlap.
            Assume data in all sections is little endian.

            Return true if any instructions were loaded at the reset address.
        """
        try:
            fi = open(filename)
            elf = ELFFile(fi)

            # Display some info in a format resembling riscvOVPsim's.
            print "Read object file '%s'" % filename
            print "Sections loaded:"
            print "  Area          Section           Address     MemSize"


            executable_stuff_at_reset_addr = False
            for section in elf.iter_sections():
                addr = section.header['sh_addr']
                size = section.header['sh_size']
                flags = section.header['sh_flags']

                # Ignore any sections not meant to be loaded to memory.
                if not (flags & SH_FLAGS.SHF_ALLOC): continue

                # Remember if we load instructions on the reset address.
                if (flags & SH_FLAGS.SHF_EXECINSTR):            
                    if m5cpu.ADDR_RESET >= addr and m5cpu.ADDR_RESET < (addr + size):
                        executable_stuff_at_reset_addr = True

                # Find out which area contains this section.
                if addr >= self.rom_bot and (addr+size) < self.rom_top:
                    # Section is within ROM area.
                    self._print_section_info(section, "ROM")
                    
                    # Fail if a writeable section wants to live in ROM area.
                    if not self.rom_writeable and (flags & SH_FLAGS.SHF_WRITE):
                        print "Error: Section '%s' in ROM area is writeable" % (section.name)
                        sys.exit(5)

                    # Otherwise just copy the little endian stuff
                    self._load_section_data(section, addr - self.rom_bot, self.rom)
                    

                elif addr >= self.ram_bot and (addr+size) < self.ram_top:
                    # Section is within RAM area.
                    self._print_section_info(section, "RAM")
                    # Just copy the section to RAM. Even if it is read-only.
                    self._load_section_data(section, addr - self.ram_bot, self.ram)
                    
            
                else:
                    # Not fully contained by ROM or RAM areas.
                    # If there's any overlap then fail, otherwise ignore section.
                    pass
                    # FIXME fail on overlap

            fi.close()

        except IOError as e:
            print >> sys.stderr, "Error reading elf file:"
            print >> sys.stderr, str(e)
            sys.exit(2)

        return executable_stuff_at_reset_addr


    def _load(self, addr):
        windex = addr / 4
        if self.rom_bot <= windex < self.rom_top:
            return self.rom[windex - self.rom_bot]
        elif self.rom_bot <= windex < self.rom_top:
            return self.ram[windex - self.ram_bot]
        else:
            return 0

    def _store(self, addr, value, lanes=4):
        masks = [0xff, 0xff, 0xffff, 0xffff, 0xffffffff]
        windex = addr / 4
        bindex = (addr % 4) if lanes == 1 else addr & 0b10 if lanes == 2 else 0
        mask = masks[lanes] << (bindex * 8)
        value = (value << (bindex * 8)) & mask

        if self.rom_bot <= windex < self.rom_top:
            word = self.rom[windex - self.rom_bot]
            word = (word & ~mask) | value
            if self.rom_writeable:
                self.rom[windex - self.rom_bot] = word
            else:
                # Storing to read-only ROM area. Ignore.
                print "[0x%08x] warning: writing to read-only address 0x%08x" % (self.PC, addr)

        elif self.rom_bot <= windex < self.rom_top:
            word = self.ram[windex - self.ram_bot]
            word = (word & ~mask) | value
            self.ram[windex - self.ram_bot] = word
        elif addr == 0x10000000: # FIXME parameter
            # FIXME to file
            sys.stdout.write("%c" % (value & 0xff))
            sys.stdout.flush()


    def _log_delta(self, pc, index, value):
        if self.delta_log_file:
            print >> self.delta_log_file, "%08x: r%02d=%08x" % (pc, index, value)


    def _log_asm(self, asm):
        if self.asm_log_file:
            print >> self.asm_log_file, asm


    def _print_section_info(self, section, area):
        print "  %-12s  %-16s  0x%08x  0x%08x" % (area, section.name, section.header['sh_addr'], section.header['sh_size'])    


    def _load_section_data(self, section, offset, mem):
        data = bytearray()
        data.extend(section.data())
        for j in range(len(data)/4):
            i = j * 4
            word = (data[i+0]<<0) | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24)
            mem[j] = word

