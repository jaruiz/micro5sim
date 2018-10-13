#!/usr/bin/env python

import argparse
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

import m5soc
import m5cpu

DEFAULT_ROM_ADDR =  m5soc.DEFAULT_ROM_ADDR
DEFAULT_ROM_WORDS = 256*1024
DEFAULT_RAM_ADDR =  m5soc.DEFAULT_RAM_ADDR
DEFAULT_RAM_WORDS = 64*1024


def _read_elf(filename, rom, ram, opts):
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
            if addr >= opts.rom_addr and (addr+size) < (opts.rom_addr + opts.rom_size):
                # Section is within ROM area.
                _print_section_info(section, "ROM")
                
                # Fail if a writeable section wants to live in ROM area.
                # FIXME pass option on to mcu object!
                if not opts.rom_writeable and (flags & SH_FLAGS.SHF_WRITE):
                    print "Error: Section '%s' in ROM area is writeable" % (section.name)
                    sys.exit(5)

                # Otherwise just copy the little endian stuff
                _load_section_data(section, addr - opts.ram_addr, rom)
                

            elif addr >= opts.ram_addr and (addr+size) < (opts.ram_addr + opts.ram_size):
                # Section is within RAM area.
                _print_section_info(section, "RAM")
                # Just copy the section to RAM. Even if it is read-only.
                _load_section_data(section, addr - opts.rom_addr, ram)
                
        
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


def _print_section_info(section, area):
    print "  %-12s  %-16s  0x%08x  0x%08x" % (area, section.name, section.header['sh_addr'], section.header['sh_size'])    


def _load_section_data(section, offset, mem):
    data = bytearray()
    data.extend(section.data())
    for j in range(len(data)/4):
        i = j * 4
        word = (data[i+0]<<0) | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24)
        mem[j] = word




#~~~~ Command Line Interface ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




def _parse_cmdline():

    parser = argparse.ArgumentParser(
        description='Simulator for micro5 risc-v core',
        epilog="See README.md for a longer description.")

    parser.add_argument('elf', metavar="ELF-FILE", type=str,
        help="Executable (elf) file")
    parser.add_argument('--rom-addr', metavar="NUM",
        help="base address of ROM area. Defaults to 0x%08x" % (DEFAULT_ROM_ADDR),
        type=int, default=DEFAULT_ROM_ADDR)
    parser.add_argument('--rom-size', metavar="NUM",
        help="size of ROM area in 32-bit words. Defaults to %d KB" % (DEFAULT_ROM_WORDS/256),
        type=int, default=DEFAULT_ROM_WORDS)
    parser.add_argument('--ram-addr', metavar="NUM",
        help="base address of RAM area. Defaults to 0x%08x" % (DEFAULT_RAM_ADDR),
        type=int, default=DEFAULT_ROM_ADDR)
    parser.add_argument('--ram-size', metavar="NUM",
        help="size of RAM area in 32-bit words. Defaults to %d KB" % (DEFAULT_RAM_WORDS/256),
        type=int, default=DEFAULT_RAM_WORDS)
    parser.add_argument('--num-inst', metavar="NUM",
        help="maximum number of instructions to execute. Defaults to unlimited",
        type=int, default=None)
    parser.add_argument('--rom-writeable', action="store_true",
        help="make ROM area writeable (effectively a second RAM area). Defaults to False",
        default=False)

    args = parser.parse_args()

    return args


def main():
    """Entry point when installed as package."""
    opts = _parse_cmdline()
    
    rom = [0] * opts.rom_size
    ram = [0] * opts.ram_size

    if not _read_elf(opts.elf, rom, ram, opts):
        print >> sys.stderr, "No executable instructions at reset address."
        sys.exit(4)

    soc = m5soc.SoC(rom, ram)

    soc.delta_log_file = open("log.txt", "w")
    soc.asm_log_file = open("trace.txt", "w")

    soc.run(opts.num_inst)


if __name__ == "__main__":
    """Entry point when run as plain script (development only)."""
    main()
    print
    sys.exit(0)
