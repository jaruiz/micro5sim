#!/usr/bin/env python

import argparse
import struct
import sys

import m5soc




#~~~~ Command Line Interface ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




def _parse_cmdline():

    parser = argparse.ArgumentParser(
        description='Simulator for micro5 risc-v core',
        epilog="See README.md for a longer description.")

    parser.add_argument('elf', metavar="ELF-FILE", type=str,
        help="Executable (elf) file")
    parser.add_argument('--rom-addr', metavar="NUM",
        help="base address of ROM area. Defaults to 0x%08x" % (m5soc.DEFAULT_ROM_ADDR),
        type=int, default=m5soc.DEFAULT_ROM_ADDR)
    parser.add_argument('--rom-size', metavar="NUM",
        help="size of ROM area in 32-bit words. Defaults to %d KB" % (m5soc.DEFAULT_ROM_WORDS/256),
        type=int, default=m5soc.DEFAULT_ROM_WORDS)
    parser.add_argument('--ram-addr', metavar="NUM",
        help="base address of RAM area. Defaults to 0x%08x" % (m5soc.DEFAULT_RAM_ADDR),
        type=int, default=m5soc.DEFAULT_ROM_ADDR)
    parser.add_argument('--ram-size', metavar="NUM",
        help="size of RAM area in 32-bit words. Defaults to %d KB" % (m5soc.DEFAULT_RAM_WORDS/256),
        type=int, default=m5soc.DEFAULT_RAM_WORDS)
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

    soc = m5soc.SoC(rom, ram)

    soc.rom_writeable = opts.rom_writeable

    if not soc.read_elf(opts.elf):
        print >> sys.stderr, "No executable instructions at reset address."
        sys.exit(4)

    soc.delta_log_file = open("log.txt", "w")
    soc.asm_log_file = open("trace.txt", "w")

    soc.run(opts.num_inst)


if __name__ == "__main__":
    """Entry point when run as plain script (development only)."""
    main()
    print
    sys.exit(0)
