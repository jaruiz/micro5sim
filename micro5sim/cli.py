#!/usr/bin/env python

import argparse
import sys

import m5soc


def _read_rom_verilog(filename):
    """Read ROM image file in Verilig's readmemh-compatible format.
    One line per 32-bit word in plain binary, hexadecimal.
    Empty (whitespace-only) line equivalent to zero.
    Returns list of words (ints).
    """

    words = []
    fi = None

    try:
        fi = open(filename)
        lines = fi.readlines()
        words = [0] * len(lines)
        for index, line in enumerate(lines):
            line = line.strip()
            if len(line) > 0:
                words[index] = int(line, 16) 
    except Exception as e:
        print >> sys.stderr, "Error reading ROM file:"
        print >> sys.stderr, str(e)
        sys.exit(2)
    finally:
        if fi: fi.close()

    return words



#~~~~ Command Line Interface ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# File format argument choices + reader functions.
ROM_FILE_READERS = {
    'verilog-hex': _read_rom_verilog
    }
# Default RAM size in words.
DEFAULT_RAM_SIZE = 64*1024

def _parse_cmdline():

    parser = argparse.ArgumentParser(
        description='Load ROM image on micro5 ISS and run it from reset',
        epilog="See README.md for a longer description.")

    parser.add_argument('rom', metavar="ROM-FILE", type=str,
        help="ROM image file")
    parser.add_argument('--format', 
        help="select format of ROM file. Defaults to '%s'" % 'verilog-hex', 
        choices=ROM_FILE_READERS.keys(), default='verilog-hex')
    parser.add_argument('--ram-size', metavar="NUM",
        help="size of RAM area in 32-bit words. Defaults to %d KB" % (DEFAULT_RAM_SIZE/256),
        type=int, default=DEFAULT_RAM_SIZE)
    parser.add_argument('--num-inst', metavar="NUM",
        help="maximum number of instructions to execute. Defaults to unlimited",
        type=int, default=None)

    args = parser.parse_args()

    return args


def main():
    """Entry point when installed as package."""
    opts = _parse_cmdline()
    
    rom = ROM_FILE_READERS[opts.format](opts.rom)
    ram = [0] * opts.ram_size

    soc = m5soc.SoC(rom, ram)

    soc.delta_log_file = open("log.txt", "w")
    soc.asm_log_file = open("trace.txt", "w")

    soc.run(opts.num_inst)


if __name__ == "__main__":
    """Entry point when run as plain script (development only)."""
    main()
    print
    sys.exit(0)
