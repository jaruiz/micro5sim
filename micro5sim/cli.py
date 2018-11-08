#!/usr/bin/env python

import argparse
import collections
import os.path
import posix
import re
import struct
import sys

import m5soc
import m5cpu


# Custom exit codes (apart from the Posix standard ones).
EX_UNIMPLEMENTED =      10
EX_TRACE_MISMATCH =     12
EX_SIG_MISMATCH =       13
EX_NOEXEC_AT_RESET =    20
EX_PROGRAM_TERMINATED = 129



# REs used to parse OVPsim trace lines...
RE_TRACE = re.compile(r"^Info\s+'[\w/]+',\s+0x([0-9a-fA-F]+)\([\w+]+\):\s+([0-9a-fA-F]+)(.*)$")
RE_TRACECHANGE = re.compile(r"^Info\s+(\w+)\s+([0-9a-fA-F]+)\s+->\s+([0-9a-fA-F]+)$")

# ...and named tuple holding a single trace entry.
TracePoint = collections.namedtuple("TracePoint", ["reg", "pre", "post", "addr", "bin", "asm"])


def _read_ovp_trace(filename):
    """Read an ovpsim trace file (generated with --trace --tracechange) and
    build a list of register change trace points: instructions that change a
    register, in execution order.
    For every instruction we will check the changed register value and the
    address, and will use the rest of the trace info for reference.

    This is a very ad-hoc debugging aid that will probably require tinkering
    with the test sources. It'll be covered by the test scripts, though.
    """

    fi = open(filename, "r")
    line_prev = None
    trace_list = []
    enable = False
    for line in fi.readlines():
        if line.find("->") > 0:
            match = RE_TRACECHANGE.match(line)
            if match:
                reg_name = match.group(1)
                reg_pre = int(match.group(2), 16)
                reg_post = int(match.group(3), 16)

                reg_ix = None if not reg_name in m5cpu.RIX else m5cpu.RIX[reg_name]
                if reg_ix == None: continue

                (addr, instruction, asm) = (0xffffffff, 0x0, "???")

                if line_prev:
                    match = RE_TRACE.match(line_prev)
                    if match:
                        addr = int(match.group(1), 16)
                        instruction = int(match.group(2), 16)
                        asm = match.group(3)
                        if addr == 0x80000108: enable = True

                tp = TracePoint(reg_ix, reg_pre, reg_post, addr, instruction, asm)

                if enable:
                    trace_list.append(tp)

        line_prev = line

    fi.close()
    return trace_list



#~~~~ Command Line Interface ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


def _parse_cmdline():

    parser = argparse.ArgumentParser(
        description='Simulator for micro5 risc-v core',
        epilog="See README.md for a longer description.")

    parser.add_argument('elf', metavar="ELF-FILE", type=str,
        help="Executable (elf) file")
    parser.add_argument('--rom-addr', metavar="ADDR",
        help="base address of ROM area. Defaults to 0x%08x" % (m5soc.DEFAULT_ROM_ADDR),
        type=lambda x: int(x,0), default=m5soc.DEFAULT_ROM_ADDR)
    parser.add_argument('--rom-size', metavar="NUM",
        help="size of ROM area in 32-bit words. Defaults to %d KB" % (m5soc.DEFAULT_ROM_WORDS/256),
        type=lambda x: int(x,0), default=m5soc.DEFAULT_ROM_WORDS)
    parser.add_argument('--ram-addr', metavar="ADDR",
        help="base address of RAM area. Defaults to 0x%08x" % (m5soc.DEFAULT_RAM_ADDR),
        type=lambda x: int(x,0), default=m5soc.DEFAULT_ROM_ADDR)
    parser.add_argument('--ram-size', metavar="NUM",
        help="size of RAM area in 32-bit words. Defaults to %d KB" % (m5soc.DEFAULT_RAM_WORDS/256),
        type=lambda x: int(x,0), default=m5soc.DEFAULT_RAM_WORDS)
    parser.add_argument('--reset-addr', metavar="ADDR",
        help="reset address. Defaults to 0x%08x." % (m5cpu.ADDR_RESET),
        type=lambda x: int(x,0), default=m5cpu.ADDR_RESET)
    parser.add_argument('--trap-addr', metavar="ADDR",
        help="trap address. Defaults to 0x%08x" % (m5cpu.ADDR_TRAP),
        type=lambda x: int(x,0), default=m5cpu.ADDR_TRAP)
    parser.add_argument('--timer-period', metavar="NUM",
        help="hardwired period of timer in clock cycles. Defaults to %d" % (m5soc.DEFAULT_TIMER_PERIOD),
        type=lambda x: int(x,0), default=m5soc.DEFAULT_TIMER_PERIOD)
    parser.add_argument('--num-inst', metavar="NUM",
        help="maximum number of instructions to execute. Defaults to unlimited",
        type=lambda x: int(x,0), default=None)
    parser.add_argument('--rom-writeable', action="store_true",
        help="make ROM area writeable (effectively a second RAM area). Defaults to False",
        default=False)
    parser.add_argument('--reg-trace', type=str, metavar='FILE',
        help="output a log of register changes",
        default=None)
    parser.add_argument('--asm-trace', type=str, metavar='FILE',
        help="output a trace of executed instructions (disassembly plus register changes)",
        default=None)
    parser.add_argument('--quit-if-idle', action="store_true",
        help="terminate simulation if instruction 'custom-idle' is executed. Defaults to False",
        default=False)
    parser.add_argument('--ovpsim-trace', metavar='FILE',
        help="check against a riscvOVPsim trace (trace+traceregs)",
        default=None)
    parser.add_argument('--trace-start', metavar="ADDR",
        help="trace enabled after fetching form this address. Default to no trace",
        type=lambda x: int(x,0), default=None)
    parser.add_argument('--sig-ref', metavar='FILE',
        help="check signature against reference",
        default=None)

    args = parser.parse_args()

    return args


def main():
    """Entry point when installed as package."""
    try:
        opts = _parse_cmdline()

        case_name = os.path.basename(opts.elf).split(".")[0]

        try:
            if opts.ovpsim_trace:
                trace_list = _read_ovp_trace(opts.ovpsim_trace)
            else:
                trace_list = None
        except IOError as e:
            _error(case_name, "Trouble reading ovp trace file: " + str(e), posix.EX_IOERR)

        rom = [0] * opts.rom_size
        ram = [0] * opts.ram_size

        soc = m5soc.SoC(rom, ram)
        soc.init()

        soc.rom_writeable = opts.rom_writeable
        soc.trace_list = trace_list
        soc.trace_start_addr = opts.trace_start
        soc.rom_bot = opts.rom_addr
        soc.ram_bot = opts.ram_addr
        soc.timer_period = opts.timer_period
        soc.cpu.reset_addr = opts.reset_addr
        soc.cpu.trap_addr = opts.trap_addr
        soc.cpu.quit_if_idle = opts.quit_if_idle

        try:
            if opts.sig_ref:
                fi = open(opts.sig_ref, "r")
                soc.signature_reference = fi.readlines()
                fi.close()
        except IOError as e:
            _error(case_name, "Trouble reading signature reference file: " + str(e), posix.EX_IOERR)

        try:
            if not soc.read_elf(opts.elf):
                _error(case_name, "No executable instructions at reset address", EX_NOEXEC_AT_RESET)
        except IOError as e:
            _error(case_name, "Trouble reading elf file: " + str(e), posix.EX_IOERR)
        except m5soc.SoCELFError as e:
            _error(case_name, str(e), posix.EX_IOERR)

        if opts.reg_trace:
            soc.delta_log_file = open(opts.reg_trace, "w")
        if opts.asm_trace:
            soc.asm_log_file = open(opts.asm_trace, "w")

        try:
            soc.reset()
            soc.run(opts.num_inst)
        except m5cpu.CPUUnimplemented as e:
            _error(case_name, str(e), EX_UNIMPLEMENTED)
        except m5cpu.CPUTraceMismatch as e:
            _error(case_name, str(e), EX_TRACE_MISMATCH)
        except m5soc.SoCQuitSigMismatch as e:
            _error(case_name, str(e), EX_SIG_MISMATCH)
        except (m5soc.SoCQuit, m5cpu.CPUIdle) as e:
            _quit(case_name, str(e), posix.EX_OK)

    except KeyboardInterrupt:
        print
        _error(case_name, "Terminated by user", EX_PROGRAM_TERMINATED)


def _error(case_name, msg, ecode):
    print "ERROR (%s):  %s" % (case_name, msg)
    sys.exit(ecode)

def _quit(case_name, msg, ecode):
    print "QUIT  (%s):  %s" % (case_name, msg)
    sys.exit(ecode)


if __name__ == "__main__":
    """Entry point when run as plain script (development only)."""
    main()
    print
    _quit(case_name, "Normal termination", posix.EX_OK)


    
