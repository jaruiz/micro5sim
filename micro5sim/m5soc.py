#!/usr/bin/env python

import argparse
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS

import m5cpu


DEFAULT_ROM_ADDR =  0x80000000
DEFAULT_ROM_WORDS = 1024*1024
DEFAULT_RAM_ADDR =  0xc0000000
DEFAULT_RAM_WORDS = 512*1024


SYMBOL_INTERCEPT_FETCH_CALLBACKS = {
    'write_tohost': "_intercept_write_tohost",
    'write_to_host': "_intercept_write_tohost",
}

SYMBOL_INTERCEPT_FETCH = {}

SYMBOL_VALUE = {
    'begin_signature': None,
    'end_signature': None
}


class SoCError(Exception):
    def __init__(self, msg):
        super(SoCError, self).__init__(msg)

class SoCELFError(SoCError):
    """Something is wrong in the elf file other than an IOError."""
    def __init__(self, msg):
        super(SoCError, self).__init__(msg)

class SoCQuit(SoCError):
    """Program hit any of the normal or abnormal termination conditions."""
    def __init__(self, msg):
        super(SoCError, self).__init__(msg)

class SoCQuitSigMatch(SoCQuit):
    """Program Quit, signature match."""
    def __init__(self, msg):
        super(SoCError, self).__init__(msg)

class SoCQuitSigMismatch(SoCQuit):
    """Program Quit, signature mismatch."""
    def __init__(self, msg):
        super(SoCError, self).__init__(msg)


class SoC(object):

    def __init__(self, rom=None, ram=None):
        self.rom = rom
        self.ram = ram
        self.rom_bot = DEFAULT_ROM_ADDR
        self.rom_top = DEFAULT_ROM_ADDR + DEFAULT_ROM_WORDS
        self.ram_bot = DEFAULT_RAM_ADDR
        self.ram_top = DEFAULT_RAM_ADDR + DEFAULT_RAM_WORDS
        self.cpu = m5cpu.CPU(self._load, self._store, self._log_delta, self._log_asm)
        self.delta_log_file = None
        self.asm_log_file = None
        self.rom_writeable = False
        self.trace_list = None
        self.signature_reference = None

    def reset(self):
        self.cpu.trace_list = self.trace_list
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
            May raise IOError.
        """

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

            # There's a number of symbol values we want to know. Watch out
            # for tymbol tables and extract them.
            if section['sh_type'] == 'SHT_SYMTAB':
                for symbol in section.iter_symbols():
                    if symbol.name in SYMBOL_INTERCEPT_FETCH_CALLBACKS:
                        callback = SYMBOL_INTERCEPT_FETCH_CALLBACKS[symbol.name]
                        SYMBOL_INTERCEPT_FETCH[symbol.entry['st_value']] = callback
                    if symbol.name in SYMBOL_VALUE:
                        SYMBOL_VALUE[symbol.name] = symbol.entry['st_value']


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
                    msg = "Error: Section '%s' in ROM area is writeable" % (section.name)
                    raise SoCELFError(msg)

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

        return executable_stuff_at_reset_addr


    def _load(self, addr, space='d'):
        if space == 'c' and  addr in SYMBOL_INTERCEPT_FETCH:
            getattr(self, SYMBOL_INTERCEPT_FETCH[addr])()

        if self.rom_bot <= addr < self.rom_top:
            #print "<%08x, %08x, %08x>" % (addr, self.rom_bot, self.rom[0])
            return self.rom[(addr - self.rom_bot)/4]
        elif self.ram_bot <= addr < self.ram_top:
            return self.ram[(addr - self.ram_bot)/4]
        else:
            return 0x42000000


    def _store(self, addr, value, lanes=4):
        masks = [0xff, 0xff, 0xffff, 0xffff, 0xffffffff]
        windex = addr / 4
        bindex = (addr % 4) if lanes == 1 else addr & 0b10 if lanes == 2 else 0
        mask = masks[lanes] << (bindex * 8)
        value = (value << (bindex * 8)) & mask

        if self.rom_bot <= addr < self.rom_top:
            word = self.rom[(addr - self.rom_bot)/4]
            word = (word & ~mask) | value
            if self.rom_writeable:
                self.rom[(addr - self.rom_bot)/4] = word
            else:
                # Storing to read-only ROM area. Ignore.
                print "[0x%08x] warning: writing to read-only address 0x%08x" % (self.PC, addr)

        elif self.ram_bot <= addr < self.ram_top:
            word = self.ram[(addr - self.ram_bot)/4]
            word = (word & ~mask) | value
            self.ram[(addr - self.ram_bot)/4] = word
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
            mem[j + offset/4] = word


    def _intercept_write_tohost(self):
        """Generate signature file."""

        if self.signature_reference:
            sig_ref = self._compute_signature()
            
            if sig_ref != None:
                if len(sig_ref) != len(self.signature_reference):
                    raise SoCQuitSigMismatch("Signature area boundary MISMATCH")

                for i in range(len(sig_ref)):
                    r0 = sig_ref[i].strip().lower()
                    r1 = self.signature_reference[i].strip().lower()
                    if r0 != r1:
                        raise SoCQuitSigMismatch("Signature MISMATCH")

                raise SoCQuitSigMatch("Signature MATCH")

            else:
                # This will have raised an exception by now but just in case.
                raise SoCQuitSigMismatch("Could not compute signature")
    
        # Intercepted write_tohost but no signature ref on cmd line.
        raise SoCQuit("No signature reference supplied")


    def _compute_signature(self):
        sig_bot = SYMBOL_VALUE['begin_signature']
        sig_top = SYMBOL_VALUE['end_signature']

        sig_ref = None

        if sig_top == None:
            raise SoCQuitSigMismatch("Can't build signature file: missing symbol 'begin_signature'")
        elif sig_bot == None:
            raise SoCQuitSigMismatch("Can't build signature file: missing symbol 'end_signature'")
        elif sig_bot > sig_top:
            raise SoCQuitSigMismatch("Can't build signature file: begin and end symbols reversed")
        else:
            # Area seems legit. Compute signature as list of ascii lines.
            print "Computing signature for area [0x%08x .. 0x%08x]" % (sig_bot, sig_top)
            sig_ref = []
            num_lines = (sig_top - sig_bot) / 16
            for line in range(num_lines):
                trc = []
                for wi in range(4):
                    address = sig_bot + (line * 16) + ((3 - wi) * 4)
                    w = self._load(address)
                    trc.append("%08x" % w)
                sig_ref.append("".join(trc))

        return sig_ref
