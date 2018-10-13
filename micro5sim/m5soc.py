#!/usr/bin/env python

import argparse
import sys

import m5cpu


DEFAULT_ROM_ADDR =  0x00000000
DEFAULT_RAM_ADDR =  0x40000000



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

    def reset(self):
        self.cpu.reset()


    def run(self, num=None):
        self.cpu.run(num)

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
            self.rom[windex - self.rom_bot] = word
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
