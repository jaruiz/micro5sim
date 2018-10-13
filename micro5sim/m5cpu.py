#!/usr/bin/env python

import argparse
import sys


ADDR_RESET =    0x00000000
ADDR_TRAP =     0x00000010


OPCODES = {
    0b1101111: ("_format_j", "_op_jal"),
    0b1100111: ("_format_i", "_op_jalr"),
    0b0110111: ("_format_u", "_op_lui"),
    0b0010011: ("_format_i", "_op_imm"),
    0b0110011: ("_format_r", "_op_reg"),
    0b0000011: ("_format_i", "_op_load"),
    0b0100011: ("_format_s", "_op_store"),
    0b1110011: ("_format_i", "_op_env"),
    0b1100011: ("_format_b", "_op_branch"),
    0b0010111: ("_format_u", "_op_auipc"),
    0b0001111: ("_format_i", "_op_fence"),
}

ALU_OPS = {
    0b0000000000:  ("add", "_op_add",),
    0b0100000000:  ("sub", "_op_sub",),
    0b0000000001:  ("sll", "_op_sll",),
    0b0000000010:  ("slt", "_op_slt",),
    0b0000000011:  ("sltu", "_op_sltu",),
    0b0000000100:  ("xor", "_op_xor",),
    0b0000000101:  ("srl", "_op_srl",),
    0b0100000101:  ("sra", "_op_sra",),
    0b0000000110:  ("or", "_op_or",),
    0b0000000111:  ("and", "_op_and",),
}

LOAD_OPS = {
    0b000:  ("lb", "_op_lb",),
    0b001:  ("lh", "_op_lh",),
    0b010:  ("lw", "_op_lw",),
    0b100:  ("lbu", "_op_lbu",),
    0b101:  ("lhu", "_op_lhu",),
}

STORE_OPS = {
    0b000:  ("sb", "_op_sb",),
    0b001:  ("sh", "_op_sh",),
    0b010:  ("sw", "_op_sw",),
}

BRANCH_OPS = {
    0b000:  ("beq", "_op_beq",),
    0b001:  ("bne", "_op_bne",),
    0b100:  ("blt", "_op_blt",),
    0b101:  ("bge", "_op_bge",),
    0b110:  ("bltu", "_op_bltu",),
    0b111:  ("bgeu", "_op_bgeu",),
}

ENV_OPS = {
    0b000:  ("csrrw", "_op_etrap",),
    0b001:  ("csrrw", "_op_csrrw",),
    0b010:  ("csrrw", "_op_csrrs",),
    0b101:  ("csrrw", "_op_csrrwi",),
}

RN = [
    "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
    "fp",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
    "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
    "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6" 
    ]

CSR_MSTATUS =   0x300
CSR_MEPC =      0x341
CSR_MCAUSE =    0x342
CSR_MIP =       0x344

CSR = {
    CSR_MSTATUS: 0,
    CSR_MEPC: 0,
    CSR_MCAUSE: 0,
    CSR_MIP: 0
}






class CPU(object):

    def __init__(self, load, store, delta, log_asm):
        self.PC = ADDR_RESET
        self.PC_next = ADDR_RESET
        self._load = load
        self._store = store
        self._log_delta = delta
        self._log_asm = log_asm
        self._rbank = [0] * 32
        self._imm = 0
        self._rd = 0
        self._rs1 = 0
        self._rs2 = 0
        self._func3 = 0
        self._func7 = 0
        self._asm = "???"


    def reset(self):
        self.PC = ADDR_RESET


    def run(self, num=None):

        while num == None or num > 0:
            if num: num -= 1
            instruction = self._fetch()
            self._decode_execute(instruction)
            self._log_asm(self._build_asm(instruction))
            self.PC = self.PC_next


    def _build_asm(self, instruction):
        return "[0x%08x] %08x    %s" % (self.PC, instruction, self._asm)


    def _fetch(self):
        instruction = self._load(self.PC, space='c')
        self.PC_next = self.PC + 4
        return instruction


    def _decode_execute(self, instruction):
        self._opcode = instruction & 0x7f
        if not self._opcode in OPCODES:
            self._unimplemented_opcode()

        # Invoke decode function, leaving the fields in 'self'...
        getattr(self, OPCODES[self._opcode][0])(instruction)
        # ...and then invoke the execute function.
        getattr(self, OPCODES[self._opcode][1])()


    def _get_bitfield(self, word, pieces, sext=None):
        field = 0
        for piece in pieces:
            fragment = (word >> piece[1]) & piece[2]
            field = field | (fragment << piece[0])
        if sext:
            if ((field >> sext) & 0x1) != 0:
                field = (field | (0xffffffff << sext)) & 0xffffffff

        return field


    def _twos_comp(self, word):
        if (word & (1 << (32 - 1))) != 0:   # If sign bit is set...
            word = word - (1 << 32)         # ...compute negative value.
        return word


    def _unimplemented_func3(self):
        print "[0x{0:08x}] UNIMPLEMENTED IMM FUNC3 {1:03b} WITH OPCODE {2:07b}".format(self.PC, self._func3, self._opcode)
        sys.exit(0)


    def _unimplemented_func73(self):
        print "[0x{0:08x}] UNIMPLEMENTED IMM FUNC7+FUNC3 {1:07b}::{2:03b} WITH OPCODE {3:07b}".format(self.PC, self._func7, self._func3, self._opcode)
        sys.exit(0)        


    def _unimplemented_csr(self, csr):
        print "[0x{0:08x}] UNIMPLEMENTED CSR 0x{1:03x}".format(self.PC, csr)
        sys.exit(0)


    def _unimplemented_opcode(self):
        print "[0x{0:08x}] UNIMPLEMENTED OPCODE {1:07b}".format(self.PC, self._opcode)
        sys.exit(0)


    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _write_csr(self, csr, value):
        if csr in CSR:
            # FIXME hook side effects
            CSR[csr] = value
        else:
            self._unimplemented_csr(csr)


    def _read_csr(self, csr):
        if csr in CSR:
            # FIXME hook side effects
            return CSR[csr]
        else:
            self._unimplemented_csr(csr)


    def _writeback(self, rd, value):
        if rd: 
            value = value & 0xffffffff
            self._rbank[rd] = value
            self._log_delta(self.PC, rd, value)


    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _format_j(self, instruction):
        imm_pieces = ((12, 12, 0xff), (11, 20, 0x1), (1, 21, 0x3ff), (20, 31, 0x1))
        self._imm = self._get_bitfield(instruction, imm_pieces, sext=20)
        self._rd = self._get_bitfield(instruction, [(0, 7, 0x1f)])


    def _format_u(self, instruction):
        imm_pieces = [(12, 12, 0xfffff)]
        self._imm = self._get_bitfield(instruction, imm_pieces)
        self._rd = self._get_bitfield(instruction, [(0, 7, 0x1f)])
        self._rs1 = self._get_bitfield(instruction, [(0, 15, 0x1f)])


    def _format_i(self, instruction):
        imm_pieces = [(0, 20, 0xfff)]
        self._imm = self._get_bitfield(instruction, imm_pieces, sext=11)
        self._rd = self._get_bitfield(instruction, [(0, 7, 0x1f)])
        self._rs1 = self._get_bitfield(instruction, [(0, 15, 0x1f)])
        self._func3 = self._get_bitfield(instruction, [(0, 12, 0x7)])
        # func7 only exists in shift immediate instructions.
        self._func7 = self._get_bitfield(instruction, [(0, 25, 0x7f)])


    def _format_s(self, instruction):
        imm_pieces = [(5, 25, 0x7f), (0, 7, 0x1f)]
        self._imm = self._get_bitfield(instruction, imm_pieces, sext=11)
        self._rs1 = self._get_bitfield(instruction, [(0, 15, 0x1f)])
        self._rs2 = self._get_bitfield(instruction, [(0, 20, 0x1f)])
        self._func3 = self._get_bitfield(instruction, [(0, 12, 0x7)])


    def _format_b(self, instruction):
        imm_pieces = [(12, 31, 0x1), (5, 25, 0x7f), (1, 8, 0xf), (11, 7, 0x1)]
        self._imm = self._get_bitfield(instruction, imm_pieces, sext=12)
        self._rs1 = self._get_bitfield(instruction, [(0, 15, 0x1f)])
        self._rs2 = self._get_bitfield(instruction, [(0, 20, 0x1f)])
        self._func3 = self._get_bitfield(instruction, [(0, 12, 0x7)])


    def _format_r(self, instruction):
        self._rd = self._get_bitfield(instruction, [(0, 7, 0x1f)])
        self._rs1 = self._get_bitfield(instruction, [(0, 15, 0x1f)])
        self._rs2 = self._get_bitfield(instruction, [(0, 20, 0x1f)])
        self._func3 = self._get_bitfield(instruction, [(0, 12, 0x7)])
        self._func7 = self._get_bitfield(instruction, [(0, 25, 0x7f)])

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _op_imm(self):
        if not self._func3 in ALU_OPS:
            self._unimplemented_func3()

        rs1 = self._rbank[self._rs1]
        (mnemo, function) = ALU_OPS[self._func3]
        res = getattr(self, function)(rs1, self._imm)
        self._writeback(self._rd, res)
        self._asm = "%si %s, %s, 0x%x" % (mnemo, RN[self._rd], RN[self._rs1], self._imm)


    def _op_reg(self):
        func = self._func3 + (self._func7 << 3)
        if not func in ALU_OPS:
            self._unimplemented_func73()

        rs1 = self._rbank[self._rs1]
        rs2 = self._rbank[self._rs2]
        
        (mnemo, function) = ALU_OPS[func]
        res = getattr(self, function)(rs1, rs2)
        self._writeback(self._rd, res)
        self._asm = "%s %s, %s, %s" % (mnemo, RN[self._rd], RN[self._rs1], RN[self._rs2])


    def _op_branch(self):
        if not self._func3 in BRANCH_OPS:
            self._unimplemented_func3()

        rs1 = self._rbank[self._rs1]
        rs2 = self._rbank[self._rs2]
        (mnemo, function) = BRANCH_OPS[self._func3]
        condition = getattr(self, function)(rs1, rs2)
        target = (self.PC + self._imm) & 0xffffffff
        if condition:
            self.PC_next = target
        self._asm = "%s %s, %s, 0x%x" % (mnemo, RN[self._rs1], RN[self._rs2], target)


    def _op_load(self):
        if not self._func3 in LOAD_OPS:
            self._unimplemented_func3()

        rs1 = self._rbank[self._rs1]
        (mnemo, function) = LOAD_OPS[self._func3]
        res = getattr(self, function)(rs1, self._imm)
        self._writeback(self._rd, res)
        self._asm = "%s %s, %d(%s)" % (mnemo, RN[self._rd], self._imm, RN[self._rs1])


    def _op_store(self):
        if not self._func3 in STORE_OPS:
            self._unimplemented_func3()

        rs1 = self._rbank[self._rs1]
        rs2 = self._rbank[self._rs2]
        (mnemo, function) = STORE_OPS[self._func3]
        res = getattr(self, function)(rs2, rs1, self._imm)
        self._asm = "%s %s, %d(%s)" % (mnemo, RN[self._rs2], self._imm, RN[self._rs1])


    def _op_env(self):
        if not self._func3 in ENV_OPS:
            self._unimplemented_func3()

        rs1 = self._rbank[self._rs1]
        (mnemo, function) = ENV_OPS[self._func3]
        res = getattr(self, function)(rs1, mnemo)
        

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



    def _op_beq(self, rs1, rs2):
        return rs1 == rs2


    def _op_bne(self, rs1, rs2):
        return rs1 != rs2


    def _op_blt(self, rs1, rs2):
        return self._twos_comp(rs1) < self._twos_comp(rs2)


    def _op_bge(self, rs1, rs2):
        return self._twos_comp(rs1) >= self._twos_comp(rs2)


    def _op_bltu(self, rs1, rs2):
        return rs1 < rs2


    def _op_bgeu(self, rs1, rs2):
        return rs1 >= rs2


    def _op_csrrw(self, rs1, mnemo):
        if self._rd:
            csr = self._read_csr(self._imm)
            self._writeback(self._rd, csr)
        self._write_csr(self._imm, rs1)
        self._asm = "%s %s, csr{%d}, %s" % (mnemo, RN[self._rd], self._imm, RN[self._rs1])


    def _op_csrrwi(self, rs1, mnemo):
        if self._rd:
            csr = self._read_csr(self._imm)
            self._writeback(self._rd, csr)

        value = self._rs1
        if ((value >> 5) & 0x1) != 0:
            value = (value | 0xffffffe0) & 0xffffffff
        self._write_csr(self._imm, value)
        self._asm = "%s %s, csr{%d}, 0x%x" % (mnemo, RN[self._rd], self._imm, value)


    def _op_csrrs(self, rs1, mnemo):
        csr = 0
        if self._rd:
            csr = self._read_csr(self._imm)
            self._writeback(self._rd, csr)
        self._write_csr(self._imm, csr | rs1) # FIXME writable mask
        self._asm = "%s %s, csr{%d}, %s" % (mnemo, RN[self._rd], self._imm, RN[self._rs1])


    def _op_etrap(self, rs1, mnemo):
        if self._func7 == 0b0000000:
            return self._op_ecall(rs1)
        elif self._func7 == 0b0100000:
            return self._op_ebreak(rs1)
        elif self._func7 == 0b0001000:
            return self._op_eret(rs1) # FIXME to be removed
        elif self._func7 == 0b0011000:
            return self._op_mret(rs1)
        else:
            self._unimplemented_func73()


    def _op_ecall(self, rs1):
        # FIXME check rs1, rd are zero
        self._do_trap(0x00)
        self._asm = "ecall %s" % (RN[self._rs1])


    def _op_ebreak(self, rs1):
        # FIXME check rs1, rd are zero
        self._do_trap(0x01)
        self._asm = "ebreak %s" % (RN[self._rs1])


    def _do_trap(self, cause):
        self._write_csr(CSR_MEPC, self.PC)
        self._write_csr(CSR_MCAUSE, cause)
        self.PC_next = ADDR_TRAP


    def _op_eret(self, rs1):
        # FIXME check rs1, rd are zero
        self.PC_next = self._read_csr(CSR_MEPC)
        self._asm = "eret %s" % (RN[self._rs1])

    def _op_mret(self, rs1):
        # FIXME check rs1, rd are zero, rs2==0x2
        self.PC_next = self._read_csr(CSR_MEPC)
        self._asm = "mret %s" % (RN[self._rs1])


    def _op_lui(self):
        self._writeback(self._rd, self._imm)
        self._asm = "lui %s, 0x%x" % (RN[self._rd], self._imm)


    def _op_auipc(self):
        self._writeback(self._rd, self.PC + self._imm)
        self._asm = "auipc %s, 0x%x" % (RN[self._rd], self._imm)


    def _op_fence(self):
        # Implemented as NOP.
        self._asm = "fence"


    def _op_jal(self):
        self._writeback(self._rd, self.PC_next)
        self.PC_next = (self.PC + self._imm) & 0xffffffff
        self._asm = "jal %s, 0x%x" % (RN[self._rd], self.PC_next)


    def _op_jalr(self):
        if self._func3 != 0:
            _unimplemented_func3()
        self._writeback(self._rd, self.PC_next)
        rs1 = self._rbank[self._rs1]
        self.PC_next = (rs1 + self._imm) & 0xfffffffe
        self._asm = "jalr %s, %s, 0x%x" % (RN[self._rd], RN[self._rs1], self._imm)


    def _op_lbu(self, a, b):
        address = (a + b) & 0xffffffff
        word = self._load(address)
        index = 8 * (address & 0x3)
        _byte = (word >> index) & 0xff
        return _byte

    def _op_lb(self, a, b):
        address = (a + b) & 0xffffffff
        word = self._load(address)
        index = 8 * (address & 0x3)
        _byte = (word >> index) & 0xff
        data = (_byte | 0xffffff00) if (_byte & 0x80) else _byte
        return data

    def _op_lhu(self, a, b):
        address = (a + b) & 0xffffffff
        word = self._load(address)
        index = 8 * (address & 0b10)
        halfword = (word >> index) & 0xffff
        return halfword


    def _op_lh(self, a, b):
        address = (a + b) & 0xffffffff
        word = self._load(address)
        index = 8 * (address & 0b10)
        halfword = (word >> index) & 0xffff
        #print "%08x  %08x %d %08x" % (self.PC, word, index, address)
        data = halfword | 0xffff0000 if (halfword & 0x8000) else halfword
        return data


    def _op_lw(self, a, b):
        address = (a + b) & 0xffffffff
        data = self._load(address)
        return data


    def _op_sw(self, rs2, rs1, imm):
        address = (rs1 + imm) & 0xffffffff
        self._store(address, rs2, 4)


    def _op_sh(self, rs2, rs1, imm):
        address = (rs1 + imm) & 0xffffffff
        self._store(address, rs2, 2)


    def _op_sb(self, rs2, rs1, imm):
        address = (rs1 + imm) & 0xffffffff
        self._store(address, rs2, 1)


    def _op_add(self, a, b):
        return a + b


    def _op_sub(self, a, b):
        return a - b


    def _op_sltu(self, a, b):
        return 1 if a < b else 0


    def _op_slt(self, a, b):
        return 1 if self._twos_comp(a) < self._twos_comp(b) else 0


    def _op_xor(self, a, b):
        return a ^ b


    def _op_or(self, a, b):
        return a | b


    def _op_and(self, a, b):
        return a & b


    def _op_sll(self, a, b):
        return a << (b & 0x1f)


    def _op_srl(self, a, b):
        if self._func7 == 0b0000000:
            return a >> (b & 0x1f)
        elif self._func7 == 0b0100000:
            return self._op_sra(a, b)
        else:
            self._unimplemented_func73()

    def _op_sra(self, a, b):
        semask = (0xffffffff00000000 >> (b & 0x1f)) if (a & 0x80000000) else 0
        return ((a >> (b & 0x1f)) | semask) & 0xffffffff
