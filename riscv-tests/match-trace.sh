#! /bin/bash
python ../micro5sim/cli.py --rom-writeable \
    --sig-ref=./riscv-compliance/riscv-test-suite/rv32i/references/$1.reference_output \
    --ovpsim-trace=./riscv-compliance/work/$1.out32 \
    --trace-start=0x80000108 \
    ./work/$1.elf
