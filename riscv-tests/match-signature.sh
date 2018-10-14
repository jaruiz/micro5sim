#! /bin/bash
python ../micro5sim/cli.py --rom-writeable \
    --sig-ref=./riscv-compliance/riscv-test-suite/rv32i/references/$1.reference_output \
    ./work/$1.elf
