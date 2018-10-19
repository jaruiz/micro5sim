# micro5sim
Golden-model simulator for micro5 RISC-V core.

This Python package is near-cycle-accurate simulator for my RISC-V soft CPU core, [micro5](https://github.com/jaruiz/micro5).

It is meant to be used as a golden model in the development of the synthesizable core. And more importantly it'll help me make sure I understand in precise detail the ISA subset to be implemented and will be (has already been) a valuable aid in [porting the Zephyr OS](https://github.com/jaruiz/zephyr) to this core.

If you are looking for a general purpose, fast, rock-solid RISC-V simulator you should maybe take a look at [Spike](https://github.com/riscv/riscv-isa-sim) or [riscvOVPsim](https://github.com/riscv/riscv-compliance/tree/master/riscv-ovpsim). 
But if you need an ISS that's dead simple and thus easy to tweak for your own core, this one may be a good starting point. Other than that, I don't think this package will be of any general interest.


## Status summary

The simulator is capable of passing 53 of the 55 test cases in the [rv32i test suite](https://github.com/riscv/riscv-compliance/tree/master/riscv-test-suite/rv32i). A port of the riscv-compliance is included in the repository [along with a makefile to drive the tests](#running-the-riscv-compliance-tests).

Timing details are mostly missing and the peripherals are only crude stubs, barely enough to [run a few Zephyr code samples](#running-zephyr-code-samples).

## Installation

You can install this package with _pip_ directly from this repository:

```bash
pip install git+git://github.com/jaruiz/micro5sim.git
```

The package installation will define a single script `micro5sim` whose usage is described below.

Of course you can also clone the repository and _pip_ or just run from your local copy. You should only do this if you want to tinker with the code or if you want to [run the included risv-compliance suite](#running-the-riscv-compliance-tests).


## Usage

This is the output of `micro5sim --help`:

```
usage: micro5sim [-h] [--rom-addr ADDR] [--rom-size NUM] [--ram-addr ADDR]
                 [--ram-size NUM] [--reset-addr ADDR] [--trap-addr ADDR]
                 [--timer-period NUM] [--num-inst NUM] [--rom-writeable]
                 [--reg-trace FILE] [--asm-trace FILE] [--quit-if-idle]
                 [--ovpsim-trace FILE] [--trace-start ADDR] [--sig-ref FILE]
                 ELF-FILE

Simulator for micro5 risc-v core

positional arguments:
  ELF-FILE             Executable (elf) file

optional arguments:
  -h, --help           show this help message and exit
  --rom-addr ADDR      base address of ROM area. Defaults to 0x80000000
  --rom-size NUM       size of ROM area in 32-bit words. Defaults to 4096 KB
  --ram-addr ADDR      base address of RAM area. Defaults to 0xc0000000
  --ram-size NUM       size of RAM area in 32-bit words. Defaults to 2048 KB
  --reset-addr ADDR    reset address. Defaults to 0x80000000.
  --trap-addr ADDR     trap address. Defaults to 0x80000004
  --timer-period NUM   hardwired period of timer in clock cycles. Defaults to
                       10000
  --num-inst NUM       maximum number of instructions to execute. Defaults to
                       unlimited
  --rom-writeable      make ROM area writeable (effectively a second RAM
                       area). Defaults to False
  --reg-trace FILE     output a log of register changes
  --asm-trace FILE     output a trace of executed instructions (disassembly
                       plus register changes)
  --quit-if-idle       terminate simulation if instruction 'custom-idle' is
                       executed. Defaults to False
  --ovpsim-trace FILE  check against a riscvOVPsim trace (trace+traceregs)
  --trace-start ADDR   trace enabled after fetching form this address. Default
                       to no trace
  --sig-ref FILE       check signature against reference

See README.md for a longer description.
```

I hope the help text is self-explanatory. You can find more information on the simulated HW and the trace files below.

Please note that the default addresses and in particular the memory sizes are not what will finally be implemented in hardware. The default values are just convenient to run the riscv-compliance suite. The Zephyr port assumes a different memory map -- see below.

## Simulated core & peripheral features

(TODO explain limitations of CPU model)
(TODO describe memory map, default and Zephyr)
(TODO describe peripherals)


## Trace files

(TODO add samples of trace files)

## Running the riscv-compliance tests

The repository includes the [riscv-compliance](https://github.com/riscv/riscv-compliance) repository as a submodule, along with the necessary support files and makefiles to run the tests on `micro5sim`.

The test driver makefile needs to have `micro5sim` installed as a Python package with _pip_. Assuming you already did that, these are step-by-step instructions to run the test suite from scratch:

```bash
# Clone the repo with its submodules:
git clone --recurse-submodules https://github.com/jaruiz/micro5sim.git
cd micro5sim

# Point RISCV_PREFIX at your riscv toolchain.
export RISCV_PREFIX=/opt/riscv32i/bin/riscv32-unknown-elf-

# Go into the test dir and build the whole test suite...
cd riscv-tests
make all
# ...then run all the rv32i tests (55 excluding any that are known to fail)
make run

```
The makefile will invoke `micro5sim` with the right arguments for each of the test cases. It will automatically compare the test signature against the pre-generated signature that comes with the `riscv-compliance` suite. The console output of the test cases is output straight to stdout, along with pass/fail messages.

Out of 55 tests, 53 are passing right now and 2 have been excluded -- you will see a warning at the end of the run.

For a quick sanity check you can just do this:

```bash
make run | egrep 'QUIT|ERROR'
```

That should give you a barrage of 53 lines like these:

```
QUIT  (I-ADD-01):  Signature MATCH
QUIT  (I-ADDI-01):  Signature MATCH
...
QUIT  (I-XOR-01):  Signature MATCH
QUIT  (I-XORI-01):  Signature MATCH
```

Unfortunately the makefile will not keep a tally of pass/fail states so you'll need to scan the output yourself for any sign of trouble.

### Excluded tests

The following tests have been explicitly excluded from the run because they check features that are not implemented:

```
I-MISALIGN_JMP-01    -- Misaligned jumps not yet simulated, will trigger trap as per spec.
I-MISALIGN_LDST-01   -- Misaligned load/stores not implemented, might end up relying on traps & SW.
```

Something will be done eventually about those. For the time being the makefile emits a warning message.


## Running Zephyr code samples

(TODO step-by-step instructions to be added)

