# micro5sim
Golden-model simulator for micro5 RISC-V core.

This Python package is near-cycle-accurate simulator for my RISC-V soft CPU core, [micro5](https://github.com/jaruiz/micro5).

It is meant to be used as a golden model in the development of the synthesizable core. And more importantly it'll help me make sure I understand in precise detail the ISA subset to be implemented and will be (has already been) a valuable aid in [porting the Zephyr OS](https://github.com/jaruiz/zephyr/tree/v1.13-branch) to this core.

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

I have made [a crude port of the Zephyr OS](https://github.com/jaruiz/zephyr/tree/v1.13-branch) for this `micro5` core. You can give it a try and run a few code samples on `micro5sim`. I will assume your system satisfies [all the dependencies listed in the Zephyr documentation](https://docs.zephyrproject.org/latest/getting_started/getting_started.html). 

_TODO: document the port in the zephyr fork readme_

As you can see, the port is based on branch `v1.13-branch` of the main repo. 
So, in order to run the Zephyr samples, you'll need to clone my Zephyr fork, checkout the branch, install `micro5sim` and then build and run the samples in question. Let's do it step by step from scratch:

```bash
# (I assume you have all the dependencies you need to work with Zephyr.)

# Clone my Zephyr fork, checking out the right branch:
git clone -b v1.13-branch https://github.com/jaruiz/zephyr

# Install micro5sim in a virtual environment:
virtualenv ve
source ve/bin/activate
pip install git+git://github.com/jaruiz/micro5sim.git

# Go into the zephr dir and prepare your environment.
cd zepyhr
source zephyr-env.sh

# Ok, ready to config and build samples.
# Let's say we want to try the basic/threads sample:
cd zephyr/samples/basic/threads

# (All of this is explained in the Zephyr docs).
# Create the build directory...
mkdir -p build/m5
cd build/m5
# ...configure the build...
cmake -DBOARD=ice40up5k_micro5 ../..
# ...and do the actual build using make.
make

# The executable code should be in ./zephyr/zephyr.elf. 
# Let's run it on micro5sim:
micro5sim --rom-writeable --rom-addr=0x0 --reset-addr=0 --trap-addr=4 zephyr/zephyr.elf
```

That'll launch the `basic/threads` sample on `micro5sim`. You should see this output...

```
Read object file 'zephyr/zephyr.elf'
Sections loaded:
  Area          Section                   Address     MemSize   
  ROM           vector                    0x00000000  0x00000008
  ROM           reset                     0x00000008  0x00000004
  ROM           exceptions                0x0000000c  0x00000254
  ROM           text                      0x00000260  0x0000321c
  ROM           devconfig                 0x00010000  0x0000003c
  ROM           rodata                    0x0001003c  0x00000928
  ROM           initlevel                 0x00010964  0x0000003c
  ROM           _static_thread_area       0x000109a0  0x00000084
  ROM           _k_mem_pool_area          0x00010a24  0x0000001c
  ROM           _k_queue_area             0x00010a40  0x00000010
  ROM           datas                     0x00010a50  0x00000014
  ROM           bss                       0x00010a68  0x000003a8
  ROM           noinit                    0x00010e10  0x00001a00
***** Booting Zephyr OS zephyr-v1.13.0-5-g3a33097 *****
Toggle USR0 LED: Counter = 0
Toggle USR1 LED: Counter = 0
Toggle USR0 LED: Counter = 1
Toggle USR0 LED: Counter = 2
Toggle USR0 LED: Counter = 3
Toggle USR0 LED: Counter = 4
^C
ERROR (zephyr):  Terminated by user
```

...assuming you `CTRL+C` the run after a while.

As you can see, we just used a single block of memory called `ROM` to contain all the executable and its data. This is certainly not realistic.

Eventually the simulator will be able to load a rom-able binary (as opposed to an elf file) and I will refine the memory map to reflect the actual hardware. But for the time being this is enough to get the ball rolling.

So far, only the following code samples have been tried at all:

1. `basic/thread`
2. `philosophers`
3. `synchronization`
4. `hello_world`

They appear to do something reasonable and where possible I have compared the output with a `qemu_riscv32` run and it roughly matches. This is only a crude start, though.

Also, be aware the this project is totally Linux-centric: I can't test any of this on a different platform, so you may enconter trouble running the samples on Windows, etc.

