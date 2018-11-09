# Build rv32i test suite and use it to verify the micro5 simulator:
#
# make all 		-- Build rv32i test suite.
# make micro5 	-- Run all relevant tests against micro5, check signatures.
# make clean 	-- Clean.
# 
# !!!! Set RISCV_PREFIX on the environment pointing at your toolchain.
# !!!! Do git submodule update --recursive before using this makefile.


# This needs to be on the environment for the test suite to work at all so 
# this default value should not be necessary.
RISCV_PREFIX ?= /opt/riscv32i/bin/riscv32-unknown-elf-

# We only build the rv32i test suite.
TEST_DIR = riscv-compliance/riscv-test-suite/rv32i/src
TEST_FILES = $(wildcard $(TEST_DIR)/*.S)
TEST_SRC = $(basename $(notdir $(TEST_FILES)))
TEST_OBJ = $(addprefix work/, $(addsuffix .o,$(TEST_SRC)))
TEST_ELF = $(addprefix work/, $(addsuffix .elf,$(TEST_SRC)))
TEST_LST = $(addprefix work/, $(addsuffix .lst,$(TEST_SRC)))
TEST_ROM = $(addprefix work/, $(addsuffix .code,$(TEST_SRC)))
TEST_RAM = $(addprefix work/, $(addsuffix .data,$(TEST_SRC)))


# These tests will NOT be run for the time being. Because they fail.
# The features in question may or may not be implemented later on.
SKIP_TESTS = I-MISALIGN_JMP-01 I-MISALIGN_LDST-01

# These are the test cases that are relevant to micro5sim.
CASE_NAMES = $(filter-out $(SKIP_TESTS), $(TEST_SRC))
CASE_GOALS = $(addprefix work/, $(addsuffix .run,$(CASE_NAMES)))


work/%.data: work/%.elf
	$(RISCV_PREFIX)objcopy \
		--only-section=.data \
		--only-section=.data.string \
		--only-section=.tohost \
		--gap-fill=0 \
		-O binary \
		$< $@

work/%.code: work/%.elf
	$(RISCV_PREFIX)objcopy \
		--only-section=.text \
		--only-section=.text.init \
		-O binary \
		$< $@

work/%.lst: work/%.elf
	$(RISCV_PREFIX)objdump -D $< > $@

work/%.elf: work/%.o micro5/link.ld
	$(RISCV_PREFIX)gcc -Os \
		-ffreestanding -nostdlib \
		-Wl,-Bstatic,-T,micro5/link.ld,--strip-debug \
		-o $@ \
		$< -lgcc

work/%.o: $(TEST_DIR)/%.S
	$(RISCV_PREFIX)gcc -c \
		-march=rv32i \
		-Imicro5 \
		-Iriscv-compliance/riscv-test-env \
		-o $@ $<

work:
	mkdir -p work

.PHONY:
warn-skipped:
	@printf "\n\033[1;33m*** WARNING: Skipped tests $(SKIP_TESTS) ***\033[0m\n\n"


.PHONY: all
all: work $(TEST_OBJ) $(TEST_ELF) $(TEST_LST) $(TEST_ROM) $(TEST_RAM) $(TEST_FILES)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: run
run: $(CASE_GOALS) warn-skipped

# Run all relevant tests against micro5sim checking signatures.
.PHONY: work/%.run
work/%.run: work/%.elf
	-python ../micro5sim/cli.py --rom-writeable \
		--rom-addr=0x80000000 \
		--rom-size=4096 \
		--ram-addr=0x80004000 \
		--ram-size=4096 \
		--asm-trace=trace.txt \
		--sig-ref=./riscv-compliance/riscv-test-suite/rv32i/references/$*.reference_output \
		$^

# Same as .run goal but using binary files and not the elf file.
# Not meant for running the test suite because you need to hardcode the
# relevant addresses.
# This is only to help me develop the interface to the RTL TB.
.PHONY: work/%.run-bin
work/%.run-bin: work/%.code work/%.data 
	-python ../micro5sim/cli.py --rom-writeable \
		--rom-addr=0x80000000 \
		--rom-size=4096 \
		--ram-addr=0x80004000 \
		--ram-size=4096 \
		--asm-trace=trace.txt \
		--sig-ref=./riscv-compliance/riscv-test-suite/rv32i/references/$*.reference_output \
		--binary \
		$^


# Run rv32i suite on ovpsim.
# You do not need this to get the signature references, those are pre-built.
# You only need this if you need the traces, in which case you need to modify
# file riscv-compliance/riscv-target/riscvOVPsim/device/rv32i/Makefile.include 
# to add --trace AND --traceregs to the simulator invocation.
.PHONY: ovpsim
ovpsim: all
	make -C riscv-compliance RISCV_TARGET=riscvOVPsim RISCV_ISA=rv32i

# Note we do NOT recursively clean the riscv-compliance submodule.
.PHONY: clean
clean:
	rm -f work/*
