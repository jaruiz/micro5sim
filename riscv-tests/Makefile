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

# We only care about the rv32i test suite.
# FIXME exclude all uneeded tests from the suite.
TEST_DIR = riscv-compliance/riscv-test-suite/rv32i/src
TEST_FILES = $(wildcard $(TEST_DIR)/*.S)
TEST_SRC = $(basename $(notdir $(TEST_FILES)))
TEST_OBJ = $(addprefix work/, $(addsuffix .o,$(TEST_SRC)))
TEST_ELF = $(addprefix work/, $(addsuffix .elf,$(TEST_SRC)))
TEST_LST = $(addprefix work/, $(addsuffix .lst,$(TEST_SRC)))


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

.PHONY: all
all: work $(TEST_OBJ) $(TEST_ELF) $(TEST_LST) $(TEST_FILES)


CASE_NAMES = $(TEST_SRC)
CASE_LOGS = $(addprefix work/, $(addsuffix .log,$(CASE_NAMES)))

run: $(CASE_LOGS)

work/%.log: work/%.elf
	python ../micro5sim/cli.py --rom-writeable \
		--sig-ref=./riscv-compliance/riscv-test-suite/rv32i/references/$*.reference_output \
		$<





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
