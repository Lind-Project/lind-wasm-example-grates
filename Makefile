# Top-level Makefile for lind-wasm-example-grates
#
# Usage:
#   make test                    # run full test suite
#   make test GRATE=geteuid-grate  # run one grate's tests
#   make list                    # list available grates
#   make c/<name>                # build a C grate
#   make rust/<name>             # build a Rust grate
#   make all                     # build all grates
#   make clean                   # remove build artifacts

SHELL := /bin/bash

GRATES_DIR := grates

# All grate directories
C_GRATES := $(shell find $(GRATES_DIR)/c -name "compile_grate.sh" -exec dirname {} \; 2>/dev/null | sort)
RUST_GRATES := $(shell find $(GRATES_DIR)/rust -name "Cargo.toml" -not -path "*/target/*" -exec dirname {} \; 2>/dev/null | sort)
ALL_GRATES := $(sort $(C_GRATES) $(RUST_GRATES))

# Targets use type/name format to avoid collisions (e.g. c/strace-grate, rust/strace-grate)
C_TARGETS := $(patsubst $(GRATES_DIR)/%,%,$(C_GRATES))
RUST_TARGETS := $(patsubst $(GRATES_DIR)/%,%,$(RUST_GRATES))
ALL_TARGETS := $(C_TARGETS) $(RUST_TARGETS)

.PHONY: all test list clean help $(ALL_TARGETS)

help:
	@echo "Usage:"
	@echo "  make test                      Run full test suite"
	@echo "  make test GRATE=<name>         Run tests for one grate"
	@echo "  make list                      List available grates"
	@echo "  make c/<grate-name>            Build a C grate"
	@echo "  make rust/<grate-name>         Build a Rust grate"
	@echo "  make all                       Build all grates"
	@echo "  make clean                     Remove build artifacts"
	@echo ""
	@echo "Available grates:"
	@for g in $(ALL_TARGETS); do echo "  $$g"; done

all: $(ALL_TARGETS)

# Build individual grates
define build_grate
$(patsubst $(GRATES_DIR)/%,%,$(1)):
	@echo "Building $(patsubst $(GRATES_DIR)/%,%,$(1))..."
	@if [ -f "$(1)/compile_grate.sh" ]; then \
		cd "$(1)" && bash compile_grate.sh; \
	elif [ -f "$(1)/Cargo.toml" ]; then \
		cd "$(1)" && cargo lind_compile; \
	else \
		echo "ERROR: No build file for $(1)"; exit 1; \
	fi
endef

$(foreach g,$(ALL_GRATES),$(eval $(call build_grate,$(g))))

# Test suite
test:
ifdef GRATE
	@./test/run_tests.sh "$(GRATE)"
else
	@./test/run_tests.sh
endif

list:
	@./test/run_tests.sh --list

# Clean
clean:
	@echo "Cleaning Rust grate targets..."
	@for g in $(RUST_GRATES); do \
		if [ -d "$$g/target" ]; then \
			echo "  $$g"; \
			(cd "$$g" && cargo clean 2>/dev/null); \
		fi; \
	done
	@echo "Cleaning C grate outputs..."
	@for g in $(C_GRATES); do \
		if [ -d "$$g/output" ]; then \
			echo "  $$g"; \
			rm -rf "$$g/output"; \
		fi; \
	done
	@echo "Cleaning .cwasm/.wasm files..."
	@find $(GRATES_DIR) \( -name "*.cwasm" -o -name "*.wasm" \) -not -path "*/target/*" -delete 2>/dev/null || true
	@echo "Done."
