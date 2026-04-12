# Top-level Makefile for lind-wasm-example-grates
#
# Usage:
#   make test                    # run full test suite
#   make test GRATE=geteuid-grate  # run one grate's tests
#   make list                    # list available grates
#   make <grate-name>            # build a single grate
#   make all                     # build all grates
#   make clean                   # remove build artifacts

SHELL := /bin/bash

EXAMPLES_DIR := examples

# All grate directories
C_GRATES := $(shell find $(EXAMPLES_DIR) -name "compile_grate.sh" -exec dirname {} \; | sort)
RUST_GRATES := $(shell find $(EXAMPLES_DIR) -name "Cargo.toml" -not -path "*/target/*" -exec dirname {} \; | sort)
ALL_GRATES := $(sort $(C_GRATES) $(RUST_GRATES))

# Extract just the directory name for make targets
GRATE_TARGETS := $(notdir $(ALL_GRATES))

.PHONY: all test list clean help $(GRATE_TARGETS)

help:
	@echo "Usage:"
	@echo "  make test                      Run full test suite"
	@echo "  make test GRATE=<name>         Run tests for one grate"
	@echo "  make list                      List available grates"
	@echo "  make <grate-name>              Build a single grate"
	@echo "  make all                       Build all grates"
	@echo "  make clean                     Remove build artifacts"
	@echo ""
	@echo "Available grates:"
	@for g in $(GRATE_TARGETS); do echo "  $$g"; done

all: $(GRATE_TARGETS)

# Build individual grates
define build_grate
$(notdir $(1)):
	@echo "Building $(notdir $(1))..."
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
	@for g in $(RUST_GRATES); do \
		if [ -d "$$g/target" ]; then \
			echo "Cleaning $$g..."; \
			cd "$$g" && cargo clean && cd -; \
		fi; \
	done
	@for g in $(C_GRATES); do \
		if [ -d "$$g/output" ]; then \
			echo "Cleaning $$g..."; \
			rm -rf "$$g/output"; \
		fi; \
	done
