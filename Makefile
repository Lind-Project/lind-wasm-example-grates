# Top-level Makefile for lind-wasm-example-grates
#
# Usage:
#   make test                    # run full test suite
#   make test GRATE=geteuid-grate  # run one grate's tests
#   make demos                   # build all demos, then run them
#   make demos-build             # build all demos
#   make demos-run               # run all demos (build first!)
#   make list                    # list available grates
#   make c/<name>                # build a C grate
#   make rust/<name>             # build a Rust grate
#   make all                     # build all grates
#   make clean                   # remove build artifacts

SHELL := /bin/bash

# All grate directories
C_GRATES := $(shell find c-grates -name "compile_grate.sh" -exec dirname {} \; 2>/dev/null | sort)
RUST_GRATES := $(shell find rust-grates -name "Cargo.toml" -not -path "*/target/*" -exec dirname {} \; 2>/dev/null | sort)
ALL_GRATES := $(sort $(C_GRATES) $(RUST_GRATES))

# Targets use type/name format to avoid collisions (e.g. c/strace-grate, rust/strace-grate)
C_TARGETS := $(patsubst c-grates/%,c/%,$(C_GRATES))
RUST_TARGETS := $(patsubst rust-grates/%,rust/%,$(RUST_GRATES))
ALL_TARGETS := $(C_TARGETS) $(RUST_TARGETS)

# All demo directories
DEMOS := $(shell find demos -name Makefile -exec dirname {} \; 2>/dev/null | sort)

.PHONY: all test list clean clean-lindfs help demos demos-build demos-run $(ALL_TARGETS)

help:
	@echo "Usage:"
	@echo "  make test                      Run full test suite"
	@echo "  make test GRATE=<name>         Run tests for one grate"
	@echo "  make list                      List available grates"
	@echo "  make c/<grate-name>            Build a C grate"
	@echo "  make rust/<grate-name>         Build a Rust grate"
	@echo "  make all                       Build all grates"
	@echo "  make demos                     Build and run all demos"
	@echo "  make demos-build               Build all demos"
	@echo "  make demos-run                 Run all demos (build first)"
	@echo "  make clean                     Remove build artifacts"
	@echo ""
	@echo "Available grates:"
	@for g in $(ALL_TARGETS); do echo "  $$g"; done
	@echo ""
	@echo "Available demos:"
	@for d in $(DEMOS); do echo "  $$d"; done

all: $(ALL_TARGETS)

# Build individual grates
define build_c_grate
c/$(notdir $(1)):
	@echo "Building c/$(notdir $(1))..."
	@cd "$(1)" && bash compile_grate.sh
endef

define build_rust_grate
rust/$(notdir $(1)):
	@echo "Building rust/$(notdir $(1))..."
	@if [ -f "$(1)/compile_grate.sh" ]; then \
		cd "$(1)" && bash compile_grate.sh; \
	else \
		cd "$(1)" && cargo lind_compile --output-dir grates; \
	fi
endef

$(foreach g,$(C_GRATES),$(eval $(call build_c_grate,$(g))))
$(foreach g,$(RUST_GRATES),$(eval $(call build_rust_grate,$(g))))

# Demos
demos: demos-build demos-run

demos-build:
	@for d in $(DEMOS); do \
		echo ""; \
		echo "========================================"; \
		echo "Building $$d"; \
		echo "========================================"; \
		$(MAKE) -C "$$d" build || exit 1; \
	done

demos-run:
	@for d in $(DEMOS); do \
		echo ""; \
		echo "========================================"; \
		echo "Running $$d"; \
		echo "========================================"; \
		$(MAKE) -C "$$d" run || exit 1; \
	done

# Test suite
test:
ifdef GRATE
	@./test/run_tests.sh "$(GRATE)"; ret=$$?; $(MAKE) -s clean-lindfs; exit $$ret
else
	@./test/run_tests.sh; ret=$$?; $(MAKE) -s clean-lindfs; exit $$ret
endif

list:
	@./test/run_tests.sh --list

# Clean lindfs artifacts (called after test and by clean)
clean-lindfs:
	@LINDFS="$${LINDFS:-$${LIND_WASM_ROOT:-$$HOME/lind-wasm}/lindfs}"; \
	rm -rf "$$LINDFS/grates/"*.cwasm 2>/dev/null || true; \
	rm -f "$$LINDFS/"*.cwasm 2>/dev/null || true; \
	chmod -R u+w "$$LINDFS/cage-"* 2>/dev/null || true; \
	rm -rf "$$LINDFS/cage-"* 2>/dev/null || true; \
	rm -f "$$LINDFS/"*.cfg "$$LINDFS/"*.conf 2>/dev/null || true; \
	rm -rf "$$LINDFS/certs" 2>/dev/null || true

# Clean everything
clean: clean-lindfs
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
	@echo "Cleaning .cwasm/.wasm files from source dirs and demos..."
	@find c-grates rust-grates demos \( -name "*.cwasm" -o -name "*.wasm" \) -not -path "*/target/*" -delete 2>/dev/null || true
	@echo "Cleaning Cargo.lock files..."
	@find rust-grates -name "Cargo.lock" -delete 2>/dev/null || true
	@echo "Done."
