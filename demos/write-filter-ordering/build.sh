#!/usr/bin/env bash
#
# Build everything needed for the write filter ordering demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building Write Filter Ordering Demo ==="

echo "Cleaning..."
(cd "$REPO_ROOT/rust-grates/strace-grate" && cargo clean 2>/dev/null || true)
(cd "$REPO_ROOT/rust-grates/write-filter-grate" && cargo clean 2>/dev/null || true)

echo "Building strace-grate (Rust, --release)..."
(cd "$REPO_ROOT/rust-grates/strace-grate" && cargo lind_compile --release --output-dir grates)

echo "Building write-filter-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/write-filter-grate" && cargo lind_compile --release --output-dir grates)

echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/write_filter_ordering_test.c"

echo "Done."
