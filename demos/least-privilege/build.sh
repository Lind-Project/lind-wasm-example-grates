#!/usr/bin/env bash
#
# Build everything needed for the least-privilege demo.
# Rust grates build with --release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Building Least-Privilege Demo ==="

# Clean
echo "Cleaning..."
(cd "$REPO_ROOT/rust-grates/namespace-grate" && cargo clean 2>/dev/null || true)
(cd "$REPO_ROOT/rust-grates/imfs-grate" && cargo clean 2>/dev/null || true)

# C grate
echo "Building seccomp-grate..."
(cd "$REPO_ROOT/c-grates/seccomp-grate" && \
  lind_compile -s --compile-grate --output-dir grates src/seccomp-grate.c src/seccomp.c)

# Rust grates with --release
echo "Building namespace-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/namespace-grate" && cargo lind_compile --release --output-dir grates)

echo "Building imfs-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/imfs-grate" && cargo lind_compile --release --output-dir grates)

# Compile test binary
echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/least_privilege_test.c"

# Copy config to lindfs
cp "$SCRIPT_DIR/seccomp_fs_deny.conf" "$LINDFS/"

echo "Done."
