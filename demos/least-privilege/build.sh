#!/usr/bin/env bash
#
# Build everything needed for the least-privilege demo.
# C grates build with -O2, Rust grates build with --release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Building Least-Privilege Demo ==="

# C grate: seccomp-grate with -O2
echo "Building seccomp-grate (C, -O2)..."
(cd "$REPO_ROOT/c-grates/seccomp-grate" && \
  lind_compile -s -O2 --compile-grate --output-dir grates src/seccomp-grate.c src/seccomp.c)

# Rust grates: namespace-grate and imfs-grate with --release
echo "Building namespace-grate (Rust, --release)..."
(cd "$REPO_ROOT/rust-grates/namespace-grate" && cargo lind_compile --release --output-dir grates)

echo "Building imfs-grate (Rust, --release)..."
(cd "$REPO_ROOT/rust-grates/imfs-grate" && cargo lind_compile --release --output-dir grates)

# Compile test binary with -O2
echo "Compiling test (-O2)..."
lind-clang -s -O2 "$SCRIPT_DIR/least_privilege_test.c"

# Copy config to lindfs
cp "$SCRIPT_DIR/seccomp_fs_deny.conf" "$LINDFS/"

echo "Done."
