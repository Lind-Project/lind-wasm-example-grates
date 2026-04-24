#!/usr/bin/env bash
#
# Build everything needed for the least-privilege demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Building Least-Privilege Demo ==="

# Build grates
echo "Building seccomp-grate..."
(cd "$REPO_ROOT" && make c/seccomp-grate)

echo "Building namespace-grate..."
(cd "$REPO_ROOT" && make rust/namespace-grate)

echo "Building imfs-grate..."
(cd "$REPO_ROOT" && make rust/imfs-grate)

# Compile test binary
echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/least_privilege_test.c"

# Copy config to lindfs
cp "$SCRIPT_DIR/seccomp_fs_deny.conf" "$LINDFS/"

echo "Done."
