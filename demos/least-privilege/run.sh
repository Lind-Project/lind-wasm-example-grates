#!/usr/bin/env bash
#
# Least-Privilege Confinement Demo
#
# Composes seccomp-grate + namespace-grate + imfs-grate to confine
# a process tree to /workspace. All filesystem access outside
# /workspace is denied with EPERM.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Least-Privilege Confinement Demo ==="
echo ""

# Build required grates
echo "Building grates..."
(cd "$REPO_ROOT" && make c/seccomp-grate)
(cd "$REPO_ROOT" && make rust/namespace-grate)
(cd "$REPO_ROOT" && make rust/imfs-grate)
echo ""

# Compile test binary
echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/least_privilege_test.c"
echo ""

# Copy config to lindfs
cp "$SCRIPT_DIR/seccomp_fs_deny.conf" "$LINDFS/"

echo "Composition:"
echo "  seccomp-grate (deny all FS by default)"
echo "    -> namespace-grate --prefix /workspace"
echo "      -> imfs-grate (in-memory FS for /workspace)"
echo "        -> least_privilege_test (the cage)"
echo ""

lind-wasm grates/seccomp-grate.cwasm seccomp_fs_deny.conf \
  grates/namespace-grate.cwasm --prefix /workspace %{ \
    grates/imfs-grate.cwasm \
  %} least_privilege_test.cwasm
