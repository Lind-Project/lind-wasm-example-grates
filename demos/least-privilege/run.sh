#!/usr/bin/env bash
#
# Least-Privilege Confinement Demo
#
# Composes seccomp-grate + namespace-grate + imfs-grate to confine
# a process tree to /workspace. All filesystem access outside
# /workspace is denied with EPERM.
#
# Prerequisites:
#   - Build seccomp-grate:    make c/seccomp-grate
#   - Build namespace-grate:  make rust/namespace-grate
#   - Build imfs-grate:       make rust/imfs-grate
#   - Compile test:           lind-clang -s demos/least-privilege/least_privilege_test.c
#   - Copy config to lindfs:  cp demos/least-privilege/seccomp_fs_deny.conf $LINDFS/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

# Copy config to lindfs
cp "$SCRIPT_DIR/seccomp_fs_deny.conf" "$LINDFS/"

echo "=== Least-Privilege Confinement Demo ==="
echo ""
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
