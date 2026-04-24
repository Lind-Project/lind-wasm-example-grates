#!/usr/bin/env bash
#
# Run the least-privilege confinement demo.
# Run build.sh first.

set -euo pipefail

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
