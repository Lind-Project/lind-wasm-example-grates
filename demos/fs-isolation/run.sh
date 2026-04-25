#!/usr/bin/env bash
#
# Run the filesystem isolation demo.
# Run build.sh first.

set -euo pipefail

echo "=== Filesystem Isolation Demo ==="
echo ""
echo "Composition:"
echo "  namespace-grate --prefix /tmp"
echo "    -> fs-view-grate (per-cage path prefixing)"
echo "      -> imfs-grate (in-memory FS)"
echo "  Host filesystem (everything outside /tmp)"
echo ""

lind-wasm grates/namespace-grate.cwasm --prefix /tmp %{ \
  grates/imfs-grate.cwasm \
  grates/fs-view-grate.cwasm \
%} fs_isolation_test.cwasm
