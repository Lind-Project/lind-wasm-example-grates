#!/usr/bin/env bash
#
# Run the filesystem isolation demo.
# Run build.sh first.

set -euo pipefail

echo "=== Filesystem Isolation Demo ==="
echo ""
echo "Composition:"
echo "  namespace-grate --prefix /tmp"
echo "    -> imfs-grate (independent in-memory FS per cage)"
echo "  Host filesystem (everything outside /tmp)"
echo ""

lind-wasm grates/namespace-grate.cwasm --prefix /tmp %{ \
  grates/imfs-grate.cwasm \
%} fs_isolation_test.cwasm
