#!/usr/bin/env bash
#
# Run the DSM shared-mmap demo.
# Run build.sh first.

set -euo pipefail

echo "=== DSM shared-mmap Demo ==="
echo ""
echo "Composition:"
echo "  fs-routing-clamp --prefix /tmp"
echo "    -> imfs-grate (in-memory FS, shared by all cages)"
echo "  Host filesystem (everything outside /tmp)"
echo ""
echo "Scenario: parent + 2 children all mmap /tmp/dsm_segment MAP_SHARED;"
echo "each writes a marker at a distinct offset; parent verifies it sees"
echo "all three.  Matches the way postgres workers attach to a DSM segment."
echo ""

lind-wasm grates/fs-routing-clamp.cwasm --prefix /tmp %{ \
  grates/imfs-grate.cwasm \
%} dsm_shared_test.cwasm
