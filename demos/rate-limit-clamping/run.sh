#!/usr/bin/env bash
#
# Run the rate-limit clamping demo.
# Run build.sh first.

set -euo pipefail

echo "=== Rate-Limit Clamping Demo ==="
echo ""
echo "Composition:"
echo "  net-routing-clamp --ports 5432-5432"
echo "    -> resource-grate (50 KB/s network rate limit)"
echo "  File I/O is NOT rate-limited (bypasses resource-grate)"
echo ""
echo "Expected: file writes are fast, socket writes to port 5432 are throttled."
echo ""

lind-wasm grates/net-routing-clamp.cwasm --ports 5432-5432 %{ \
  grates/resource-grate.cwasm ratelimit_demo.cfg \
%} ratelimit_demo.cwasm
