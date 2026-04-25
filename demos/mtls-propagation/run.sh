#!/usr/bin/env bash
#
# Run the mTLS propagation demo.
# Run build.sh first.

set -euo pipefail

echo "=== mTLS Propagation Demo ==="
echo ""
echo "The mtls-grate transparently wraps all TCP connections in TLS."
echo "Handler tables propagate across fork, so all worker cages get"
echo "mTLS automatically — no per-worker configuration needed."
echo ""

lind-wasm grates/mtls-grate.cwasm \
  --server-cert ./certs/server.crt \
  --server-key ./certs/server.key \
  --ca ./certs/ca.crt \
  -- mtls_propagation_test.cwasm
