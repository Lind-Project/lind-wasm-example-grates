#!/usr/bin/env bash
#
# Build everything needed for the mTLS propagation demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Building mTLS Propagation Demo ==="

echo "Cleaning..."
(cd "$REPO_ROOT/rust-grates/mtls-grate" && cargo clean 2>/dev/null || true)

echo "Building mtls-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/mtls-grate" && cargo lind_compile --release --output-dir grates)

echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/mtls_propagation_test.c"

# Generate test certs if they don't exist
if [[ ! -f "$LINDFS/certs/cert.pem" ]]; then
    echo "Generating test certificates..."
    bash "$REPO_ROOT/rust-grates/mtls-grate/test/setup.sh"
fi

echo "Done."
