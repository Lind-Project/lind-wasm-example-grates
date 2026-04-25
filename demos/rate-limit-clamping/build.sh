#!/usr/bin/env bash
#
# Build everything needed for the rate-limit clamping demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LINDFS="${LINDFS:-${LIND_WASM_ROOT:-$HOME/lind-wasm}/lindfs}"

echo "=== Building Rate-Limit Clamping Demo ==="

echo "Building net-namespace-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/net-namespace-grate" && cargo lind_compile --release --output-dir grates)

# resource-grate is built without --release because the busy-wait
# rate limiter loop gets partially optimized out in release mode.
echo "Building resource-grate..."
(cd "$REPO_ROOT/rust-grates/resource-grate" && cargo lind_compile --output-dir grates)

echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/ratelimit_demo.c"

# Copy config to lindfs
cp "$SCRIPT_DIR/ratelimit_demo.cfg" "$LINDFS/"

echo "Done."
