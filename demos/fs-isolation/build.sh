#!/usr/bin/env bash
#
# Build everything needed for the filesystem isolation demo.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building Filesystem Isolation Demo ==="

echo "Cleaning..."
(cd "$REPO_ROOT/rust-grates/namespace-grate" && cargo clean 2>/dev/null || true)
(cd "$REPO_ROOT/rust-grates/fs-view-grate" && cargo clean 2>/dev/null || true)
(cd "$REPO_ROOT/rust-grates/imfs-grate" && cargo clean 2>/dev/null || true)

echo "Building namespace-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/namespace-grate" && cargo lind_compile --release --output-dir grates)

echo "Building fs-view-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/fs-view-grate" && cargo lind_compile --release --output-dir grates)

echo "Building imfs-grate (--release)..."
(cd "$REPO_ROOT/rust-grates/imfs-grate" && cargo lind_compile --release --output-dir grates)

echo "Compiling test..."
lind-clang -s "$SCRIPT_DIR/fs_isolation_test.c"

echo "Done."
