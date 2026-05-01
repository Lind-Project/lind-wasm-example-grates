#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

if [[ -z "${LIND_WASM_APPS_SYSROOT:-}" ]]; then
  LIND_WASM_APPS_DIR="$(
    find "$HOME" -type d -name lind-wasm-apps 2>/dev/null | head -n 1
  )"

  if [[ -z "$LIND_WASM_APPS_DIR" ]]; then
    echo "ERROR: LIND_WASM_APPS_SYSROOT is not set and could not find lind-wasm-apps folder" >&2
    echo "Please set LIND_WASM_APPS_SYSROOT manually, e.g.:" >&2
    echo "  export LIND_WASM_APPS_SYSROOT=/path/to/lind-wasm-apps/build/sysroot_merged" >&2
    exit 1
  fi

  export LIND_WASM_APPS_SYSROOT="$LIND_WASM_APPS_DIR/build/sysroot_merged"
fi

[[ -d "$LIND_WASM_APPS_SYSROOT" ]] || {
  echo "ERROR: LIND_WASM_APPS_SYSROOT does not exist: $LIND_WASM_APPS_SYSROOT" >&2
  exit 1
}

echo "Using LIND_WASM_APPS_SYSROOT: $LIND_WASM_APPS_SYSROOT"

lind_compile -s --compile-grate --output-dir grates \
  src/witness-grate.c \
  "$LIND_WASM_APPS_SYSROOT"/include/ed25519/*.c \
  -I"$LIND_WASM_APPS_SYSROOT"/include/ed25519
