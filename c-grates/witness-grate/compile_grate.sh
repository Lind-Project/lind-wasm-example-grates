#!/usr/bin/env bash

set -euo

cd "$(dirname "$0")"

if [[ -z "${LIND_WASM_APPS_SYSROOT:-}" ]]; then
  LIND_WASM_APPS_SYSROOT="$(
    find "$HOME" -type d -path "*/lind-wasm-apps/build/sysroot_merged" -print -quit 2>/dev/null
  )"

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
