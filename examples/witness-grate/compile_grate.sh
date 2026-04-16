#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

: "${LIND_WASM_APPS:?LIND_WASM_APPS is not set}"

lind_compile -s --compile-grate \
  src/witness_grate.c \
  "$LIND_WASM_APPS"/ed25519/*.c \
  -I"$LIND_WASM_APPS"/
