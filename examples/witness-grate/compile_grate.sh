#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile --compile-grate src/witness_grate.c /home/lind/lind-wasm-apps/ed25519/*.c -I/home/lind/lind-wasm-apps/

