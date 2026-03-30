#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile --compile-grate src/witness_grate.c src/crypto/*.c -Isrc/crypto

