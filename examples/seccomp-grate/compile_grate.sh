#!/usr/bin/env bash

LINDFS_ROOT="${LIND_WASM_ROOT}"/lindfs

set -euo pipefail

cd "$(dirname "$0")"
lind_compile --compile-grate src/seccomp_grate.c src/seccomp.c
cp src/seccomp-config.ini $LINDFS_ROOT
