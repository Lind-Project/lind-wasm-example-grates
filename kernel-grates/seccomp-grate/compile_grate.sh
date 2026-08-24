#!/usr/bin/env bash

LINDFS_ROOT="${LIND_WASM_ROOT}"/lindfs

set -euo pipefail

cd "$(dirname "$0")"
gcc -O2 -I linux/tools/include -I linux/usr/include \
    seccomp-grate.c seccomp.c -lpthread -o seccomp-grate
gcc -o seccomp_chmod_test test/seccomp_chmod_test.c
