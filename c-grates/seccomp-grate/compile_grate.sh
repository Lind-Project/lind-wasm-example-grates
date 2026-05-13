#!/usr/bin/env bash

LINDFS_ROOT="${LIND_WASM_ROOT}"/lindfs

set -euo pipefail

cd "$(dirname "$0")"
lind_compile -s --compile-grate --output-dir grates src/seccomp-grate.c src/seccomp.c
cp policies/seccomp_blacklist_test.conf $LINDFS_ROOT
cp policies/seccomp_whitelist_test.conf $LINDFS_ROOT
