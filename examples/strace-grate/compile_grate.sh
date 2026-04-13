#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile -s --compile-grate src/strace_grate.c src/strace.c
