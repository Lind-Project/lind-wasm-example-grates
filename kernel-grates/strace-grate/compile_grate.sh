#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
gcc -O2 -I linux/tools/include -I linux/usr/include src/strace-grate.c src/strace.c -lpthread -o strace-grate
gcc -static -o strace_test test/strace_test.c
