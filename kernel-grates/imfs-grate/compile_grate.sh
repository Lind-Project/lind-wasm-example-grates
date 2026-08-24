#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
gcc -O2 -g -I ~/threei/linux/tools/include -I ~/threei/linux/usr/include \
    src/imfs-grate.c src/imfs.c -lpthread -o imfs-grate
gcc -static test/imfs-test.c -o imfs-test
