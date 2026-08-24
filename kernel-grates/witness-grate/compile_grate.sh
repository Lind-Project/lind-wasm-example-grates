#!/usr/bin/env bash

set -euo

cd "$(dirname "$0")"

git clone https://github.com/orlp/ed25519.git
gcc -O2 -I ~/threei/linux/tools/include -I ~/threei/linux/usr/include \
    -I ed25519/src src/witness-grate.c ed25519/src/*.c -lpthread -o witness-grate
gcc -static tests/exit_failure.c -o witness-test
head -c 32 /dev/urandom > witness.seed
