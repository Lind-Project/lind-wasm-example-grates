#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile --compile-grate src/seccomp_grate.c src/seccomp.c
