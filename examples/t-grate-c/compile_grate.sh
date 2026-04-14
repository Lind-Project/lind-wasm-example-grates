#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
lind_compile -s --compile-grate src/t_grate.c src/tee.c src/handlers.c
