#!/usr/bin/env bash
set -euo pipefail

lind_compile --compile-grate src/imfs_grate.c src/imfs.c
