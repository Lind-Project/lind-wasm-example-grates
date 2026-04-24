#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile -s --compile-grate --output-dir grates src/geteuid-grate.c
