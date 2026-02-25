#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"
lind_compile --compile-grate src/geteuid_grate.c
