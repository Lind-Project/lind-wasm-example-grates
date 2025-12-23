#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <example-dir>"
    exit 1
fi

TARGET="$1"

# Enter the example directory
pushd "$TARGET" >/dev/null

# Now everything is relative to the example dir
echo "[cwd] $(pwd)"

# Load per-example config
if [[ ! -f build.conf ]]; then
    echo "missing build.conf"
    exit 1
fi
source build.conf

CLANG=/home/lind/lind-wasm/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin/clang
SYSROOT=/home/lind/lind-wasm/src/glibc/sysroot
WASM_OPT=/home/lind/lind-wasm/tools/binaryen/bin/wasm-opt
WASMTIME=/home/lind/lind-wasm/src/wasmtime/target/release/wasmtime

SRC_DIR="src"
mkdir -p output
OUT="output/${ENTRY%.c}"

MAX_MEMORY="${MAX_MEMORY:-268435456}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"
EXTRA_WASM_OPT="${EXTRA_WASM_OPT:-}"

echo "[build] $OUT (max-mem=$MAX_MEMORY)"

"$CLANG" -pthread \
  --target=wasm32-unknown-wasi \
  --sysroot "$SYSROOT" \
  -Wl,--import-memory,--export-memory,--max-memory="$MAX_MEMORY",\
--export=__stack_pointer,--export=__stack_low,--export=pass_fptr_to_wt \
  $EXTRA_CFLAGS \
  "$SRC_DIR"/*.c \
  -g -O0 -o "$OUT.wasm"

"$WASM_OPT" \
  --epoch-injection \
  --debuginfo \
  $EXTRA_WASM_OPT \
  "$OUT.wasm" -o "$OUT.wasm"

"$WASMTIME" compile "$OUT.wasm" -o "$OUT.cwasm"

# Return to original directory
popd >/dev/null
