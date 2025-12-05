#!/bin/bash


mkdir -p output

cat ./tools/magic.tmpl > magic.h
python3 ./tools/wand.py 0 >> magic.h

cat ./tools/magic.ctmpl > magic.c
python3 ./tools/wand.py 1 >> magic.c

# IF=("$@")
# F="${IF[0]}"
# B="$(basename "$F" .c)"
# OUT="${B}"

# /home/lind/lind-wasm/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin/clang -pthread --target=wasm32-unknown-wasi --sysroot /home/lind/lind-wasm/src/glibc/sysroot -Wl,--import-memory,--export-memory,--max-memory=1570242560,--export=signal_callback,--export=__stack_pointer,--export=__stack_low,--export=open_grate,--export=close_grate,--export=geteuid_grate,--export=getegid_grate,--export-table magic.c "$@" -g -DLIB -DDIAG -D_GNU_SOURCE -O0 -o output/${OUT}.wasm && /home/lind/lind-wasm/tools/binaryen/bin/wasm-opt --epoch-injection --asyncify -O2 --debuginfo output/${OUT}.wasm -o output/${OUT}.wasm && /home/lind/lind-wasm/src/wasmtime/target/release/wasmtime compile output/${OUT}.wasm -o output/${OUT}.cwasm

# rm magic.c magic.h

if [ $# -lt 1 ]; then
    echo "Usage: $0 <source.c>"
    exit 1
fi

SRC="$1"
BASE="${SRC%.c}"

CLANG="/home/lind/lind-wasm/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin/clang"
SYSROOT="/home/lind/lind-wasm/src/glibc/sysroot"
WASM_OPT="/home/lind/lind-wasm/tools/binaryen/bin/wasm-opt"
WASMTIME="/home/lind/lind-wasm/src/wasmtime/target/release/wasmtime"

"$CLANG" -pthread \
    --target=wasm32-unknown-wasi \
    --sysroot "$SYSROOT" \
    -Wl,--import-memory,--export-memory,--max-memory=67108864,\
--export=__stack_pointer,--export=__stack_low,--export=pass_fptr_to_wt \
    "$SRC" \
    -g -O0 -o "${BASE}.wasm"

"$WASM_OPT" --asyncify --epoch-injection --debuginfo "${BASE}.wasm" -o "${BASE}.wasm"

"$WASMTIME" compile "${BASE}.wasm" -o "${BASE}.cwasm"
