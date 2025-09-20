#!/bin/bash

/home/lind/lind-wasm/clang+llvm-16.0.4-x86_64-linux-gnu-ubuntu-22.04/bin/clang -pthread --target=wasm32-unknown-wasi --sysroot /home/lind/lind-wasm/src/glibc/sysroot -Wl,--import-memory,--export-memory,--max-memory=1570242560,--export=signal_callback,--export=__stack_pointer,--export=__stack_low,--export=open_grate,--export=close_grate,--export=lseek_grate,--export=read_grate,--export=write_grate,--export=fcntl_grate,--export-table imfs_grate.c imfs.c -g -DLIB -DDIAG -D_GNU_SOURCE -O0 -o imfs_grate.wasm && /home/lind/lind-wasm/tools/binaryen/bin/wasm-opt --epoch-injection --asyncify -O2 --debuginfo imfs_grate.wasm -o imfs_grate.wasm && /home/lind/lind-wasm/src/wasmtime/target/release/wasmtime compile imfs_grate.wasm -o imfs_grate.cwasm

