#!/bin/bash

set -x 

WASMTIME_BACKTRACE_DETAILS=1 RUST_BACKTRACE=1 /home/lind/lind-wasm/src/wasmtime/target/release/wasmtime run --allow-precompiled --wasi threads=y --wasi preview2=n output/geteuid_grate.wasm getegid_grate.wasm ./mash.wasm -c "etest.wasm & imfs_grate.wasm runopen.wasm & getgid_grate.wasm gidtest.wasm" 
