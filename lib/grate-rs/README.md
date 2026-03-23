# Getting Started

To use grate-rs, please complete the following setup steps:

## 1. Add lind-wasm scripts to your PATH

```sh
export PATH=$PATH:/home/lind/lind-wasm/scripts/
```

## 2. Install required Rust component

rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

## 3. Build examples with lind_compile
Navigate to the grate-rs directory and compile the examples:

```sh
cd lind-wasm-example-grates/lib/grate-rs
cargo lind_compile --examples
```
