# fs-tee-grate

`fs-tee-grate` tees selected filesystem syscalls to two grate stacks, then
returns the primary stack's result to the cage.

The grate watches for `%{` and `%}` markers in the exec chain to split the
launch into primary, secondary, and target phases, then rewrites registered
handlers so calls on the target cage fan out to both stacks.

## Usage

```bash
lind-wasm grates/fs-tee-grate.cwasm \
  %{ <primary-grate>.cwasm %} \
  %{ <secondary-grate>.cwasm %} \
  <target>.cwasm [args...]
```

For syscalls handled by `fs-tee-grate`, the primary path runs first and its
return value is preserved. The secondary path is executed for comparison or
side effects.

## Intercepted syscalls

`open`, `stat`, `access`, `unlink`, `mkdir`, `rmdir`, `rename`, `truncate`,
`chmod`, `chdir`, `readlink`, `unlinkat`, `readlinkat`, `read`, `write`,
`close`, `pread`, `pwrite`, `lseek`, `fstat`, `fcntl`, `ftruncate`,
`fchmod`, `readv`, `writev`, `dup`, `dup2`, `dup3`

## Building

```bash
cd rust-grates/fs-tee-grate
cargo lind_compile --output-dir grates
```

## Test Assets

The `test/` directory contains a small target program (`test.c`) plus
example C grates used to exercise tee behavior for `read`.
