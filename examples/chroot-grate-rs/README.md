# chroot-grate-rs

## Build

```bash
cargo lind_compile
```

## Run

This binary expects `--chroot-dir` followed by the program (and args) to run
under the grate:

```bash
lind_run chroot-grate-rs.wasm --chroot-dir cage.wasm
```

## Code layout

- `src/main.rs`: registration and explicit handlers (`readlink*`, `getcwd`,
  `fork`, `chdir`, `chroot`).
- `src/paths.rs`: path normalization/chroot utilities and the
  `input_path_handler!` macro.
- `src/sockets.rs`: AF_UNIX sockaddr translation helpers and socket handler
  macros.

