# chroot-grate

## Build

```bash
cargo lind_compile --output-dir grates
```

## Run

This binary expects `--chroot-dir` followed by the program (and args) to run
under the grate:

```bash
lind-wasm grates/chroot-grate.cwasm --chroot-dir cage.cwasm
```

## Code layout

- `src/main.rs`: registration and explicit handlers (`readlink*`, `getcwd`,
  `fork`, `chdir`, `chroot`).
- `src/paths.rs`: path normalization/chroot utilities and the
  `input_path_handler!` macro.
- `src/sockets.rs`: AF_UNIX sockaddr translation helpers and socket handler
  macros.

