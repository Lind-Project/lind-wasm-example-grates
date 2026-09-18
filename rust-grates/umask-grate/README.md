# umask-grate

A grate that enforces minimum file-permission restrictions by modifying every
`umask(2)` call made by a cage. The cage may request any umask, but the grate
adds the configured mask bits before the syscall reaches the kernel.

This allows an operator to enforce restrictions whenever the cage sets its
umask, without modifying the caged program. The cage may still choose a more
restrictive mask.

## How it works

1. **Mask enforcement**: The grate intercepts `SYS_UMASK` only. When the cage
   calls `umask(mask)`, it computes `enforced_mask = (mask | force_bits) &
   0777` and forwards that value to Lind's real `SYS_UMASK` implementation.

2. **Lind-owned umask semantics**: Lind stores the resulting umask and applies
   it to normal filesystem creation operations such as `open`, `openat`, and
   `mkdir`. The grate does not intercept those syscalls or alter file modes.

3. **Configurable restrictions**: The `--force-bits` option accepts an octal
   mask. For example, `022` always removes group-write and other-write
   permissions from newly created files and directories.

4. **Pass-through by default**: The default forced mask is `0000`, so the
   cage's requested umask is forwarded unchanged when no option is provided.

5. **Return value**: The cage receives the previous effective umask returned
   by the forwarded syscall. Because forced bits are applied to every call,
   the returned mask may already include those bits. All other syscalls pass
   through without modification.

## Usage

```bash
lind-wasm grates/umask-grate.cwasm [--force-bits <octal>] <program> [args...]
```

### Example

Prevent a program from creating group- or other-writable files:

```bash
lind-wasm grates/umask-grate.cwasm --force-bits 022 myapp.cwasm
```

If the program requests a mask of `0000`, the grate forwards `0022`; Lind then
creates a file requested as `0666` with mode `0644` under normal POSIX umask
semantics. A more restrictive request such as `0077` remains `0077`.

## Intercepted syscalls

| Category | Syscalls |
|----------|----------|
| File creation mask | umask |

## Building

```bash
cd rust-grates/umask-grate
cargo lind_compile --output-dir grates
```

## Code layout

- `src/main.rs`: argument parsing, forced-mask storage, `SYS_UMASK` handler
  registration, and child execution.
- `test/umask_test.c`: libc `umask()` tests for `open`, `mkdir`, and `openat`
  with `--force-bits 022`.
