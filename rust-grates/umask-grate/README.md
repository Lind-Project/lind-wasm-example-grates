# umask-grate

A grate that intercepts `umask(2)` calls made by a cage. The cage may request
any umask, but the grate ORs the configured mask bits into the request and
stores the resulting effective mask internally for that cage.

## How it works

1. **`umask` interception**: The grate registers a handler for `SYS_UMASK`
   only. When the cage calls `umask(mask)`, it computes
   `enforced_mask = (mask | force_bits) & 0777`, stores that value in the
   grate's state keyed by the calling cage, and returns the previous effective
   mask. It does not call down to RawPOSIX.

2. **Configurable forced bits**: The `--force-bits` option accepts an octal
   mask that is OR'd into every requested umask.

3. **No creation-syscall handling**: The grate does not intercept `open`,
   `openat`, `mkdir`, `mknod`, `mkfifo`, or `O_TMPFILE`, and it does not
   propagate its stored umask to RawPOSIX.

4. **Pass-through by default**: The default forced mask is `0000`, so the
   cage's requested umask is stored unchanged when no option is provided.

5. **Return value**: The cage receives the previous effective umask from the
   grate. Because forced bits are applied to every call,
   the returned mask may already include those bits. All other syscalls pass
   through without modification.

## Usage

```bash
lind-wasm grates/umask-grate.cwasm [--force-bits <octal>] <program> [args...]
```

### Example

Force group-write and other-write bits into every requested umask:

```bash
lind-wasm grates/umask-grate.cwasm --force-bits 022 myapp.cwasm
```

If the program requests a mask of `0000`, the grate stores `0022` and returns
the previous effective mask. A more restrictive request such as `0077` remains
`0077`.

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

- `src/main.rs`: argument parsing, forced-mask and per-cage umask storage,
  `SYS_UMASK` handler registration, and child execution.
- `test/umask_test.c`: libc `umask()` return-value and forced-mask tests with
  `--force-bits 022`.
