# fchmodat-grate

A grate that clamps file permission bits by ANDing the `mode` argument of
every `fchmodat(2)` call with a configurable mask before the syscall reaches
the kernel.

This is the `at`-variant counterpart to `fchmod-grate`, enforcing the same
permission ceiling for path-based permission changes that use a directory file
descriptor — without modifying the cage program and without requiring any
privileges.

## How it works

When a cage calls `fchmodat(dirfd, path, mode, flags)`, the grate intercepts
the syscall, computes `masked_mode = mode & MASK`, and forwards
`fchmodat(dirfd, path, masked_mode, flags)` to the kernel. All other arguments
— `dirfd`, `path`, and `flags` — are passed through unchanged. The cage
receives the return value of the real syscall.

Bits not present in the mask are silently stripped. For example, with
`--mask 644`:

- `fchmodat(AT_FDCWD, "file", 0777, 0)` → kernel sees mode `0644`
- `fchmodat(AT_FDCWD, "file", 0755, 0)` → kernel sees mode `0644`
- `fchmodat(AT_FDCWD, "file", 0600, 0)` → kernel sees mode `0600` (within mask, preserved)
- `fchmodat(dirfd,    "file", 04755, 0)` → kernel sees mode `0644` (setuid bit stripped)

The default mask (`07777`) passes all bits through unchanged, so the grate
is a no-op without `--mask`.

`dirfd` may be `AT_FDCWD` (relative to the calling process's cwd), a real
directory file descriptor, or any value when `path` is absolute (in which case
the kernel ignores `dirfd` entirely). The `flags` argument is forwarded as-is;
note that `AT_SYMLINK_NOFOLLOW` is not supported on Linux and the kernel will
return `ENOTSUP`.

## Usage

```bash
lind-wasm grates/fchmodat-grate.cwasm [--mask <octal>] <program> [args...]
```

### Example

Prevent any cage file from receiving execute or setuid bits via path-based
permission changes:

```bash
lind-wasm grates/fchmodat-grate.cwasm --mask 644 myapp.cwasm
```

## Options

| Flag | Description |
|------|-------------|
| `--mask <octal>` | Octal permission mask ANDed with every `fchmodat` mode. Default: `7777` (no restriction). |

## Intercepted syscalls

| Syscall | Effect |
|---------|--------|
| `fchmodat(dirfd, path, mode, flags)` | `mode` is replaced with `mode & MASK` before dispatch. |

## Building

```bash
cd rust-grates/fchmodat-grate
cargo lind_compile --output-dir grates
```

## Code layout

- `src/main.rs`: argument parsing, mask initialisation, handler registration
  via `GrateBuilder`, and the `fchmodat` handler.
