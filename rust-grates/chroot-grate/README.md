# chroot-grate

A grate that confines a cage to a directory subtree by transparently rewriting
all filesystem paths. The cage sees `/` as its root, but every path-based
syscall is prefixed with the configured chroot directory before reaching the
kernel.

Unlike `chroot(2)`, this requires no privileges and cannot be escaped by the
caged process — the grate intercepts the syscall before it executes, so the
cage never operates on raw host paths.

## How it works

1. **Path rewriting**: Every path-based syscall (`open`, `stat`, `mkdir`,
   `unlink`, `rename`, etc.) has its path argument read from cage memory,
   resolved against the cage's virtual cwd, and prefixed with the chroot
   directory before dispatch.

2. **Virtual cwd tracking**: `chdir` updates a per-cage virtual cwd table
   instead of calling the host `chdir`. `getcwd` returns the virtual path.
   Relative paths in any syscall are resolved against this virtual cwd.

3. **Fork propagation**: On `fork`, the child cage inherits the parent's
   virtual cwd.

4. **AF_UNIX socket paths**: `bind`, `connect`, `sendto`, `accept`,
   `getsockname`, `getpeername`, and `recvfrom` translate `sun_path` in
   `sockaddr_un` structures so AF_UNIX sockets work transparently inside
   the chroot.

5. **Output path stripping**: `readlink` and `readlinkat` strip the chroot
   prefix from returned symlink targets so the cage sees virtual paths.

6. **Nested chroot denied**: The cage cannot call `chroot(2)` — it returns
   EPERM.

## Usage

```bash
lind-wasm grates/chroot-grate.cwasm --chroot-dir <path> <program> [args...]
```

### Example

Confine a program to `/home/user/sandbox`:

```bash
lind-wasm grates/chroot-grate.cwasm --chroot-dir /home/user/sandbox myapp.cwasm
```

The program sees `/` as its root. Opening `/etc/config` actually opens
`/home/user/sandbox/etc/config` on the host.

## Intercepted syscalls

| Category | Syscalls |
|----------|----------|
| Path-based FS | open, stat, access, statfs, mkdir, rmdir, unlink, unlinkat, chmod, truncate, rename, link, execve |
| Path output | readlink, readlinkat |
| CWD management | chdir, fchdir, getcwd, chroot |
| Process lifecycle | fork |
| AF_UNIX sockets | bind, connect, sendto, accept, getsockname, getpeername, recvfrom |

## Building

```bash
cd rust-grates/chroot-grate
cargo lind_compile --output-dir grates
```

## Code layout

- `src/main.rs`: argument parsing, handler registration via GrateBuilder, and
  explicit handlers for readlink, readlinkat, getcwd, chdir, fork, execve, and chroot.
- `src/paths.rs`: path normalization, chroot prefixing, per-cage cwd tracking,
  and the `input_path_handler!` macro.
- `src/sockets.rs`: AF_UNIX sockaddr translation helpers and the
  `socket_translate_handler!` / `socket_untranslate_handler!` macros.
