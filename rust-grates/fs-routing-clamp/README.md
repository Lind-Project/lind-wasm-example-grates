# fs-routing-clamp

A meta-grate that conditionally routes filesystem syscalls to one or more
clamped grates based on a path prefix. Syscalls on paths that match the prefix
are dispatched to the clamped grate stack; everything else passes through to the
kernel unchanged.

This enables composing filesystem grates (like imfs-grate or fs-view-grate)
so they only handle a specific subtree, while the rest of the filesystem
remains accessible to the cage.

## How it works

1. **Startup**: Parses `--prefix <path>` and the `%{ ... %}` clamp block from
   the command line. Forks a child cage and registers lifecycle handlers.

2. **Clamp phase**: The child cage execs each grate listed inside `%{ ... %}`.
   Each grate's `register_handler` calls are intercepted — the routing clamp
   allocates alt syscall numbers and builds a routing table mapping
   `(cage, syscall)` pairs to the clamped grate's handler. When `%}` is
   reached, the clamp phase ends and the target program execs.

3. **Runtime routing**:
   - **Path-based syscalls** (open, stat, mkdir, etc.): The path is read from
     cage memory. If it starts with the configured prefix, the call is routed
     to the clamped grate via its alt syscall number. Otherwise it passes
     through to the kernel.
   - **FD-based syscalls** (read, write, close, etc.): The routing clamp tracks
     which file descriptors were opened under the prefix (via per-fd metadata
     in fdtables). FD-based calls on clamped fds are routed to the clamped
     grate; unclamped fds pass through.
   - **Lifecycle** (fork, exec, exit): Child cages inherit the routing table
     and handler chain so the policy propagates across the process tree.

## Usage

```bash
lind-wasm grates/fs-routing-clamp.cwasm --prefix <path> %{ <grates...> %} <program> [args...]
```

### Pairing with imfs-grate

The most common composition: route a path prefix to an in-memory filesystem.
The cage sees a real filesystem at that prefix, but all data lives in memory
and is isolated from the host.

```bash
lind-wasm grates/fs-routing-clamp.cwasm --prefix /workspace %{ \
  grates/imfs-grate.cwasm \
%} myapp.cwasm
```

- `/workspace/*` operations go to imfs (in-memory, sandboxed)
- All other paths pass through to the host kernel

### Stacking multiple clamped grates

Multiple grates can be composed inside the clamp. They execute as a chain —
each grate forks, registers, and execs the next:

```bash
lind-wasm grates/fs-routing-clamp.cwasm --prefix /tmp %{ \
  grates/imfs-grate.cwasm \
  grates/fs-view-grate.cwasm \
%} myapp.cwasm
```

Here, `/tmp` operations go through fs-view-grate (which prefixes paths with
`/cage-<id>/` for per-cage isolation) then to imfs-grate (which stores files
in memory). Each cage gets an independent `/tmp`.

### Composing with outer grates

The routing clamp can sit inside a larger grate composition:

```bash
lind-wasm grates/seccomp-grate.cwasm seccomp_deny_fs.conf \
  grates/fs-routing-clamp.cwasm --prefix /workspace %{ \
    grates/imfs-grate.cwasm \
  %} myapp.cwasm
```

Seccomp denies all FS syscalls by default. The routing clamp permits
`/workspace` operations by routing them to imfs. Everything outside
`/workspace` hits seccomp's deny policy.

## Intercepted syscalls

| Category | Syscalls |
|----------|----------|
| Path-based FS | open, stat, access, unlink, mkdir, rmdir, rename, truncate, chmod, chdir, readlink, unlinkat, readlinkat |
| FD-based FS | read, write, close, pread, pwrite, lseek, fstat, fcntl, ftruncate, fchmod, readv, writev, dup, dup2, dup3 |
| Lifecycle | fork (clone), exec, exit, register_handler |

## Building

```bash
cd rust-grates/fs-routing-clamp
cargo lind_compile --release --output-dir grates
```

## Code layout

- `src/main.rs`: argument parsing, child fork, lifecycle handler registration,
  and waitpid loop.
- `src/handlers/clamped_lifecycle.rs`: handlers for register_handler (intercepts
  clamped grate registrations), exec (detects `%}` boundary), fork (copies
  fdtables and routes to child), and exit (cleanup).
- `src/handlers/ns_handlers.rs`: runtime routing handlers — path-based handlers
  check the prefix and dispatch via alt; fd-based handlers check fdtables
  metadata; open handler tracks new fds; close handler removes fd entries.
- `src/helpers.rs`: route table management, alt syscall allocation, path reading
  utilities, and do_syscall wrapper.
