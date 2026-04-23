# ipc-grate

Userspace IPC for Lind. Intercepts pipe, socket, and I/O syscalls and
services them entirely in-memory using ring buffers, eliminating kernel
round-trips for inter-cage communication.

For fds that belong to pipes or sockets created by this grate, all I/O
happens in userspace. For all other fds (files, kernel sockets to
non-loopback addresses), syscalls are forwarded transparently.

## What it handles

**Pipes**: `pipe()` and `pipe2()` create in-memory ring buffer pairs.
Reads and writes go directly through the buffer with no kernel
involvement. Pipe fds are tracked via fdtables and refcounted — when the
last write end closes, readers see EOF.

**Unix domain sockets (AF_UNIX)**: `socket()`, `bind()`, `listen()`,
`connect()`, `accept()`, and `socketpair()` are handled entirely in
userspace. Each connected socket pair gets two ring buffers (one per
direction). The `connect`/`accept` handshake uses an internal pending
connection queue.

**Loopback sockets (AF_INET 127.0.0.1)**: TCP connections to localhost
are intercepted at `connect()` time and converted to userspace pipe
pairs, same as AF_UNIX. Non-loopback AF_INET connections are forwarded
to the kernel.

**I/O**: `read()`, `write()`, `close()`, `dup()`, `dup2()`, `dup3()`,
`fcntl()`, and `shutdown()` are routed based on whether the fd belongs
to an IPC pipe/socket or a kernel fd.

**Lifecycle**: `fork()` copies the fdtable and bumps pipe refcounts for
the child cage. `exec()` closes cloexec fds and reserves fds 0-2.

## Intercepted syscalls

| Category | Syscalls |
|----------|----------|
| Pipes | pipe, pipe2 |
| Sockets | socket, socketpair, bind, listen, connect, accept, shutdown |
| I/O | read, write, close, dup, dup2, dup3, fcntl |
| Lifecycle | fork (clone), exec |

## Architecture

```
src/
  main.rs    — handler registration, syscall dispatch, fork/exec logic
  pipe.rs    — ring buffer pipe (lock-free SPSC via ringbuf crate)
  socket.rs  — socket state machine, connection registry, pending queue
  ipc.rs     — global IPC state, pipe/socket creation, fd lookup
```

The pipe implementation uses `ringbuf`'s lock-free SPSC ring buffer.
Each pipe has atomic read/write refcounts and an EOF flag. The ring
buffer's producer and consumer halves are NOT wrapped in Mutex because
`std::sync::Mutex` does not synchronize across Lind runtime threads.

## Usage

```bash
lind-wasm ipc-grate.cwasm <program> [args...]
```

## Building

```bash
cd examples/ipc-grate
cargo lind_compile
```

## Known limitations

- `accept()` returns EAGAIN when no pending connection exists. With the
  Lind runtime's serial executor, blocking accept would deadlock because
  the connecting cage's handler can't run while accept is spinning.
- `sendto()` and `recvfrom()` with addresses are not yet implemented for
  the userspace path (forwarded to kernel).
