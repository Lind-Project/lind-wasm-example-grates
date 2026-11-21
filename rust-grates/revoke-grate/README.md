# revoke-grate

Revokes file descriptors held by running cages, in the spirit of BSD's
`revoke(2)` but addressed by `(cage, fd)` instead of by path. The grate adds a
`revoke` syscall that cages and grates below it can call at any time. From
then on, every syscall the target cage makes on that fd is answered as if the
descriptor pointed at `/dev/null` (default) or `/dev/zero`. The cage keeps
running and keeps a valid-looking fd, but can no longer read, write, stat, map
or otherwise reach the object behind it.

The grate provides the mechanism only. Deciding _what_ to revoke (an abusive
connection, an expired lease, a runaway log) belongs to whatever calls it: the
app itself, a sibling management cage, or a policy grate stacked below this
one. As with any grate, only cages whose syscalls route through it can be
revoked, so its position in the stack decides who is covered.

The grate emulates the device itself rather than opening a real `/dev/null`,
so it does not depend on `/dev` existing inside lindfs.

## The revoke syscall

```c
#include "lind_revoke.h"   /* rust-grates/revoke-grate/include/ */

int lind_revoke(uint64_t target_cage, int fd, int flags);
/* flags: REVOKE_MODE_NULL (0) or REVOKE_MODE_ZERO (1) */
```

Syscall number `3001` (`SYS_REVOKE`); arguments `(target_cage, fd, flags)`.
The header is a thin `make_threei_call` wrapper with no dependency on the
grate, and `src/abi.rs` is the Rust side of the same ABI.

| Return   | Meaning                                                                     |
| -------- | --------------------------------------------------------------------------- |
| 0        | revoked (revoking an already revoked fd also succeeds; the mode is updated) |
| `EINVAL` | unknown mode, or reserved flag bits set                                     |
| `ESRCH`  | target cage is not routed through this grate, or has exited                 |
| `EBADF`  | fd is not open in the target cage                                           |
| `EPERM`  | refused by the permission hook (never, currently)                           |
| `ENOSYS` | revoke-grate is not in the caller's stack (returned by threei)              |

**Permissions:** none yet. Every call passes through a single
`authorize(caller, target, fd)` hook in `src/handlers.rs` that currently
allows everything. The grate already records each cage's parent
(`state::parent_of`), so a descendant-only rule like `kill()` is a few lines.
Caveat: the caller's cage ID comes from the argument cage IDs, which the
caller supplies, so any such check trusts it.

**Grate missing:** threei returns `ENOSYS` for a syscall number with no
handler, so callers can probe for the grate. Older lind-wasm runtimes abort
instead.

## Usage

```bash
lind-wasm grates/revoke-grate.cwasm [--log] [--] <program> [args...]
```

- `--log`: print the cage IDs at startup, every revoke, and every emulated
  call to stderr.

Revocations are made at runtime through the syscall above. Cage IDs are
allocated in increasing order starting at 1. When the grate is launched
directly by `lind-wasm` it is cage 1, `<program>` is cage 2, and cages that
`<program>` forks get 3, 4 and so on. Only `<program>` and its descendants
route through this grate, so only they can be revoked (others get `ESRCH`).

## Semantics

The real descriptor is **left open**, so its fd number cannot be handed out
again by `open`/`socket`/... while it is marked revoked. Revocation is tracked
per `(cage, fd)` **slot**, not per open file: other descriptors that already
referred to the same file (an earlier `dup`, the parent's copy after a fork)
stay live. From the moment of revocation it follows the descriptor:

| Event                                                             | Effect                                                  |
| ----------------------------------------------------------------- | ------------------------------------------------------- |
| `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD[_CLOEXEC])` of a revoked fd | new fd is revoked with the same mode                    |
| `dup2`/`dup3` of a non-revoked fd onto a revoked one              | slot is no longer revoked                               |
| `close`                                                           | forwarded; slot is no longer revoked                    |
| `fork` (non-thread `clone`)                                       | child inherits all of the parent's revocations          |
| `execve`                                                          | revocations survive unless the real fd is close-on-exec |

### Emulated results on a revoked fd

| Syscalls                                     | `null`                                                                           | `zero`                                  |
| -------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------- |
| read, pread, readv, preadv                   | 0 (EOF)                                                                          | buffer filled with zeros, returns count |
| write, pwrite, writev, pwritev               | returns count                                                                    | returns count                           |
| lseek                                        | 0                                                                                | 0                                       |
| fsync, fdatasync, sync_file_range, flock     | 0                                                                                | 0                                       |
| mmap                                         | `ENODEV`                                                                         | anonymous zero mapping                  |
| ftruncate                                    | `EINVAL`                                                                         | `EINVAL`                                |
| ioctl                                        | `ENOTTY`                                                                         | `ENOTTY`                                |
| fstat, fstatfs, fchmod                       | `EACCES`                                                                         | `EACCES`                                |
| fchdir, getdents                             | `ENOTDIR`                                                                        | `ENOTDIR`                               |
| socket calls (bind … getpeername, accept[4]) | `ENOTSOCK`                                                                       | `ENOTSOCK`                              |
| epoll_wait (epfd) / epoll_ctl (epfd, fd)     | `EINVAL` / `EPERM`                                                               | same                                    |
| `*at` calls with revoked dirfd               | relative path → `ENOTDIR`, empty/NULL path → `EACCES`, absolute path → forwarded | same                                    |

`fstat` returns `EACCES` instead of forwarding, so the real file's metadata
does not leak.

### Known gaps

- `poll`, `ppoll` and `select` are forwarded unchanged, so readiness reflects
  the real object rather than an always-ready `/dev/null`.
- `fcntl(F_GETFL)` and similar non-dup commands are forwarded and can reveal
  the real fd's flags.
- Forks have a small race: the child cage can run before its inherited
  revocations are recorded (same race as the fdtables copy in other grates).
- Slot granularity: descriptors that already shared the file at revoke time
  are not revoked (see Semantics). Revoking the open file itself is future work.
- A call already blocked in the kernel (e.g. a `read` on a socket) is not woken
  by a revoke; only later calls are emulated.
- No permission check yet (see above).
- `readv`/`writev` assume a wasm32 `struct iovec` layout.

## Intercepted syscalls

| Category        | Syscalls                                                                                                                               |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Data            | read, pread, readv, preadv, write, pwrite, writev, pwritev, lseek, mmap                                                                |
| Metadata / misc | fstat, fstatfs, fchmod, fchdir, getdents, fsync, fdatasync, sync_file_range, flock, ftruncate, ioctl                                   |
| Sockets         | bind, listen, connect, accept, accept4, shutdown, sendto, recvfrom, sendmsg, recvmsg, setsockopt, getsockopt, getsockname, getpeername |
| epoll           | epoll_wait, epoll_ctl                                                                                                                  |
| `*at`           | openat, unlinkat, readlinkat, fchmodat, mkdirat, fchownat, newfstatat, faccessat, utimensat, statx, symlinkat, renameat, renameat2     |
| Lifecycle       | close, dup, dup2, dup3, fcntl, clone, execve                                                                                           |
| Provided        | revoke (3001)                                                                                                                          |

## Building

```bash
make rust/revoke-grate
# or
cd rust-grates/revoke-grate && cargo lind_compile --release --output-dir grates
```

## Testing

```bash
make test GRATE=revoke-grate
```

`test/revoke_syscall_test.c` (no grate args) revokes fds at runtime through
the syscall and checks:

- error cases (`EINVAL`/`EBADF`/`ESRCH`);
- null mode: EOF reads, swallowed writes, `isatty`/`fstat`/`mmap` errors,
  `F_DUPFD` propagation, and a regular file left untouched;
- zero mode: zero-filled `read`/`readv`, zero `mmap`, `dup`/`dup2`
  propagation, overwriting the slot with `dup2`, and `close` clearing it;
- slot semantics: an earlier `dup` stays live;
- fork: a child inherits the parent's revocations, and a parent can revoke a
  running child's fd without affecting its own copy.

## Code layout

- `src/main.rs`: CLI parsing and handler registration.
- `src/abi.rs`: revoke syscall number and flag encoding.
- `src/state.rs`: the `(cage, fd) -> mode` revocation table and the cage tree.
- `src/handlers.rs`: syscall handlers, emulation, the revoke handler and its
  `authorize` hook.
- `src/utils.rs`: the `rlog!` macro and helpers for copying to and from cage
  memory.
- `include/lind_revoke.h`: header-only C client wrapper.
