# revoke-grate

This grate adds a new `revokefd` syscall available to all cages below it which takes
`(cage, fd, flags)` in order to revoke a given file descriptor by stubbing it to
like a `/dev/null` or `/dev/zero`.

This is inspired by BSD's [`revoke(2)`](https://man.freebsd.org/cgi/man.cgi?query=revoke&sektion=2&n=1) syscall
(which targets only file paths, and only character devices).

This grate does not decide when or which FD is revoked, that decision belongs to a
down-stack grate or cage.

The `/dev/null` and `/dev/zero` behaviour is implemented by this grate itself and doesn't
depend on lindfs's `/dev`.

## Using the syscall

The `revokefd` syscall is added with `syscall_number` 4001, and can be invoked like a regular
syscall using `make_threei_call`. For ease of use, this grate also provides a short header file
in [./include/lind_revokefd.h](./include/lind_revokefd.h) which exposes the flags and the
`lind_revokefd()` function:

```c
#include "lind_revokefd.h"

int lind_revokefd(uint64_t target_cage, int fd, int flags);
// flags: REVOKE_MODE_NULL (0) or REVOKE_MODE_ZERO (1)
```

The syscall can return the following values:

| Return   | Meaning                                                                   |
| -------- | ------------------------------------------------------------------------- |
| 0        | revoked (the mode can be updated through a duplicate `revokefd` call)     |
| `EINVAL` | unknown mode                                                              |
| `ESRCH`  | target cage is not routed through this grate, or has exited               |
| `EBADF`  | fd is not open in the target cage                                         |
| `EPERM`  | refused by the permission hook (currently unimplemented so always passes) |

## Instantiating the grate

```bash
lind-wasm grates/revoke-grate.cwasm [--log] [--] <program> [args...]
```

## Revocation Semantics

The real descriptor is left open and not closed, this ensures that a revoked fd is not
reassigned through a new `open`/`socket`/... call.

Revocation is tracked through `(cageid, fd)` pair, and not the underlying file or device.
This means that an FD that was `dup`'d before revocation can still be accessed through the
`dup`'d FD.

Once an FD is revoked, the following behaviour is enforced on it:

| Event                                                | Effect                                                  |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD[_CLOEXEC])`    | new fd is revoked with the same mode                    |
| `dup2`/`dup3` of a non-revoked fd onto a revoked one | slot is no longer revoked                               |
| `close`                                              | forwarded, slot is no longer revoked                    |
| `fork`                                               | child inherits all of the parent's revocations          |
| `execve`                                             | revocations survive unless the real fd is close-on-exec |

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

## Known gaps

- `poll`, `ppoll` and `select` are forwarded unchanged, so readiness reflects
  the real object rather than an always-ready `/dev/null`.
- A call already blocked in the kernel (e.g. a `read` on a socket) is not woken
  by a revoke; only later calls are emulated.
- No permission check yet.

## Building & Testing

```bash
make rust/revoke-grate
# or
cargo lind_compile --release --output-dir grates
```

Testing:

```bash
make test GRATE=revoke-grate
```
