#ifndef LIND_REVOKEFD_H
#define LIND_REVOKEFD_H

/*
 * lind_revokefd.h: client side of revoke-grate's revokefd syscall.
 *
 * Header-only; needs nothing but lind_syscall.h from the sysroot. Kept in
 * sync with rust-grates/revoke-grate/src/abi.rs.
 *
 *   int lind_revokefd(uint64_t target_cage, int fd, int flags);
 *
 * Revokes fd slot `fd` in cage `target_cage` (which may be the caller): from
 * then on every syscall that cage makes on that fd behaves as if the fd
 * pointed at /dev/null (REVOKE_MODE_NULL) or /dev/zero (REVOKE_MODE_ZERO).
 * The revocation follows dup/fork and ends when the slot is closed.
 *
 * Returns 0, or -1 with errno set:
 *   EINVAL  unknown mode or reserved flag bits set
 *   ESRCH   target cage is not routed through revoke-grate, or has exited
 *   EBADF   fd is not open in the target cage
 *   EPERM   refused by the grate's permission policy
 *   ENOSYS  revoke-grate is not in the caller's grate stack
 *
 * NOTE: ENOSYS needs a lind-wasm runtime where threei returns ENOSYS for
 * unhandled syscall numbers. Older runtimes abort instead.
 */

#include <stdint.h>
#include <unistd.h>
#include <lind_syscall.h>

#define SYS_REVOKEFD 3001

#define REVOKE_MODE_NULL 0
#define REVOKE_MODE_ZERO 1

static inline int lind_revokefd(uint64_t target_cage, int fd, int flags) {
    uint64_t self = (uint64_t)getpid(); /* cage ID */
    return make_threei_call(SYS_REVOKEFD, 0, self, self,
                            target_cage, self,
                            (uint64_t)(uint32_t)fd, self,
                            (uint64_t)(uint32_t)flags, self,
                            0, 0, 0, 0, 0, 0,
                            1 /* translate -errno into errno */);
}

#endif /* LIND_REVOKEFD_H */
