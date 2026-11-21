//! Syscall handlers for revoke-grate.
//!
//! Every handler follows the same shape: look up whether the fd argument(s)
//! of the call are revoked in the calling cage. If not, forward the call
//! unchanged through threei. If so, return what the call would have returned
//! had the descriptor been `/dev/null` (or `/dev/zero`), without touching the
//! real descriptor.
//!
//! The calling cage is taken from the fd argument's own `argNcage`, the same
//! convention the other grates use.

use grate_rs::constants::error::{
    EACCES, EBADF, EINVAL, ENODEV, ENOTDIR, ENOTSOCK, ENOTTY, EPERM, ESRCH,
};
use grate_rs::constants::fs::{F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, FD_CLOEXEC};
use grate_rs::constants::mman::MAP_ANON;
use grate_rs::constants::*;
use grate_rs::{GrateError, SyscallHandler, getcageid, is_thread_clone, make_threei_call};

use crate::abi;
use crate::state::{self, Mode};
use crate::utils::{
    arg_first_byte, iov_total, log, log_emulated, neg, norm_fd, read_iovecs, zero_fill,
};

// ── Call plumbing ───────────────────────────────────────────────────

/// The six (arg, argcage) pairs of an intercepted syscall.
pub struct Call {
    pub args: [u64; 6],
    pub cages: [u64; 6],
}

impl Call {
    /// Forward the call unchanged on behalf of the calling cage.
    fn forward(&self, nr: u64) -> i64 {
        // forward_raw(nr, self.cages[0], &self.args, &self.cages)
        match make_threei_call(
            nr as u32,
            nr,
            getcageid(),
            self.cages[0],
            self.args[0],
            self.cages[0],
            self.args[1],
            self.cages[1],
            self.args[2],
            self.cages[2],
            self.args[3],
            self.cages[3],
            self.args[4],
            self.cages[4],
            self.args[5],
            self.cages[5],
            0,
        ) {
            Ok(r) => r,
            Err(GrateError::MakeSyscallError(e)) => e,
            Err(_) => neg(EINVAL),
        }
    }

    /// Revocation state of the fd held in argument `idx`.
    fn revoked(&self, idx: usize) -> Option<Mode> {
        state::lookup(self.cages[idx], self.args[idx])
    }
}

/// Define an `extern "C"` handler with the 3i signature, binding the
/// arguments to a `Call` named `$c`.
macro_rules! handler {
    ($name:ident, |$c:ident| $body:expr) => {
        pub extern "C" fn $name(
            _grate: u64,
            a1: u64,
            c1: u64,
            a2: u64,
            c2: u64,
            a3: u64,
            c3: u64,
            a4: u64,
            c4: u64,
            a5: u64,
            c5: u64,
            a6: u64,
            c6: u64,
        ) -> i64 {
            let $c = Call {
                args: [a1, a2, a3, a4, a5, a6],
                cages: [c1, c2, c3, c4, c5, c6],
            };
            $body
        }
    };
}

/// Handler that forwards unless the fd in argument `$idx` is revoked, in
/// which case `$emu` (with the mode bound to `$m`) is returned instead.
macro_rules! on_revoked {
    ($name:ident, $nr:expr, $idx:expr, |$c:ident, $m:ident| $emu:expr) => {
        handler!($name, |$c| match $c.revoked($idx) {
            Some($m) => {
                log_emulated(stringify!($name), &$c, $idx, $m);
                $emu
            }
            None => $c.forward($nr),
        });
    };
}

/// `read`/`pread` on a revoked fd.
fn emu_read(c: &Call, m: Mode) -> i64 {
    match m {
        Mode::Null => 0,
        Mode::Zero => zero_fill(c.cages[1], c.args[1], c.args[2]),
    }
}

/// `readv`/`preadv` on a revoked fd.
fn emu_readv(c: &Call, m: Mode) -> i64 {
    if m == Mode::Null {
        return 0;
    }
    let iovs = match read_iovecs(c.cages[1], c.args[1], c.args[2]) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for (base, len) in iovs {
        let r = zero_fill(c.cages[1], base, len);
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        if (r as u64) < len {
            break;
        }
    }
    total
}

/// `writev`/`pwritev` on a revoked fd: report everything as written.
fn emu_writev(c: &Call) -> i64 {
    match read_iovecs(c.cages[1], c.args[1], c.args[2]) {
        Ok(v) => iov_total(&v),
        Err(e) => e,
    }
}

/// For an `*at` call: if the dirfd in `dirfd_idx` is revoked and the path in
/// `path_idx` would be resolved relative to it, return the emulated error.
fn at_blocked(c: &Call, dirfd_idx: usize, path_idx: usize) -> Option<i64> {
    let m = c.revoked(dirfd_idx)?;
    let r = match arg_first_byte(c.cages[path_idx], c.args[path_idx]) {
        // Absolute path: dirfd is ignored, nothing to revoke.
        Ok(Some(b'/')) => return None,
        // NULL or "" (AT_EMPTY_PATH-style): operates on the fd itself.
        Ok(None) | Ok(Some(0)) => neg(EACCES),
        // Relative path: resolving against /dev/null fails.
        Ok(Some(_)) => neg(ENOTDIR),
        Err(e) => e,
    };
    log_emulated("at-dirfd", c, dirfd_idx, m);
    Some(r)
}

// ── Data path ───────────────────────────────────────────────────────

on_revoked!(read_handler, SYS_READ, 0, |c, m| emu_read(&c, m));
on_revoked!(pread_handler, SYS_PREAD, 0, |c, m| emu_read(&c, m));
on_revoked!(readv_handler, SYS_READV, 0, |c, m| emu_readv(&c, m));
on_revoked!(preadv_handler, SYS_PREADV, 0, |c, m| emu_readv(&c, m));

on_revoked!(write_handler, SYS_WRITE, 0, |c, _m| c.args[2] as i64);
on_revoked!(pwrite_handler, SYS_PWRITE, 0, |c, _m| c.args[2] as i64);
on_revoked!(writev_handler, SYS_WRITEV, 0, |c, _m| emu_writev(&c));
on_revoked!(pwritev_handler, SYS_PWRITEV, 0, |c, _m| emu_writev(&c));

on_revoked!(lseek_handler, SYS_LSEEK, 0, |_c, _m| 0);
on_revoked!(fsync_handler, SYS_FSYNC, 0, |_c, _m| 0);
on_revoked!(fdatasync_handler, SYS_FDATASYNC, 0, |_c, _m| 0);
on_revoked!(sync_file_range_handler, SYS_SYNC_FILE_RANGE, 0, |_c, _m| 0);
on_revoked!(flock_handler, SYS_FLOCK, 0, |_c, _m| 0);
on_revoked!(ftruncate_handler, SYS_FTRUNCATE, 0, |_c, _m| neg(EINVAL));
on_revoked!(ioctl_handler, SYS_IOCTL, 0, |_c, _m| neg(ENOTTY));

// Metadata of the real object must not leak, nor may it be modified.
on_revoked!(fstat_handler, SYS_FSTAT, 0, |_c, _m| neg(EACCES));
on_revoked!(fstatfs_handler, SYS_FSTATFS, 0, |_c, _m| neg(EACCES));
on_revoked!(fchmod_handler, SYS_FCHMOD, 0, |_c, _m| neg(EACCES));
on_revoked!(fchdir_handler, SYS_FCHDIR, 0, |_c, _m| neg(ENOTDIR));
on_revoked!(getdents_handler, SYS_GETDENTS, 0, |_c, _m| neg(ENOTDIR));

// mmap(addr, len, prot, flags, fd, off): fd is argument 5.
handler!(mmap_handler, |c| {
    let anon = (c.args[3] as u32 as i32) & MAP_ANON != 0;
    match c.revoked(4) {
        Some(m) if !anon => {
            log_emulated("mmap_handler", &c, 4, m);
            match m {
                // /dev/null cannot be mapped.
                Mode::Null => neg(ENODEV),
                // /dev/zero maps as fresh zero pages: make it anonymous.
                Mode::Zero => {
                    let mut a = c.args;
                    a[3] |= MAP_ANON as u64;
                    a[4] = (-1i64) as u64;
                    a[5] = 0;
                    let new_call = Call {
                        args: a,
                        cages: c.cages,
                    };
                    new_call.forward(SYS_MMAP)
                }
            }
        }
        _ => c.forward(SYS_MMAP),
    }
});

// ── Sockets: /dev/null is not a socket ──────────────────────────────

on_revoked!(bind_handler, SYS_BIND, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(listen_handler, SYS_LISTEN, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(connect_handler, SYS_CONNECT, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(accept_handler, SYS_ACCEPT, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(accept4_handler, SYS_ACCEPT4, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(shutdown_handler, SYS_SHUTDOWN, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(sendto_handler, SYS_SENDTO, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(recvfrom_handler, SYS_RECVFROM, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(sendmsg_handler, SYS_SENDMSG, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(recvmsg_handler, SYS_RECVMSG, 0, |_c, _m| neg(ENOTSOCK));
on_revoked!(setsockopt_handler, SYS_SETSOCKOPT, 0, |_c, _m| neg(
    ENOTSOCK
));
on_revoked!(getsockopt_handler, SYS_GETSOCKOPT, 0, |_c, _m| neg(
    ENOTSOCK
));
on_revoked!(getsockname_handler, SYS_GETSOCKNAME, 0, |_c, _m| neg(
    ENOTSOCK
));
on_revoked!(getpeername_handler, SYS_GETPEERNAME, 0, |_c, _m| neg(
    ENOTSOCK
));

// ── epoll ───────────────────────────────────────────────────────────

on_revoked!(epoll_wait_handler, SYS_EPOLL_WAIT, 0, |_c, _m| neg(EINVAL));

// epoll_ctl(epfd, op, fd, event)
handler!(epoll_ctl_handler, |c| {
    if let Some(m) = c.revoked(0) {
        log_emulated("epoll_ctl_handler", &c, 0, m);
        return neg(EINVAL);
    }
    if let Some(m) = c.revoked(2) {
        // /dev/null does not support epoll.
        log_emulated("epoll_ctl_handler", &c, 2, m);
        return neg(EPERM);
    }
    c.forward(SYS_EPOLL_CTL)
});

// ── *at calls with a revoked dirfd ──────────────────────────────────

macro_rules! at_handler {
    ($name:ident, $nr:expr, $(($d:expr, $p:expr)),+) => {
        handler!($name, |c| {
            $( if let Some(r) = at_blocked(&c, $d, $p) { return r; } )+
            c.forward($nr)
        });
    };
}

at_handler!(openat_handler, SYS_OPENAT, (0, 1));
at_handler!(unlinkat_handler, SYS_UNLINKAT, (0, 1));
at_handler!(readlinkat_handler, SYS_READLINKAT, (0, 1));
at_handler!(fchmodat_handler, SYS_FCHMODAT, (0, 1));
at_handler!(mkdirat_handler, SYS_MKDIRAT, (0, 1));
at_handler!(fchownat_handler, SYS_FCHOWNAT, (0, 1));
at_handler!(newfstatat_handler, SYS_NEWFSTATAT, (0, 1));
at_handler!(faccessat_handler, SYS_FACCESSAT, (0, 1));
at_handler!(utimensat_handler, SYS_UTIMENSAT, (0, 1));
at_handler!(statx_handler, SYS_STATX, (0, 1));
// symlinkat(target, newdirfd, linkpath)
at_handler!(symlinkat_handler, SYS_SYMLINKAT, (1, 2));
// renameat(olddirfd, oldpath, newdirfd, newpath)
at_handler!(renameat_handler, SYS_RENAMEAT, (0, 1), (2, 3));
at_handler!(renameat2_handler, SYS_RENAMEAT2, (0, 1), (2, 3));

// ── Descriptor lifecycle ────────────────────────────────────────────

handler!(close_handler, |c| {
    let r = c.forward(SYS_CLOSE);
    // Linux releases the fd even when close reports EINTR/EIO.
    if r != neg(EBADF) {
        state::unrevoke(c.cages[0], c.args[0]);
    }
    r
});

/// After a successful dup-like call that produced `newfd` from `oldfd`.
fn propagate_dup(cage: u64, oldfd: u64, newfd: u64) {
    if norm_fd(oldfd) == norm_fd(newfd) {
        return;
    }
    match state::lookup(cage, oldfd) {
        Some(m) => state::revoke(cage, newfd, m),
        // Slot overwritten by a non-revoked descriptor.
        None => state::unrevoke(cage, newfd),
    }
}

handler!(dup_handler, |c| {
    let r = c.forward(SYS_DUP);
    if r >= 0 {
        propagate_dup(c.cages[0], c.args[0], r as u64);
    }
    r
});

handler!(dup2_handler, |c| {
    let r = c.forward(SYS_DUP2);
    if r >= 0 {
        propagate_dup(c.cages[0], c.args[0], c.args[1]);
    }
    r
});

handler!(dup3_handler, |c| {
    let r = c.forward(SYS_DUP3);
    if r >= 0 {
        propagate_dup(c.cages[0], c.args[0], c.args[1]);
    }
    r
});

// fcntl(fd, cmd, arg): only the dup commands change the revocation table.
handler!(fcntl_handler, |c| {
    let cmd = c.args[1] as u32 as i32;
    let r = c.forward(SYS_FCNTL);
    if r >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        propagate_dup(c.cages[0], c.args[0], r as u64);
    }
    r
});

handler!(clone_handler, |c| {
    let parent = c.cages[0];
    let r = c.forward(SYS_CLONE);
    // Threads share the cage (and its fd table); only real forks inherit.
    if r > 0 && !is_thread_clone(c.args[0], c.cages[0]) {
        state::add_cage(r as u64, parent);
        state::inherit(parent, r as u64);
    }
    r
});

// ── The revoke syscall ──────────────────────────────────────────────

/// Permission hook for `revoke`. Every revoke passes through here exactly
/// once, before any state changes; returning `Err(errno)` refuses it.
///
/// Currently allows everything. A descendant-only policy (like `kill`) would
/// walk `state::parent_of` from `target` up to `caller`.
///
/// Caveat: `caller` comes from the argument cage IDs, which the calling cage
/// supplies itself. 3i does not pass the grate an unforgeable caller ID, so
/// any check built on this hook trusts that value.
fn authorize(_caller: u64, _target: u64, _fd: u64) -> Result<(), i32> {
    Ok(())
}

// revoke(target_cage, fd, flags). See abi.rs.
handler!(revoke_handler, |c| {
    let caller = c.cages[0];
    let target = c.args[0];
    let fd_raw = c.args[1] as u32 as i32;
    let flags = c.args[2] as u32;

    let mode = match abi::decode_flags(flags) {
        Some(m) => m,
        None => return neg(EINVAL),
    };
    if fd_raw < 0 {
        return neg(EBADF);
    }
    let fd = fd_raw as u64;
    if !state::is_known_cage(target) {
        return neg(ESRCH);
    }
    if let Err(e) = authorize(caller, target, fd) {
        return neg(e);
    }
    // Only an open descriptor can be revoked. This also catches a target that
    // has exited (3i returns ESRCH for calls into a dead cage).
    let r = fcntl_getfd(target, fd);
    if r < 0 {
        return r;
    }
    state::revoke(target, fd, mode);

    log(format!(
        "[revoke-grate] cage {} revoked cage {} fd {} as {:?}",
        caller, target, fd, mode
    )
    .as_str());

    0
});

handler!(exec_handler, |c| {
    let cage = c.cages[0];
    // Drop revocations whose real fd is close-on-exec; the rest survive exec.
    for (fd, _) in state::fds_of(cage) {
        let new_call = Call {
            args: [fd, F_GETFD as u64, 0, 0, 0, 0],
            cages: [cage; 6],
        };
        let flags = new_call.forward(SYS_FCNTL);
        if flags >= 0 && flags & (FD_CLOEXEC as i64) != 0 {
            state::unrevoke(cage, fd);
        }
    }
    c.forward(SYS_EXECVE)
});

/// `fcntl(fd, F_GETFD)` in `cage`, on its behalf.
fn fcntl_getfd(cage: u64, fd: u64) -> i64 {
    let new_call = Call {
        args: [fd, F_GETFD as u64, 0, 0, 0, 0],
        cages: [cage; 6],
    };
    new_call.forward(SYS_FCNTL)
}

/// Ask the kernel layer whether `fd` is currently open in `cage`.
pub fn fd_is_open(cage: u64, fd: u64) -> bool {
    fcntl_getfd(cage, fd) >= 0
}

/// Every (syscall, handler) pair this grate registers.
pub fn handler_table() -> Vec<(u64, SyscallHandler)> {
    vec![
        (SYS_READ, read_handler as SyscallHandler),
        (SYS_PREAD, pread_handler),
        (SYS_READV, readv_handler),
        (SYS_PREADV, preadv_handler),
        (SYS_WRITE, write_handler),
        (SYS_PWRITE, pwrite_handler),
        (SYS_WRITEV, writev_handler),
        (SYS_PWRITEV, pwritev_handler),
        (SYS_LSEEK, lseek_handler),
        (SYS_FSYNC, fsync_handler),
        (SYS_FDATASYNC, fdatasync_handler),
        (SYS_SYNC_FILE_RANGE, sync_file_range_handler),
        (SYS_FLOCK, flock_handler),
        (SYS_FTRUNCATE, ftruncate_handler),
        (SYS_IOCTL, ioctl_handler),
        (SYS_FSTAT, fstat_handler),
        (SYS_FSTATFS, fstatfs_handler),
        (SYS_FCHMOD, fchmod_handler),
        (SYS_FCHDIR, fchdir_handler),
        (SYS_GETDENTS, getdents_handler),
        (SYS_MMAP, mmap_handler),
        (SYS_BIND, bind_handler),
        (SYS_LISTEN, listen_handler),
        (SYS_CONNECT, connect_handler),
        (SYS_ACCEPT, accept_handler),
        (SYS_ACCEPT4, accept4_handler),
        (SYS_SHUTDOWN, shutdown_handler),
        (SYS_SENDTO, sendto_handler),
        (SYS_RECVFROM, recvfrom_handler),
        (SYS_SENDMSG, sendmsg_handler),
        (SYS_RECVMSG, recvmsg_handler),
        (SYS_SETSOCKOPT, setsockopt_handler),
        (SYS_GETSOCKOPT, getsockopt_handler),
        (SYS_GETSOCKNAME, getsockname_handler),
        (SYS_GETPEERNAME, getpeername_handler),
        (SYS_EPOLL_WAIT, epoll_wait_handler),
        (SYS_EPOLL_CTL, epoll_ctl_handler),
        (SYS_OPENAT, openat_handler),
        (SYS_UNLINKAT, unlinkat_handler),
        (SYS_READLINKAT, readlinkat_handler),
        (SYS_FCHMODAT, fchmodat_handler),
        (SYS_MKDIRAT, mkdirat_handler),
        (SYS_FCHOWNAT, fchownat_handler),
        (SYS_NEWFSTATAT, newfstatat_handler),
        (SYS_FACCESSAT, faccessat_handler),
        (SYS_UTIMENSAT, utimensat_handler),
        (SYS_STATX, statx_handler),
        (SYS_SYMLINKAT, symlinkat_handler),
        (SYS_RENAMEAT, renameat_handler),
        (SYS_RENAMEAT2, renameat2_handler),
        (SYS_CLOSE, close_handler),
        (SYS_DUP, dup_handler),
        (SYS_DUP2, dup2_handler),
        (SYS_DUP3, dup3_handler),
        (SYS_FCNTL, fcntl_handler),
        (SYS_CLONE, clone_handler),
        (SYS_EXECVE, exec_handler),
        (abi::SYS_REVOKE, revoke_handler),
    ]
}
