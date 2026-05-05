use crate::{register_handler, make_threei_call, GrateError, SyscallHandler};
use crate::constants::*;

#[derive(Debug, Clone, Copy)]
pub enum FdArgKind {
    /// Normal fd, must exist in fdtables.
    Fd,

    /// Directory fd used by *at syscalls.
    /// AT_FDCWD = -100 should not be translated.
    DirFd,

    /// Existing fd that must be translated, e.g. dup oldfd.
    OldFd,

    /// Target fd number supplied by the user, e.g. dup2/dup3 newfd.
    /// This is usually NOT translated the same way as an existing fd.
    NewFd,
}

#[derive(Debug, Clone, Copy)]
pub struct FdArgSpec {
    pub index: usize,
    pub kind: FdArgKind,
}

#[derive(Debug, Clone, Copy)]
pub struct SyscallFdSpec {
    pub syscall_num: u64,
    pub fd_args: &'static [FdArgSpec],
}

pub const FD_ARG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
];

pub const FD_ARG_1_AND_2: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
    FdArgSpec { index: 1, kind: FdArgKind::Fd },
];

pub const OLD0_NEW1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::OldFd },
    FdArgSpec { index: 1, kind: FdArgKind::NewFd },
];

pub const DIRFD_ARG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
];

pub const DIRFD_ARG_1_AND_3: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
    FdArgSpec { index: 2, kind: FdArgKind::DirFd },
];

pub const X86_64_FD_SYSCALL_SPECS: &[SyscallFdSpec] = &[
    SyscallFdSpec { syscall_num: SYS_READ, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_WRITE, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_CLOSE, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FCNTL, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_LSEEK, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_IOCTL, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FSTAT, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FSYNC, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FDATASYNC, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FTRUNCATE, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FLOCK, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FCHDIR, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FCHMOD, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_GETDENTS, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FSTATFS, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FSYNC_FILE_RANGE, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_PREAD, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_PWRITE, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_READV, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_WRITEV, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_BIND, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_LISTEN, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_CONNECT, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_SHUTDOWN, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_SENDTO, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_RECVFROM, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_SENDMSG, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_RECVMSG, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_SETSOCKOPT, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_GETSOCKOPT, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_GETSOCKNAME, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_GETPEERNAME, fd_args: FD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_EPOLL_WAIT, fd_args: FD_ARG_1 },
    
    SyscallFdSpec { syscall_num: SYS_OPENAT, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_MKDIR, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_MKNOD, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_UNLINKAT, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_SYMLINKAT, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_READLINKAT, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_FCHMOD, fd_args: DIRFD_ARG_1 },
    SyscallFdSpec { syscall_num: SYS_ACCESS, fd_args: DIRFD_ARG_1 },

];

const AT_FDCWD_U64: u64 = (-100i64) as u64;
const EBADF: u64 = (-9i64) as u64;
const ENOSYS: u64 = (-38i64) as u64;

fn find_fd_spec(syscall_num: u64) -> Option<&'static SyscallFdSpec> {
    X86_64_FD_SYSCALL_SPECS
        .iter()
        .find(|spec| spec.syscall_num == syscall_num)
}

fn translate_to_underfd(cage: u64, fd: u64) -> Option<u64> {
    fdtables::translate_virtual_fd(cage, fd).ok().map(|e| e.underfd)
}

fn translate_fd_arg(cageid: u64, arg: u64, kind: FdArgKind) -> Result<u64, u64> {
    match kind {
        FdArgKind::Fd | FdArgKind::OldFd => {
            translate_to_underfd(cageid, arg).ok_or(EBADF)
        }

        FdArgKind::DirFd => {
            if arg == AT_FDCWD_U64 {
                Ok(arg)
            } else {
                translate_to_underfd(cageid, arg).ok_or(EBADF)
            }
        }

        FdArgKind::NewFd => {
            // todo: add logic here
            Ok(arg)
        }
    }
}

fn fd_handler_impl(
    syscall_num: u64,
    fd_specs: &'static [FdArgSpec],

    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let argcages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    for spec in fd_specs {
        let old_fd = args[spec.index];

        match translate_fd_arg(cageid, old_fd, spec.kind) {
            Ok(underfd) => {
                args[spec.index] = underfd;
            }
            Err(errno_ret) => {
                return errno_ret as i32;
            }
        }
    }

    match make_threei_call(
        syscall_num as u32,
        0, 
        cageid,
        arg1cage,
        args[0],
        argcages[0],
        args[1],
        argcages[1],
        args[2],
        argcages[2],
        args[3],
        argcages[3],
        args[4],
        argcages[4],
        args[5],
        argcages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(GrateError::MakeSyscallError(ret)) => ret,
        Err(_) => ENOSYS as i32,
    }
}

macro_rules! define_fd_handler {
    (
        $handler_name:ident,
        $syscall_num:expr,
        $fd_specs:expr
    ) => {
        pub extern "C" fn $handler_name(
            cageid: u64,
            arg1: u64,
            arg1cage: u64,
            arg2: u64,
            arg2cage: u64,
            arg3: u64,
            arg3cage: u64,
            arg4: u64,
            arg4cage: u64,
            arg5: u64,
            arg5cage: u64,
            arg6: u64,
            arg6cage: u64,
        ) -> i32 {
            fd_handler_impl(
                $syscall_num,
                $fd_specs,
                cageid,
                arg1,
                arg1cage,
                arg2,
                arg2cage,
                arg3,
                arg3cage,
                arg4,
                arg4cage,
                arg5,
                arg5cage,
                arg6,
                arg6cage,
            )
        }
    };
}

define_fd_handler!(fd_read_handler, SYS_READ, FD_ARG_1);
define_fd_handler!(fd_write_handler, SYS_WRITE, FD_ARG_1);
define_fd_handler!(fd_close_handler, SYS_CLOSE, FD_ARG_1);
define_fd_handler!(fd_fstat_handler, SYS_FSTAT, FD_ARG_1);
define_fd_handler!(fd_lseek_handler, SYS_LSEEK, FD_ARG_1);
define_fd_handler!(fd_ioctl_handler, SYS_IOCTL, FD_ARG_1);
define_fd_handler!(fd_pread64_handler, SYS_PREAD, FD_ARG_1);
define_fd_handler!(fd_pwrite64_handler, SYS_PWRITE, FD_ARG_1);
define_fd_handler!(fd_readv_handler, SYS_READV, FD_ARG_1);
define_fd_handler!(fd_writev_handler, SYS_WRITEV, FD_ARG_1);
define_fd_handler!(fd_dup_handler, SYS_DUP, FD_ARG_1);
// define_fd_handler!(fd_dup2_handler, SYS_DUP2, OLD_FD_ARG_1_NEW_FD_ARG_2);
// define_fd_handler!(fd_dup3_handler, SYS_DUP3, OLD_FD_ARG_1_NEW_FD_ARG_2);
define_fd_handler!(fd_sendmsg_handler, SYS_SENDMSG, FD_ARG_1);
define_fd_handler!(fd_fcntl_handler, SYS_FCNTL, FD_ARG_1);

define_fd_handler!(fd_openat_handler, SYS_OPENAT, DIRFD_ARG_1);
define_fd_handler!(fd_renameat_handler, SYS_RENAME, DIRFD_ARG_1_AND_3);
define_fd_handler!(fd_linkat_handler, SYS_LINK, DIRFD_ARG_1_AND_3);

pub const FD_HANDLER_TABLE: &[(u64, SyscallHandler)] = &[
    (SYS_READ, fd_read_handler as SyscallHandler),
    (SYS_WRITE, fd_write_handler as SyscallHandler),
    (SYS_CLOSE, fd_close_handler as SyscallHandler),
    (SYS_FSTAT, fd_fstat_handler as SyscallHandler),
    (SYS_LSEEK, fd_lseek_handler as SyscallHandler),
    (SYS_IOCTL, fd_ioctl_handler as SyscallHandler),
    (SYS_PREAD, fd_pread64_handler as SyscallHandler),
    (SYS_PWRITE, fd_pwrite64_handler as SyscallHandler),
    (SYS_READV, fd_readv_handler as SyscallHandler),
    (SYS_WRITEV, fd_writev_handler as SyscallHandler),
    (SYS_DUP, fd_dup_handler as SyscallHandler),
    // (SYS_DUP2, fd_dup2_handler as SyscallHandler),
    // (SYS_DUP3, fd_dup3_handler as SyscallHandler),
    (SYS_SENDMSG, fd_sendmsg_handler as SyscallHandler),
    (SYS_FCNTL, fd_fcntl_handler as SyscallHandler),
    (SYS_OPENAT, fd_openat_handler as SyscallHandler),
];

pub fn register_single_default_fd_handler(
    cageid: u64,
    syscall_num: u64,
    grateid: u64,
    handler: SyscallHandler,
) -> Result<(), GrateError> {
    register_handler(cageid, syscall_num, grateid, handler)
}

pub fn register_default_fd_handlers_except(
    cageid: u64,
    grateid: u64,
    except_syscalls: &[u64],
) -> Result<(), GrateError> {
    for &(syscall_nr, handler) in FD_HANDLER_TABLE {
        if except_syscalls.contains(&syscall_nr) {
            continue;
        }

        if let Err(e) = register_handler(cageid, syscall_nr, grateid, handler) {
            eprintln!(
                "failed to register fd syscall handler: syscall_nr={}, grateid={}, err={:?}",
                syscall_nr, grateid, e
            );
            return Err(e);
        }
    }

    Ok(())
}
