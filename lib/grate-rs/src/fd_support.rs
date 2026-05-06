use crate::{make_threei_call, GrateError, SyscallHandler};
use crate::constants::error::{EBADF, ENOSYS, EMFILE};
use crate::constants::syscall_numbers::*;

// todo:
// fcntl: check for F_DUPFD, F_DUPFD_CLOEXEC and handle fd translation for the new fd.
// dup2, dup3: handle individually

pub const FDKIND_KERNEL: u32 = 1;
pub const O_CLOEXEC: i32 = 0o2000000; // Close on exec

#[derive(Debug, Clone, Copy)]
pub enum FdArgKind {
    /// Normal fd, must exist in fdtables.
    Fd,

    /// Directory fd used by *at syscalls.
    /// AT_FDCWD = -100 should not be translated.
    DirFd,

    /// Existing fd that must be translated, e.g. dup oldfd.
    OldFd,

    /// todo: integrate with current logic
    NewFd,

    FLAG,
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

pub const CREATION_DIRFD_1_FLAG_3: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
    FdArgSpec { index: 2, kind: FdArgKind::FLAG },
];

pub const CREATION_FLAG_2: &[FdArgSpec] = &[
    FdArgSpec { index: 1, kind: FdArgKind::FLAG },
];

pub const CREATION_FD_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
];

pub const FD_ARG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
];

pub const FD_ARG_1_AND_2: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
    FdArgSpec { index: 1, kind: FdArgKind::Fd },
];

pub const DIRFD_ARG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
];

pub const DIRFD_ARG_1_AND_3: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
    FdArgSpec { index: 2, kind: FdArgKind::DirFd },
];

const AT_FDCWD_U64: u64 = (-100i64) as u64;

fn translate_to_underfd(cage: u64, fd: u64) -> Option<u64> {
    fdtables::translate_virtual_fd(cage, fd).ok().map(|e| e.underfd)
}

fn translate_fd_arg(cageid: u64, arg: u64, kind: FdArgKind) -> Result<u64, u64> {
    match kind {
        FdArgKind::Fd | FdArgKind::OldFd => {
            println!("[translate_fd_arg] translating fd arg: cageid={}, arg={}, kind={:?}", cageid, arg, kind);
            translate_to_underfd(cageid, arg).ok_or(EBADF as u64)
        }

        FdArgKind::DirFd => {
            if arg == AT_FDCWD_U64 {
                Ok(arg)
            } else {
                translate_to_underfd(cageid, arg).ok_or(EBADF as u64)
            }
        }

        FdArgKind::NewFd => {
            // todo: add logic here
            todo!()
        }

        FdArgKind::FLAG => todo!(),
    }
}

fn fd_creation_handler_impl(
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

    let kernel_fd = match make_threei_call(
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
        Err(_) => ENOSYS,
    };

    let should_cloexec = ((arg2 as i32) & O_CLOEXEC) != 0;
    match fdtables::get_unused_virtual_fd(arg1cage, FDKIND_KERNEL, kernel_fd as u64, should_cloexec, 0) {
        Ok(vfd) => vfd as i32,
        Err(_) => EMFILE, // Too many open files
    }
}


fn fd_translation_handler_impl(
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
    println!("[fd_translation_handler_impl] syscall_num={}, cageid={}", syscall_num, cageid);
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let argcages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    for spec in fd_specs {
        let old_fd = args[spec.index];
        println!("[fd_translation_handler_impl] translating fd arg: index={}, old_fd={}, oldfd_cageid={}", spec.index, old_fd, argcages[spec.index]);
        match translate_fd_arg(argcages[spec.index], old_fd, spec.kind) {
            Ok(underfd) => {
                println!("[fd_translation_handler_impl] translated fd arg: index={}, underfd={}", spec.index, underfd);
                args[spec.index] = underfd;
                
            }
            Err(errno_ret) => {
                println!("[fd_translation_handler_impl] fd translation failed: index={}, old_fd={}, errno={}", spec.index, old_fd, errno_ret);
                return errno_ret as i32;
            }
        }
    }

    println!("[fd_support] syscall_num={}", syscall_num);

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
        Err(_) => ENOSYS,
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
            fd_translation_handler_impl(
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

macro_rules! define_fd_creation_handler {
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
            fd_creation_handler_impl(
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
define_fd_handler!(fd_fcntl_handler, SYS_FCNTL, FD_ARG_1);
define_fd_handler!(fd_lseek_handler, SYS_LSEEK, FD_ARG_1);
define_fd_handler!(fd_ioctl_handler, SYS_IOCTL, FD_ARG_1);
define_fd_handler!(fd_fstat_handler, SYS_FSTAT, FD_ARG_1);
define_fd_handler!(fd_fsync_handler, SYS_FSYNC, FD_ARG_1);
define_fd_handler!(fd_fdatasync_handler, SYS_FDATASYNC, FD_ARG_1);
define_fd_handler!(fd_ftruncate_handler, SYS_FTRUNCATE, FD_ARG_1);
define_fd_handler!(fd_flock_handler, SYS_FLOCK, FD_ARG_1);
define_fd_handler!(fd_fchdir_handler, SYS_FCHDIR, FD_ARG_1);
define_fd_handler!(fd_getdents_handler, SYS_GETDENTS, FD_ARG_1);
define_fd_handler!(fd_fstatfs_handler, SYS_FSTATFS, FD_ARG_1);
define_fd_handler!(fd_sync_file_range_handler, SYS_SYNC_FILE_RANGE, FD_ARG_1);
define_fd_handler!(fd_pread_handler, SYS_PREAD, FD_ARG_1);
define_fd_handler!(fd_pwrite_handler, SYS_PWRITE, FD_ARG_1);
define_fd_handler!(fd_readv_handler, SYS_READV, FD_ARG_1);
define_fd_handler!(fd_writev_handler, SYS_WRITEV, FD_ARG_1);
define_fd_handler!(fd_bind_handler, SYS_BIND, FD_ARG_1);
define_fd_handler!(fd_listen_handler, SYS_LISTEN, FD_ARG_1);
define_fd_handler!(fd_connect_handler, SYS_CONNECT, FD_ARG_1);
define_fd_handler!(fd_shutdown_handler, SYS_SHUTDOWN, FD_ARG_1);
define_fd_handler!(fd_sendto_handler, SYS_SENDTO, FD_ARG_1);
define_fd_handler!(fd_recvfrom_handler, SYS_RECVFROM, FD_ARG_1);
define_fd_handler!(fd_sendmsg_handler, SYS_SENDMSG, FD_ARG_1);
define_fd_handler!(fd_recvmsg_handler, SYS_RECVMSG, FD_ARG_1);
define_fd_handler!(fd_setsockopt_handler, SYS_SETSOCKOPT, FD_ARG_1);
define_fd_handler!(fd_getsockopt_handler, SYS_GETSOCKOPT, FD_ARG_1);
define_fd_handler!(fd_getsockname_handler, SYS_GETSOCKNAME, FD_ARG_1);
define_fd_handler!(fd_getpeername_handler, SYS_GETPEERNAME, FD_ARG_1);
define_fd_handler!(fd_epoll_wait_handler, SYS_EPOLL_WAIT, FD_ARG_1);

define_fd_handler!(fd_openat_handler, SYS_OPENAT, DIRFD_ARG_1);
define_fd_handler!(fd_mkdir_handler, SYS_MKDIR, DIRFD_ARG_1);
define_fd_handler!(fd_mknod_handler, SYS_MKNOD, DIRFD_ARG_1);
define_fd_handler!(fd_unlinkat_handler, SYS_UNLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_symlinkat_handler, SYS_SYMLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_readlinkat_handler, SYS_READLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_access_handler, SYS_ACCESS, DIRFD_ARG_1);
// define_fd_handler!(fd_dup2_handler, SYS_DUP2, OLD_FD_ARG_1_NEW_FD_ARG_2);
// define_fd_handler!(fd_dup3_handler, SYS_DUP3, OLD_FD_ARG_1_NEW_FD_ARG_2);

define_fd_creation_handler!(fd_creating_open_handler, SYS_OPEN, CREATION_FLAG_2);
define_fd_creation_handler!(fd_creating_openat_handler, SYS_OPENAT, CREATION_DIRFD_1_FLAG_3);

pub const FD_HANDLER_TABLE: &[(u64, SyscallHandler)] = &[
    (SYS_READ, fd_read_handler as SyscallHandler),
    (SYS_WRITE, fd_write_handler as SyscallHandler),
    (SYS_CLOSE, fd_close_handler as SyscallHandler),
    (SYS_FCNTL, fd_fcntl_handler as SyscallHandler),
    (SYS_LSEEK, fd_lseek_handler as SyscallHandler),
    (SYS_IOCTL, fd_ioctl_handler as SyscallHandler),
    (SYS_FSTAT, fd_fstat_handler as SyscallHandler),
    (SYS_FSYNC, fd_fsync_handler as SyscallHandler),
    (SYS_FDATASYNC, fd_fdatasync_handler as SyscallHandler),
    (SYS_FTRUNCATE, fd_ftruncate_handler as SyscallHandler),
    (SYS_FLOCK, fd_flock_handler as SyscallHandler),
    (SYS_FCHDIR, fd_fchdir_handler as SyscallHandler),
    (SYS_GETDENTS, fd_getdents_handler as SyscallHandler),
    (SYS_FSTATFS, fd_fstatfs_handler as SyscallHandler),
    (SYS_SYNC_FILE_RANGE, fd_sync_file_range_handler as SyscallHandler),
    (SYS_PREAD, fd_pread_handler as SyscallHandler),
    (SYS_PWRITE, fd_pwrite_handler as SyscallHandler),
    (SYS_READV, fd_readv_handler as SyscallHandler),
    (SYS_WRITEV, fd_writev_handler as SyscallHandler),
    // (SYS_DUP2, fd_dup2_handler as SyscallHandler),
    // (SYS_DUP3, fd_dup3_handler as SyscallHandler),

    (SYS_BIND, fd_bind_handler as SyscallHandler),
    (SYS_LISTEN, fd_listen_handler as SyscallHandler),
    (SYS_CONNECT, fd_connect_handler as SyscallHandler),
    (SYS_SHUTDOWN, fd_shutdown_handler as SyscallHandler),
    (SYS_SENDTO, fd_sendto_handler as SyscallHandler),
    (SYS_RECVFROM, fd_recvfrom_handler as SyscallHandler),
    (SYS_SENDMSG, fd_sendmsg_handler as SyscallHandler),
    (SYS_RECVMSG, fd_recvmsg_handler as SyscallHandler),
    (SYS_SETSOCKOPT, fd_setsockopt_handler as SyscallHandler),
    (SYS_GETSOCKOPT, fd_getsockopt_handler as SyscallHandler),
    (SYS_GETSOCKNAME, fd_getsockname_handler as SyscallHandler),
    (SYS_GETPEERNAME, fd_getpeername_handler as SyscallHandler),
    (SYS_EPOLL_WAIT, fd_epoll_wait_handler as SyscallHandler),

    (SYS_OPENAT, fd_openat_handler as SyscallHandler),
    (SYS_MKDIR, fd_mkdir_handler as SyscallHandler),
    (SYS_MKNOD, fd_mknod_handler as SyscallHandler),
    (SYS_UNLINKAT, fd_unlinkat_handler as SyscallHandler),
    (SYS_SYMLINKAT, fd_symlinkat_handler as SyscallHandler),
    (SYS_READLINKAT, fd_readlinkat_handler as SyscallHandler),
    (SYS_ACCESS, fd_access_handler as SyscallHandler),
];
