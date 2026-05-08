use crate::{make_threei_call, GrateError, SyscallHandler};
use crate::constants::error::{EBADF, ENOSYS, EMFILE};
use crate::constants::syscall_numbers::*;
use crate::constants::fs::*;

#[derive(Eq, PartialEq, Default, Copy, Clone, Debug)]
#[repr(C)]
pub struct SockPair {
    pub sock1: i32,
    pub sock2: i32,
}

pub const FDKIND_KERNEL: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq)]
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

    FcntlFd,

    SOCKPAIR,

    POLLFD,

    EPFD,

    FLAG,

    CREAT,
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

pub const CREATION: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const CREATION_DIRFD_1_FLAG_3: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
    FdArgSpec { index: 2, kind: FdArgKind::FLAG },
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const CREATION_FLAG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::FLAG },
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const CREATION_FLAG_2: &[FdArgSpec] = &[
    FdArgSpec { index: 1, kind: FdArgKind::FLAG },
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const CREATION_FD_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const CREATION_DIRFD_ARG_1_FLAG: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::DirFd },
    FdArgSpec { index: 2, kind: FdArgKind::FLAG },
    FdArgSpec { index: 0, kind: FdArgKind::CREAT },
];

pub const FD_ARG_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
];

pub const FD_ARG_5: &[FdArgSpec] = &[
    FdArgSpec { index: 4, kind: FdArgKind::Fd },
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

pub const OLD_FD_1_NEW_FD_2: &[FdArgSpec] = &[
    FdArgSpec { index: 1, kind: FdArgKind::NewFd },
    FdArgSpec { index: 0, kind: FdArgKind::OldFd },
];

pub const OLD_FD_1_NEW_FD_2_FLAG: &[FdArgSpec] = &[
    FdArgSpec { index: 1, kind: FdArgKind::NewFd },
    FdArgSpec { index: 0, kind: FdArgKind::OldFd },
    FdArgSpec { index: 2, kind: FdArgKind::FLAG },
];

pub const FCNTL_FD_1_FLAG_2: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::FcntlFd },
];

pub const SOCKPAIR: &[FdArgSpec] = &[
    FdArgSpec { index: 3, kind: FdArgKind::SOCKPAIR },
    FdArgSpec { index: 1, kind: FdArgKind::FLAG },
];

pub const POLL_1: &[FdArgSpec] = &[
    FdArgSpec { index: 0, kind: FdArgKind::POLLFD },
];

pub const EPOLL_1_FD_3: &[FdArgSpec] = &[
    FdArgSpec { index: 2, kind: FdArgKind::EPFD },
    FdArgSpec { index: 0, kind: FdArgKind::Fd },
];

const AT_FDCWD_U64: u64 = (-100i64) as u64;

fn translate_fd_arg(cageid: u64, arg: u64, kind: FdArgKind) -> Result<u64, u64> {
    if kind == FdArgKind::DirFd && arg == AT_FDCWD_U64 {
        return Ok(arg);
    }
    
    match fdtables::translate_virtual_fd(cageid, arg) {
        Ok(vfd) => Ok(vfd.underfd),
        Err(_) => {
            Err(EBADF as u64)
        }
    }
}

fn fd_translation_handler_impl(
    syscall_num: u64,
    fd_specs: &'static [FdArgSpec],

    this_grateid: u64,
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
    let mut argcages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let mut should_create_vfd = false;
    let mut should_cloexec = false;
    let mut should_socketpair = false;
    let mut should_poll = false;

    let mut old_fd_entry = fdtables::FDTableEntry {
        fdkind: 0,
        underfd: 0,
        should_cloexec: false,
        perfdinfo: 0,
    };
    let mut old_fd_cageid = 0;

    let mut new_fd = 0;
    let mut new_fd_cageid = 0;

    let mut should_dup2 = false;

    let mut origin_socket_vector_ptr: u64 = 0;
    let mut kernel_socket_vector: [i32; 2] = [0, 0];

    let mut pollfds_ptr: *mut libc::pollfd = std::ptr::null_mut();
    let mut pollfd_cageid: u64 = 0;

    for spec in fd_specs {
        match spec.kind {
            FdArgKind::Fd | FdArgKind::DirFd => {
                let kernel_fd = args[spec.index];
                let fd_cageid = argcages[spec.index];

                if syscall_num == SYS_MMAP {
                    // For mmap, we only translate the fd if it's not -1 (i.e. not MAP_ANONYMOUS)
                    if kernel_fd == u64::MAX {
                        continue;
                    }
                }

                match translate_fd_arg(fd_cageid, kernel_fd, spec.kind) {
                    Ok(underfd) => {

                        args[spec.index] = underfd;

                        if syscall_num == SYS_CLOSE {
                            let _ = fdtables::close_virtualfd(fd_cageid, kernel_fd);
                        }
                    }

                    Err(errno_ret) => {
                        return -(errno_ret as i32);
                    }
                }
            }
            
            FdArgKind::NewFd => {
                // newfd will always be the first one to loop
                should_dup2 = true;
                new_fd = args[spec.index];
                new_fd_cageid = argcages[spec.index];
            }

            FdArgKind::OldFd => {
                old_fd_entry = match fdtables::translate_virtual_fd(argcages[spec.index], args[spec.index]) {
                    Ok(entry) => entry,
                    Err(_) => {
                        return EBADF as i32;
                    }
                };
                old_fd_cageid = argcages[spec.index];
                args[spec.index] = old_fd_entry.underfd;
            }

            FdArgKind::FcntlFd => {
                let kernel_fd = args[0];
                let fd_cageid = argcages[0];

                match translate_fd_arg(fd_cageid, kernel_fd, FdArgKind::Fd) {
                    Ok(underfd) => {
                        args[0] = underfd;

                        let flags = args[2] as i32;
                        should_cloexec |= (flags & O_CLOEXEC) != 0;

                        if flags & F_DUPFD != 0 || flags & F_DUPFD_CLOEXEC != 0 {
                            should_create_vfd = true;
                        }
                    }

                    Err(errno_ret) => {
                        return -(errno_ret as i32);
                    }
                }
            }

            FdArgKind::SOCKPAIR => {
                should_socketpair = true;
                origin_socket_vector_ptr = args[spec.index];
                args[spec.index] = kernel_socket_vector.as_ptr() as u64;
                argcages[spec.index] = this_grateid;
            }

            FdArgKind::POLLFD => {
                should_poll = true;
                pollfds_ptr = args[spec.index] as *mut libc::pollfd;
                pollfd_cageid = argcages[spec.index];
                let nfds = args[spec.index + 1] as libc::nfds_t;

                if !pollfds_ptr.is_null() {
                    for i in 0..nfds {
                        unsafe {
                            let pollfd_ptr = pollfds_ptr.add(i as usize);
                            let kernel_fd = (*pollfd_ptr).fd;

                            // Per POSIX/Linux poll semantics, negative fd means ignored.
                            // Do not translate it.
                            if kernel_fd < 0 {
                                continue;
                            }

                            match translate_fd_arg(pollfd_cageid, kernel_fd as u64, FdArgKind::Fd) {
                                Ok(underfd) => {
                                    (*pollfd_ptr).fd = underfd as i32;
                                }

                                Err(errno_ret) => {
                                    return -(errno_ret as i32);
                                }
                            }
                        }
                    }
                }

            }

            FdArgKind::EPFD => {
                args[spec.index] = *fdtables::epoll_get_underfd_hashmap(this_grateid, argcages[spec.index])
                    .unwrap()
                    .get(&FDKIND_KERNEL)
                    .unwrap();
                argcages[spec.index] = this_grateid;
            }

            FdArgKind::FLAG => {
                should_cloexec |= ((args[spec.index] as i32) & O_CLOEXEC) != 0;
            }

            FdArgKind::CREAT => {
                should_create_vfd = true;
            }
        }
    }

    let ret = match make_threei_call(
        syscall_num as u32,
        0,
        this_grateid,
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

    // syscall failed, do not create vfd and do not mutate fdtable.
    if ret < 0 {
        return ret;
    }

    if should_dup2 {
        let flags = fd_specs
            .iter()
            .find(|spec| matches!(spec.kind, FdArgKind::FLAG))
            .map(|spec| args[spec.index] as i32)
            .unwrap_or(0);

        match fdtables::get_specific_virtual_fd(
            old_fd_cageid,
            new_fd,
            FDKIND_KERNEL,
            ret as u64,
            should_cloexec,
            0,
        ) {
            Ok(_) => return new_fd as i32,
            Err(_) => return EMFILE,
        }
    }

    if should_create_vfd {
        let kernel_fd = ret;

        return match fdtables::get_unused_virtual_fd(
            arg1cage,
            FDKIND_KERNEL,
            kernel_fd as u64,
            should_cloexec,
            0,
        ) {
            Ok(vfd) => vfd as i32,
            Err(_) => EMFILE,
        };
    }

    if should_socketpair {
        let ksv_1 = kernel_socket_vector[0];
        let ksv_2 = kernel_socket_vector[1];
        let vsv_1 =
            fdtables::get_unused_virtual_fd(arg1cage, FDKIND_KERNEL, ksv_1 as u64, should_cloexec, 0).unwrap();
        let vsv_2 =
            fdtables::get_unused_virtual_fd(arg1cage, FDKIND_KERNEL, ksv_2 as u64, should_cloexec, 0).unwrap();
        let virtual_socket_vector = origin_socket_vector_ptr as *mut SockPair;
        unsafe {
            (*virtual_socket_vector).sock1 = vsv_1 as i32;
            (*virtual_socket_vector).sock2 = vsv_2 as i32;
        }
    }

    if should_poll {
        args[0] = pollfds_ptr as u64;
    }

    ret
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
define_fd_handler!(fd_mmap_handler, SYS_MMAP, FD_ARG_5);

define_fd_handler!(fd_mkdir_handler, SYS_MKDIR, DIRFD_ARG_1);
define_fd_handler!(fd_mknod_handler, SYS_MKNOD, DIRFD_ARG_1);
define_fd_handler!(fd_unlinkat_handler, SYS_UNLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_symlinkat_handler, SYS_SYMLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_readlinkat_handler, SYS_READLINKAT, DIRFD_ARG_1);
define_fd_handler!(fd_access_handler, SYS_ACCESS, DIRFD_ARG_1);

define_fd_handler!(fd_open_handler, SYS_OPEN, CREATION_FLAG_2);
define_fd_handler!(fd_openat_handler, SYS_OPENAT, CREATION_DIRFD_ARG_1_FLAG);
define_fd_handler!(fd_dup_handler, SYS_DUP, CREATION_FD_1);
define_fd_handler!(fd_dup2_handler, SYS_DUP2, OLD_FD_1_NEW_FD_2);
define_fd_handler!(fd_dup3_handler, SYS_DUP3, OLD_FD_1_NEW_FD_2_FLAG);
define_fd_handler!(fd_fcntl_handler, SYS_FCNTL, FCNTL_FD_1_FLAG_2);

define_fd_handler!(fd_socket_handler, SYS_SOCKET, CREATION_FLAG_2);
define_fd_handler!(fd_socketpair_handler, SYS_SOCKETPAIR, SOCKPAIR);
define_fd_handler!(fd_epoll_create_handler, SYS_EPOLL_CREATE, CREATION);
define_fd_handler!(fd_epoll_create1_handler, SYS_EPOLL_CREATE1, CREATION_FLAG_1);

define_fd_handler!(fd_epoll_ctl_handler, SYS_EPOLL_CTL, EPOLL_1_FD_3);

pub const FD_HANDLER_TABLE: &[(u64, SyscallHandler)] = &[
    (SYS_READ, fd_read_handler as SyscallHandler),
    (SYS_WRITE, fd_write_handler as SyscallHandler),
    (SYS_CLOSE, fd_close_handler as SyscallHandler),
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
    (SYS_MMAP, fd_mmap_handler as SyscallHandler),

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
    
    (SYS_MKDIR, fd_mkdir_handler as SyscallHandler),
    (SYS_MKNOD, fd_mknod_handler as SyscallHandler),
    (SYS_UNLINKAT, fd_unlinkat_handler as SyscallHandler),
    (SYS_SYMLINKAT, fd_symlinkat_handler as SyscallHandler),
    (SYS_READLINKAT, fd_readlinkat_handler as SyscallHandler),
    (SYS_ACCESS, fd_access_handler as SyscallHandler),

    (SYS_OPEN, fd_open_handler as SyscallHandler),
    (SYS_OPENAT, fd_openat_handler as SyscallHandler),
    (SYS_DUP, fd_dup_handler as SyscallHandler),
    (SYS_DUP2, fd_dup2_handler as SyscallHandler),
    (SYS_DUP3, fd_dup3_handler as SyscallHandler),
    (SYS_FCNTL, fd_fcntl_handler as SyscallHandler),

    (SYS_SOCKET, fd_socket_handler as SyscallHandler),
    (SYS_SOCKETPAIR, fd_socketpair_handler as SyscallHandler),
    (SYS_EPOLL_CREATE, fd_epoll_create_handler as SyscallHandler),
    (SYS_EPOLL_CREATE1, fd_epoll_create1_handler as SyscallHandler),

    (SYS_EPOLL_CTL, fd_epoll_ctl_handler as SyscallHandler),
];
