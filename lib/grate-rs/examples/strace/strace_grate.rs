mod strace;

use strace::{Arg, parse_arg};
use grate_rs::{GrateBuilder, make_threei_call, GrateError};
use grate_rs::constants;

// invoking macros to register syscall handler
//
// ARGS:
// 1. handler_name      - syscall handler name
// 2. syscall_number    - syscall number passed via "Syscall" enum 
// 3. [arg_type]        - argument types passed sequentially in a tuple

define_syscall_handler!(read_syscall, constants::SYS_READ, [Int, Int, Int]);
define_syscall_handler!(write_syscall, constants::SYS_WRITE, [Int, Int, Int]);
define_syscall_handler!(open_syscall, constants::SYS_OPEN, [CString, Int, Int]);
define_syscall_handler!(close_syscall, constants::SYS_CLOSE, [Int]);
define_syscall_handler!(stat_syscall, constants::SYS_XSTAT, [CString, Int]);
define_syscall_handler!(fstat_syscall, constants::SYS_FXSTAT, [Int, Int]);
define_syscall_handler!(poll_syscall, constants::SYS_POLL, [Int, Int, Int]);
define_syscall_handler!(lseek_syscall, constants::SYS_LSEEK, [Int, Int, Int]);
define_syscall_handler!(mmap_syscall, constants::SYS_MMAP, [Int, Int, Int, Int, Int, Int]);
define_syscall_handler!(mprotect_syscall, constants::SYS_MPROTECT, [Int, Int, Int]);
define_syscall_handler!(munmap_syscall, constants::SYS_MUNMAP, [Int, Int]);
define_syscall_handler!(brk_syscall, constants::SYS_BRK, [Int]);
define_syscall_handler!(sigaction_syscall, constants::SYS_SIGACTION, [Int, Int, Int]);
define_syscall_handler!(sigprocmask_syscall, constants::SYS_SIGPROCMASK, [Int, Int, Int]);
define_syscall_handler!(ioctl_syscall, constants::SYS_IOCTL, [Int, Int, Int]);
define_syscall_handler!(pread_syscall, constants::SYS_PREAD, [Int, Int, Int, Int]);
define_syscall_handler!(pwrite_syscall, constants::SYS_PWRITE, [Int, Int, Int, Int]);
define_syscall_handler!(writev_syscall, constants::SYS_WRITEV, [Int, Int, Int]);
define_syscall_handler!(access_syscall, constants::SYS_ACCESS, [CString, Int]);
define_syscall_handler!(pipe_syscall, constants::SYS_PIPE, [Int]);
define_syscall_handler!(select_syscall, constants::SYS_SELECT, [Int, Int, Int, Int, Int]);
define_syscall_handler!(sched_yield_syscall, constants::SYS_SCHED_YIELD, []);
define_syscall_handler!(shmget_syscall, constants::SYS_SHMGET, [Int, Int, Int]);
define_syscall_handler!(shmat_syscall, constants::SYS_SHMAT, [Int, Int, Int]);
define_syscall_handler!(shmctl_syscall, constants::SYS_SHMCTL, [Int, Int, Int]);
define_syscall_handler!(dup_syscall, constants::SYS_DUP, [Int]);
define_syscall_handler!(dup2_syscall, constants::SYS_DUP2, [Int, Int]);
define_syscall_handler!(nanosleep_syscall, constants::SYS_NANOSLEEP_TIME64, [Int, Int]);
define_syscall_handler!(setitimer_syscall, constants::SYS_SETITIMER, [Int, Int, Int]);
define_syscall_handler!(getpid_syscall, constants::SYS_GETPID, []);
define_syscall_handler!(socket_syscall, constants::SYS_SOCKET, [Int, Int, Int]);
define_syscall_handler!(connect_syscall, constants::SYS_CONNECT, [Int, Int, Int]);
define_syscall_handler!(accept_syscall, constants::SYS_ACCEPT, [Int, Int, Int]);
define_syscall_handler!(sendto_syscall, constants::SYS_SENDTO, [Int, Int, Int, Int, Int, Int]);
define_syscall_handler!(recvfrom_syscall, constants::SYS_RECVFROM, [Int, Int, Int, Int, Int, Int]);
define_syscall_handler!(shutdown_syscall, constants::SYS_SHUTDOWN, [Int, Int]);
define_syscall_handler!(bind_syscall, constants::SYS_BIND, [Int, Int, Int]);
define_syscall_handler!(listen_syscall, constants::SYS_LISTEN, [Int, Int]);
define_syscall_handler!(getsockname_syscall, constants::SYS_GETSOCKNAME, [Int, Int, Int]);
define_syscall_handler!(getpeername_syscall, constants::SYS_GETPEERNAME, [Int, Int, Int]);
define_syscall_handler!(socketpair_syscall, constants::SYS_SOCKETPAIR, [Int, Int, Int, Int]);
define_syscall_handler!(setsockopt_syscall, constants::SYS_SETSOCKOPT, [Int, Int, Int, Int, Int]);
define_syscall_handler!(getsockopt_syscall, constants::SYS_GETSOCKOPT, [Int, Int, Int, Int, Int]);
define_syscall_handler!(clone_syscall, constants::SYS_CLONE, [Int, Int, Int, Int, Int]);
define_syscall_handler!(fork_syscall, constants::SYS_FORK, []);
define_syscall_handler!(exec_syscall, constants::SYS_EXEC, [CString, Int, Int]);
//define_syscall_handler!(exit_syscall, constants::SYS_EXIT, [Int]);
define_syscall_handler!(waitpid_syscall, constants::SYS_WAITPID, [Int, Int, Int]);
define_syscall_handler!(kill_syscall, constants::SYS_KILL, [Int, Int]);
define_syscall_handler!(shmdt_syscall, constants::SYS_SHMDT, [Int]);
define_syscall_handler!(fcntl_syscall, constants::SYS_FCNTL, [Int, Int, Int]);
define_syscall_handler!(flock_syscall, constants::SYS_FLOCK, [Int, Int]);
define_syscall_handler!(fsync_syscall, constants::SYS_FSYNC, [Int]);
define_syscall_handler!(fdatasync_syscall, constants::SYS_FDATASYNC, [Int]);
define_syscall_handler!(truncate_syscall, constants::SYS_TRUNCATE, [CString, Int]);
define_syscall_handler!(ftruncate_syscall, constants::SYS_FTRUNCATE, [Int, Int]);
define_syscall_handler!(getdents_syscall, constants::SYS_GETDENTS, [Int, Int, Int]);
define_syscall_handler!(getcwd_syscall, constants::SYS_GETCWD, [Int, Int]);
define_syscall_handler!(chdir_syscall, constants::SYS_CHDIR, [CString]);
define_syscall_handler!(fchdir_syscall, constants::SYS_FCHDIR, [Int]);
define_syscall_handler!(rename_syscall, constants::SYS_RENAME, [CString, CString]);
define_syscall_handler!(unlink_syscall, constants::SYS_UNLINK, [CString]);
define_syscall_handler!(readlink_syscall, constants::SYS_READLINK, [CString, Int, Int]);
define_syscall_handler!(chmod_syscall, constants::SYS_CHMOD, [CString, Int]);
define_syscall_handler!(fchmod_syscall, constants::SYS_FCHMOD, [Int, Int]);
define_syscall_handler!(getuid_syscall, constants::SYS_GETUID, []);
define_syscall_handler!(getgid_syscall, constants::SYS_GETGID, []);
define_syscall_handler!(geteuid_syscall, constants::SYS_GETEUID, []);
define_syscall_handler!(getegid_syscall, constants::SYS_GETEGID, []);
define_syscall_handler!(getppid_syscall, constants::SYS_GETPPID, []);
define_syscall_handler!(statfs_syscall, constants::SYS_STATFS, [CString, Int]);
define_syscall_handler!(fstatfs_syscall, constants::SYS_FSTATFS, [Int, Int]);
define_syscall_handler!(gethostname_syscall, constants::SYS_GETHOSTNAME, [Int, Int]);
define_syscall_handler!(futex_syscall, constants::SYS_FUTEX, [Int, Int, Int, Int, Int, Int]);
define_syscall_handler!(epoll_create_syscall, constants::SYS_EPOLL_CREATE, [Int]);
define_syscall_handler!(clock_gettime_syscall, constants::SYS_CLOCK_GETTIME, [Int, Int]);
define_syscall_handler!(epoll_wait_syscall, constants::SYS_EPOLL_WAIT, [Int, Int, Int, Int]);
define_syscall_handler!(epoll_ctl_syscall, constants::SYS_EPOLL_CTL, [Int, Int, Int, Int]);
define_syscall_handler!(unlinkat_syscall, constants::SYS_UNLINKAT, [Int, CString, Int]);
define_syscall_handler!(readlinkat_syscall, constants::SYS_READLINKAT, [Int, CString, Int, Int]);
define_syscall_handler!(sync_file_range_syscall, constants::SYS_SYNC_FILE_RANGE, [Int, Int, Int, Int]);
define_syscall_handler!(epoll_create1_syscall, constants::SYS_EPOLL_CREATE1, [Int]);
define_syscall_handler!(dup3_syscall, constants::SYS_DUP3, [Int, Int, Int]);
define_syscall_handler!(pipe2_syscall, constants::SYS_PIPE2, [Int, Int]);
define_syscall_handler!(getrandom_syscall, constants::SYS_GETRANDOM, [Int, Int, Int]);
fn main() {
    println!("[Grate Init]: Initializing Strace Grate\n");
    
    // register syscall handlers
    let builder = GrateBuilder::new()
        .register(constants::SYS_READ, read_syscall)
        .register(constants::SYS_WRITE, write_syscall)
        .register(constants::SYS_OPEN, open_syscall)
        .register(constants::SYS_CLOSE, close_syscall)
        .register(constants::SYS_MMAP, mmap_syscall)
        .register(constants::SYS_XSTAT, stat_syscall)
        .register(constants::SYS_FXSTAT, fstat_syscall)
        .register(constants::SYS_POLL, poll_syscall)
        .register(constants::SYS_LSEEK, lseek_syscall)
        .register(constants::SYS_MMAP, mmap_syscall)
        .register(constants::SYS_MPROTECT, mprotect_syscall)
        .register(constants::SYS_MUNMAP, munmap_syscall)
        .register(constants::SYS_BRK, brk_syscall)
        .register(constants::SYS_SIGACTION, sigaction_syscall)
        .register(constants::SYS_SIGPROCMASK, sigprocmask_syscall)
        .register(constants::SYS_IOCTL, ioctl_syscall)
        .register(constants::SYS_PREAD, pread_syscall)
        .register(constants::SYS_PWRITE, pwrite_syscall)
        .register(constants::SYS_WRITEV, writev_syscall)
        .register(constants::SYS_ACCESS, access_syscall)
        .register(constants::SYS_PIPE, pipe_syscall)
        .register(constants::SYS_SELECT, select_syscall)
        .register(constants::SYS_SCHED_YIELD, sched_yield_syscall)
        .register(constants::SYS_SHMGET, shmget_syscall)
        .register(constants::SYS_SHMAT, shmat_syscall)
        .register(constants::SYS_SHMCTL, shmctl_syscall)
        .register(constants::SYS_DUP, dup_syscall)
        .register(constants::SYS_DUP2, dup2_syscall)
        .register(constants::SYS_NANOSLEEP_TIME64, nanosleep_syscall)
        .register(constants::SYS_SETITIMER, setitimer_syscall)
        .register(constants::SYS_GETPID, getpid_syscall)
        .register(constants::SYS_SOCKET, socket_syscall)
        .register(constants::SYS_CONNECT, connect_syscall)
        .register(constants::SYS_ACCEPT, accept_syscall)
        .register(constants::SYS_SENDTO, sendto_syscall)
        .register(constants::SYS_RECVFROM, recvfrom_syscall)
        .register(constants::SYS_SHUTDOWN, shutdown_syscall)
        .register(constants::SYS_BIND, bind_syscall)
        .register(constants::SYS_LISTEN, listen_syscall)
        .register(constants::SYS_GETSOCKNAME, getsockname_syscall)
        .register(constants::SYS_GETPEERNAME, getpeername_syscall)
        .register(constants::SYS_SOCKETPAIR, socketpair_syscall)
        .register(constants::SYS_SETSOCKOPT, setsockopt_syscall)
        .register(constants::SYS_GETSOCKOPT, getsockopt_syscall)
        .register(constants::SYS_CLONE, clone_syscall)
        .register(constants::SYS_FORK, fork_syscall)
        .register(constants::SYS_EXEC, exec_syscall)
        //.register(constants::SYS_EXIT, exit_syscall)
        .register(constants::SYS_WAITPID, waitpid_syscall)
        .register(constants::SYS_KILL, kill_syscall)
        .register(constants::SYS_SHMDT, shmdt_syscall)
        .register(constants::SYS_FCNTL, fcntl_syscall)
        .register(constants::SYS_FLOCK, flock_syscall)
        .register(constants::SYS_FSYNC, fsync_syscall)
        .register(constants::SYS_FDATASYNC, fdatasync_syscall)
        .register(constants::SYS_TRUNCATE, truncate_syscall)
        .register(constants::SYS_FTRUNCATE, ftruncate_syscall)
        .register(constants::SYS_GETDENTS, getdents_syscall)
        .register(constants::SYS_GETCWD, getcwd_syscall)
        .register(constants::SYS_CHDIR, chdir_syscall)
        .register(constants::SYS_FCHDIR, fchdir_syscall)
        .register(constants::SYS_RENAME, rename_syscall)
        .register(constants::SYS_UNLINK, unlink_syscall)
        .register(constants::SYS_READLINK, readlink_syscall)
        .register(constants::SYS_CHMOD, chmod_syscall)
        .register(constants::SYS_FCHMOD, fchmod_syscall)
        .register(constants::SYS_GETUID, getuid_syscall)
        .register(constants::SYS_GETGID, getgid_syscall)
        .register(constants::SYS_GETEUID, geteuid_syscall)
        .register(constants::SYS_GETEGID, getegid_syscall)
        .register(constants::SYS_GETPPID, getppid_syscall)
        .register(constants::SYS_STATFS, statfs_syscall)
        .register(constants::SYS_FSTATFS, fstatfs_syscall)
        .register(constants::SYS_GETHOSTNAME, gethostname_syscall)
        .register(constants::SYS_FUTEX, futex_syscall)
        .register(constants::SYS_EPOLL_CREATE, epoll_create_syscall)
        .register(constants::SYS_CLOCK_GETTIME, clock_gettime_syscall)
        .register(constants::SYS_EPOLL_WAIT, epoll_wait_syscall)
        .register(constants::SYS_EPOLL_CTL, epoll_ctl_syscall)
        .register(constants::SYS_UNLINKAT, unlinkat_syscall)
        .register(constants::SYS_READLINKAT, readlinkat_syscall)
        .register(constants::SYS_SYNC_FILE_RANGE, sync_file_range_syscall)
        .register(constants::SYS_EPOLL_CREATE1, epoll_create1_syscall)
        .register(constants::SYS_DUP3, dup3_syscall)
        .register(constants::SYS_PIPE2, pipe2_syscall)
        .register(constants::SYS_GETRANDOM, getrandom_syscall)
        .teardown(|result: Result<i32, GrateError>| {
            println!("Result: {:#?}", result);
        }); 
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    builder.run(argv);
}
