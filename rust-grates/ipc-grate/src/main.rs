//! IPC grate — userspace pipe-based IPC for Lind.
//!
//! Intercepts pipe, read, write, close, dup, and fcntl syscalls. For fds that
//! belong to pipes created by this grate, services them entirely in userspace
//! using in-memory ring buffers. For all other fds, forwards to make_syscall
//! transparently.
//!
//! Usage:
//!   ipc-grate <program> [args...]

mod handlers;
mod helpers;
mod ipc;
mod pipe;
mod socket;

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, getcageid};

use ipc::init;

fn main() {
    let grate_cage_id = getcageid();
    init(grate_cage_id);

    // Register fdtables-level close handlers so refcount decrements
    // happen automatically on all entry-removal paths: close_virtualfd,
    // get_specific_virtual_fd overwrite, empty_fds_for_exec, AND
    // remove_cage_from_fdtable (cage exit).  Without this, e.g. a
    // process exiting (postgres backend after locale enumeration)
    // doesn't decrement pipe.write_refs, so the parent's fgets / poll
    // never sees EOF.
    fdtables::register_close_handlers(
        ipc::IPC_PIPE,
        handlers::ipc_pipe_close_handler,
        handlers::ipc_pipe_close_handler,
    );
    fdtables::register_close_handlers(
        socket::IPC_SOCKET,
        handlers::ipc_socket_close_handler,
        handlers::ipc_socket_close_handler,
    );

    let argv: Vec<String> = std::env::args().skip(1).collect();

    GrateBuilder::new()
        // Pipe syscalls
        .register(SYS_PIPE, handlers::pipe_handler)
        .register(SYS_PIPE2, handlers::pipe2_handler)
        // I/O syscalls (handle both pipes and sockets)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_OPENAT, handlers::openat_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .register(SYS_DUP3, handlers::dup3_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_POLL, handlers::poll_handler)
        .register(SYS_SELECT, handlers::select_handler)
        // Pure-translation handlers for fd-taking syscalls — they
        // translate the grate vfd in arg1 to its runtime vfd before
        // forwarding to RawPOSIX, since the two fdtable instances are
        // independent.
        .register(SYS_LSEEK, handlers::lseek_handler)
        .register(SYS_IOCTL, handlers::ioctl_handler)
        .register(SYS_FSTAT, handlers::fstat_handler)
        .register(SYS_FSYNC, handlers::fsync_handler)
        .register(SYS_FDATASYNC, handlers::fdatasync_handler)
        .register(SYS_FTRUNCATE, handlers::ftruncate_handler)
        .register(SYS_GETDENTS, handlers::getdents_handler)
        .register(SYS_FSTATFS, handlers::fstatfs_handler)
        .register(SYS_FCHDIR, handlers::fchdir_handler)
        .register(SYS_FCHMOD, handlers::fchmod_handler)
        .register(SYS_FLOCK, handlers::flock_handler)
        .register(SYS_PREAD, handlers::pread_handler)
        .register(SYS_PWRITE, handlers::pwrite_handler)
        .register(SYS_READV, handlers::readv_handler)
        .register(SYS_WRITEV, handlers::writev_handler)
        .register(SYS_PREADV, handlers::preadv_handler)
        .register(SYS_PWRITEV, handlers::pwritev_handler)
        .register(SYS_SYNC_FILE_RANGE, handlers::sync_file_range_handler)
        .register(SYS_MMAP, handlers::mmap_handler)
        .register(SYS_PPOLL, handlers::ppoll_handler)
        .register(SYS_EPOLL_CREATE, handlers::epoll_create_handler)
        .register(SYS_EPOLL_CREATE1, handlers::epoll_create1_handler)
        .register(SYS_EPOLL_CTL, handlers::epoll_ctl_handler)
        .register(SYS_EPOLL_WAIT, handlers::epoll_wait_handler)
        // Socket syscalls
        .register(SYS_SOCKET, handlers::socket_handler)
        .register(SYS_SOCKETPAIR, handlers::socketpair_handler)
        .register(SYS_BIND, handlers::bind_handler)
        .register(SYS_LISTEN, handlers::listen_handler)
        .register(SYS_CONNECT, handlers::connect_handler)
        .register(SYS_ACCEPT, handlers::accept_handler)
        .register(SYS_ACCEPT4, handlers::accept4_handler)
        .register(SYS_SHUTDOWN, handlers::shutdown_handler)
        .register(SYS_SETSOCKOPT, handlers::setsockopt_handler)
        .register(SYS_GETSOCKOPT, handlers::getsockopt_handler)
        .register(SYS_GETSOCKNAME, handlers::getsockname_handler)
        .register(SYS_GETPEERNAME, handlers::getpeername_handler)
        .register(SYS_SENDTO, handlers::sendto_handler)
        .register(SYS_RECVFROM, handlers::recvfrom_handler)
        .register(SYS_SENDMSG, handlers::sendmsg_handler)
        .register(SYS_RECVMSG, handlers::recvmsg_handler)
        // Lifecycle
        .register(SYS_CLONE, handlers::fork_handler)
        .register(SYS_EXEC, handlers::exec_handler)
        .register(SYS_EXIT, handlers::exit_handler)
        .register(SYS_EXIT_GROUP, handlers::exit_group_handler)
        .preexec(|child_cage: i32| {
            let cage_id = child_cage as u64;
            fdtables::init_empty_cage(cage_id);
            for fd in 0..3u64 {
                let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
            }
        })
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[ipc-grate] error: {:?}", e);
            }
        })
        .run(argv);
}
