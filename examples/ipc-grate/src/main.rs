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

    let argv: Vec<String> = std::env::args().skip(1).collect();

    GrateBuilder::new()
        // Pipe syscalls
        .register(SYS_PIPE, handlers::pipe_handler)
        .register(SYS_PIPE2, handlers::pipe2_handler)
        // I/O syscalls (handle both pipes and sockets)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .register(SYS_DUP3, handlers::dup3_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        // Socket syscalls
        .register(SYS_SOCKET, handlers::socket_handler)
        .register(SYS_SOCKETPAIR, handlers::socketpair_handler)
        .register(SYS_BIND, handlers::bind_handler)
        .register(SYS_LISTEN, handlers::listen_handler)
        .register(SYS_CONNECT, handlers::connect_handler)
        .register(SYS_ACCEPT, handlers::accept_handler)
        .register(SYS_SHUTDOWN, handlers::shutdown_handler)
        // Lifecycle
        .register(SYS_CLONE, handlers::fork_handler)
        .register(SYS_EXEC, handlers::exec_handler)
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
