//! IPC grate — userspace pipe-based IPC for Lind.
//!
//! Intercepts pipe, read, write, close, dup, and fcntl syscalls. For fds that
//! belong to pipes created by this grate, services them entirely in userspace
//! using in-memory ring buffers. For all other fds, forwards to make_syscall
//! transparently.
//!
//! Usage:
//!   ipc-grate -- clang -O2 foo.c -o /out/foo

mod pipe;
mod socket;
mod ipc;

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, SyscallHandler, copy_data_between_cages, getcageid, make_threei_call};

use ipc::*;

// =====================================================================
//  Helpers
// =====================================================================

/// Forward a syscall to the next handler via make_threei_call.
/// Used for fds that are NOT owned by ipc-grate.
///
/// source_cage (grate) is used for handler table lookup.
/// calling_cage is the cage that made the syscall — used as operational target.
fn forward_syscall(
    nr: u64, calling_cage: u64,
    args: &[u64; 6], arg_cages: &[u64; 6],
) -> i32 {
    let grate_cage = getcageid();
    match make_threei_call(
        nr as u32, 0, grate_cage, calling_cage,
        args[0], arg_cages[0], args[1], arg_cages[1], args[2], arg_cages[2],
        args[3], arg_cages[3], args[4], arg_cages[4], args[5], arg_cages[5], 0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

// =====================================================================
//  Handlers
// =====================================================================

/// pipe (syscall 22): create a pipe pair.
///
/// Allocates a ring buffer, registers both fds in fdtables, writes the
/// two fd numbers back to the cage's pipefd[2] array.
pub extern "C" fn pipe_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // pipefd[2] pointer
    _arg2: u64, _arg2cage: u64,
    _arg3: u64, _arg3cage: u64,
    _arg4: u64, _arg4cage: u64,
    _arg5: u64, _arg5cage: u64,
    _arg6: u64, _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let this_cage = getcageid();

    let (rfd, wfd) = match with_ipc(|s| s.create_pipe(cage_id, 0)) {
        Ok(fds) => fds,
        Err(e) => return e,
    };

    // Write the two fds back to the cage's pipefd[2] array.
    let fds: [i32; 2] = [rfd, wfd];
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        fds.as_ptr() as u64, this_cage,
        arg1, arg1cage,
        8, 0, // 2 x i32 = 8 bytes
    );

    0
}

/// pipe2 (syscall 293): create a pipe pair with flags.
pub extern "C" fn pipe2_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // pipefd[2] pointer
    arg2: u64, _arg2cage: u64,   // flags
    _arg3: u64, _arg3cage: u64,
    _arg4: u64, _arg4cage: u64,
    _arg5: u64, _arg5cage: u64,
    _arg6: u64, _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let this_cage = getcageid();
    let flags = arg2 as i32;

    let (rfd, wfd) = match with_ipc(|s| s.create_pipe(cage_id, flags)) {
        Ok(fds) => fds,
        Err(e) => return e,
    };

    let fds: [i32; 2] = [rfd, wfd];
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        fds.as_ptr() as u64, this_cage,
        arg1, arg1cage,
        8, 0,
    );

    0
}

/// read (syscall 0): read from pipe or forward.
///
/// If arg1 (fd) is a pipe read-end in fdtables, read from the ring buffer
/// and copy data to the cage. Otherwise forward to make_syscall.
pub extern "C" fn read_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // buf
    arg3: u64, _arg3cage: u64,   // count
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    // Check if this fd is a pipe or socket we own.
    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_READ, cage_id, &args, &arg_cages);
    }

    let (underfd, fdkind, flags) = info.unwrap();
    let nonblocking = (flags & O_NONBLOCK) != 0;

    // Get the right pipe to read from based on fd type.
    let pipe = match fdkind {
        IPC_PIPE => {
            // Check that this is the read end (O_RDONLY).
            if !is_read_end(flags) {
                return -9; // EBADF — can't read from a write-end
            }
            with_ipc(|s| s.get_pipe(underfd))
        }
        IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.recvpipe.clone())
        }),
        _ => return -9,
    };

    let pipe = match pipe {
        Some(p) => p,
        None => return -9,
    };

    let mut buf = vec![0u8; count];
    let ret = pipe.read(&mut buf, count, nonblocking);

    if ret > 0 && arg2 != 0 {
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            buf.as_ptr() as u64, this_cage,
            arg2, arg2cage,
            ret as u64, 0,
        );
    }

    ret
}

/// write (syscall 1): write to pipe or forward.
pub extern "C" fn write_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // buf
    arg3: u64, _arg3cage: u64,   // count
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_WRITE, cage_id, &args, &arg_cages);
    }

    let (underfd, fdkind, flags) = info.unwrap();
    let nonblocking = (flags & O_NONBLOCK) != 0;

    // Get the right pipe to write to based on fd type.
    let pipe = match fdkind {
        IPC_PIPE => {
            // Check that this is the write end (O_WRONLY).
            if !is_write_end(flags) {
                return -9; // EBADF — can't write to a read-end
            }
            with_ipc(|s| s.get_pipe(underfd))
        }
        IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.sendpipe.clone())
        }),
        _ => return -9,
    };

    let pipe = match pipe {
        Some(p) => p,
        None => return -9,
    };

    // Copy data from the cage's buffer.
    let mut buf = vec![0u8; count];
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        arg2, arg2cage,
        buf.as_mut_ptr() as u64, this_cage,
        count as u64, 0,
    );

    pipe.write(&buf, count, nonblocking)
}

/// close (syscall 3): close a pipe fd or forward.
///
/// Decrements the appropriate refcount on the pipe. If this was the
/// last write-end, sets EOF so readers get 0.
pub extern "C" fn close_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_CLOSE, cage_id, &args, &arg_cages);
    }

    let (pipe_id, fdkind, flags) = info.unwrap();

    // Decrement the appropriate refcount based on fd type.
    match fdkind {
        IPC_PIPE => {
            if let Some(pipe) = with_ipc(|s| s.get_pipe(pipe_id)) {
                if is_read_end(flags) {
                    pipe.decr_read_ref();
                } else {
                    pipe.decr_write_ref();
                }
            }
        }
        socket::IPC_SOCKET => {
            // Closing a socket: decrement write refs on sendpipe (triggers
            // EOF for peer's reads) and read refs on recvpipe.
            with_ipc(|s| {
                if let Some(sock) = s.sockets.get(pipe_id) {
                    if let Some(ref sp) = sock.sendpipe {
                        sp.decr_write_ref();
                    }
                    if let Some(ref rp) = sock.recvpipe {
                        rp.decr_read_ref();
                    }
                }
            });
        }
        _ => {}
    }

    // Remove the fd from fdtables.
    let _ = fdtables::close_virtualfd(cage_id, fd);

    0
}

/// dup (syscall 32): duplicate a pipe fd or forward.
///
/// Allocates a new fd in fdtables pointing to the same pipe, and
/// increments the appropriate refcount.
pub extern "C" fn dup_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_DUP, cage_id, &args, &arg_cages);
    }

    let (pipe_id, fdkind, flags) = info.unwrap();

    // Allocate new fd with same underfd and fdkind.
    let new_fd = match fdtables::get_unused_virtual_fd(
        cage_id, fdkind, pipe_id, false, flags as u64,
    ) {
        Ok(fd) => fd as i32,
        Err(_) => return -24, // EMFILE
    };

    // Increment the appropriate refcount based on fd type.
    match fdkind {
        IPC_PIPE => {
            if let Some(pipe) = with_ipc(|s| s.get_pipe(pipe_id)) {
                if is_read_end(flags) {
                    pipe.incr_read_ref();
                } else {
                    pipe.incr_write_ref();
                }
            }
        }
        socket::IPC_SOCKET => {
            // Dup'ing a socket: both ends get an extra reference.
            with_ipc(|s| {
                if let Some(sock) = s.sockets.get(pipe_id) {
                    if let Some(ref sp) = sock.sendpipe {
                        sp.incr_write_ref();
                    }
                    if let Some(ref rp) = sock.recvpipe {
                        rp.incr_read_ref();
                    }
                }
            });
        }
        _ => {}
    }

    new_fd
}

/// dup2 (syscall 33): duplicate pipe fd to specific target, or forward.
pub extern "C" fn dup2_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // oldfd
    arg2: u64, _arg2cage: u64,   // newfd
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let oldfd = arg1;
    let newfd = arg2;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, oldfd);
    if info.is_none() {
        return forward_syscall(SYS_DUP2, cage_id, &args, &arg_cages);
    }

    let (pipe_id, fdkind, flags) = info.unwrap();

    // Close newfd if it's already open (dup2 semantics).
    // If newfd was a pipe/socket, close_handler would handle its refcounts,
    // but close_virtualfd doesn't call our handler, so we need to manually
    // decrement refs if newfd was one of ours.
    if let Some((new_underfd, new_fdkind, new_flags)) = lookup_ipc_fd(cage_id, newfd) {
        match new_fdkind {
            IPC_PIPE => {
                if let Some(pipe) = with_ipc(|s| s.get_pipe(new_underfd)) {
                    if is_read_end(new_flags) { pipe.decr_read_ref(); }
                    else { pipe.decr_write_ref(); }
                }
            }
            socket::IPC_SOCKET => {
                with_ipc(|s| {
                    if let Some(sock) = s.sockets.get(new_underfd) {
                        if let Some(ref sp) = sock.sendpipe { sp.decr_write_ref(); }
                        if let Some(ref rp) = sock.recvpipe { rp.decr_read_ref(); }
                    }
                });
            }
            _ => {}
        }
    }
    let _ = fdtables::close_virtualfd(cage_id, newfd);

    // Register the new fd at the specific number.
    let _ = fdtables::get_specific_virtual_fd(
        cage_id, newfd, fdkind, pipe_id, false, flags as u64,
    );

    // Increment the appropriate refcount for the new reference.
    match fdkind {
        IPC_PIPE => {
            if let Some(pipe) = with_ipc(|s| s.get_pipe(pipe_id)) {
                if is_read_end(flags) { pipe.incr_read_ref(); }
                else { pipe.incr_write_ref(); }
            }
        }
        socket::IPC_SOCKET => {
            with_ipc(|s| {
                if let Some(sock) = s.sockets.get(pipe_id) {
                    if let Some(ref sp) = sock.sendpipe { sp.incr_write_ref(); }
                    if let Some(ref rp) = sock.recvpipe { rp.incr_read_ref(); }
                }
            });
        }
        _ => {}
    }

    newfd as i32
}

/// dup3 (syscall 292): dup2 with flags.
pub extern "C" fn dup3_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, _arg3cage: u64,   // flags
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    // dup3 is dup2 + flags. Delegate to dup2 logic.
    dup2_handler(
        cageid, arg1, arg1cage, arg2, arg2cage,
        arg3, _arg3cage, arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    )
}

/// fcntl (syscall 72): handle F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL
/// for pipe fds, or forward.
pub extern "C" fn fcntl_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, _arg2cage: u64,   // op
    arg3: u64, _arg3cage: u64,   // arg
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let op = arg2 as i32;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_FCNTL, cage_id, &args, &arg_cages);
    }

    let (_pipe_id, _fdkind, flags) = info.unwrap();

    match op {
        F_GETFL => flags,
        F_SETFL => {
            // Update perfdinfo in fdtables.
            let _ = fdtables::set_perfdinfo(cage_id, fd, arg3);
            0
        }
        F_GETFD => {
            // Return FD_CLOEXEC status.
            match fdtables::translate_virtual_fd(cage_id, fd) {
                Ok(entry) => if entry.should_cloexec { 1 } else { 0 },
                Err(_) => -9,
            }
        }
        F_SETFD => {
            // Set FD_CLOEXEC.
            let _ = fdtables::set_cloexec(cage_id, fd, (arg3 & 1) != 0);
            0
        }
        F_DUPFD => {
            // Like dup but use fd >= arg3.
            dup_handler(cageid, arg1, arg1cage, arg2, _arg2cage,
                        arg3, _arg3cage, arg4, arg4cage, arg5, arg5cage, arg6, arg6cage)
        }
        _ => -22, // EINVAL
    }
}

/// fork (syscall 57): forward fork and clone fdtables for the child.
///
/// The child cage starts running as soon as forward_syscall(SYS_CLONE)
/// returns.  To prevent the child from using an uninitialised fdtable
/// (which causes "Unknown cageid" panics) or closing an fd before its
/// refcount is bumped (which causes premature pipe EOF / EPIPE), we:
///
///   1. Pre-collect parent's pipe Arc refs via with_ipc (needs IPC_STATE,
///      so must happen BEFORE acquiring CAGE_INIT_LOCK to avoid deadlock
///      with create_pipe → ensure_cage_exists path).
///   2. Acquire CAGE_INIT_LOCK, then fork, copy fdtable, bump refcounts,
///      and release.  The child's first handler call goes through
///      lookup_ipc_fd which also acquires CAGE_INIT_LOCK — so the child
///      blocks until setup is complete.
pub extern "C" fn fork_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // --- Phase 1: snapshot parent's fdtable and pre-collect pipe/socket
    //     Arc references BEFORE forking.  Uses IPC_STATE (via with_ipc) but
    //     NOT CAGE_INIT_LOCK, so no lock-ordering issue.
    let parent_fds = fdtables::return_fdtable_copy(cage_id);

    enum RefBump {
        Pipe { pipe: std::sync::Arc<pipe::PipeBuffer>, is_read: bool },
        Socket {
            sendpipe: Option<std::sync::Arc<pipe::PipeBuffer>>,
            recvpipe: Option<std::sync::Arc<pipe::PipeBuffer>>,
        },
    }

    let mut bumps: Vec<RefBump> = Vec::new();
    for (_fd, entry) in &parent_fds {
        match entry.fdkind {
            IPC_PIPE => {
                if let Some(pipe) = with_ipc(|s| s.get_pipe(entry.underfd)) {
                    bumps.push(RefBump::Pipe {
                        pipe,
                        is_read: is_read_end(entry.perfdinfo as i32),
                    });
                }
            }
            socket::IPC_SOCKET => {
                let refs = with_ipc(|s| {
                    s.sockets.get(entry.underfd).map(|sock| {
                        (sock.sendpipe.clone(), sock.recvpipe.clone())
                    })
                });
                if let Some((sp, rp)) = refs {
                    bumps.push(RefBump::Socket { sendpipe: sp, recvpipe: rp });
                }
            }
            _ => {}
        }
    }

    // --- Phase 2: fork + copy fdtable + bump refcounts, all under the
    //     shared-memory fork semaphore.  The child starts running after
    //     forward_syscall returns but blocks in lookup_ipc_fd (which also
    //     acquires the semaphore), so it cannot touch fdtables or pipe
    //     refcounts until we are done.
    ipc::fork_lock();

    let ret = forward_syscall(SYS_CLONE, cage_id, &args, &arg_cages);

    if ret <= 0 {
        ipc::fork_unlock();
        return ret;
    }

    let child_cage_id = ret as u64;

    // Copy the parent's fdtable to the child entry-by-entry.
    //
    // We intentionally avoid copy_fdtable_for_cage because it copies a
    // [Option<FDTableEntry>; 1024] (~24KB) onto the WASM stack which can
    // overflow and corrupt memory.
    if !fdtables::check_cage_exists(child_cage_id) {
        fdtables::init_empty_cage(child_cage_id);
    }
    for (fd, entry) in &parent_fds {
        let _ = fdtables::get_specific_virtual_fd(
            child_cage_id,
            *fd,
            entry.fdkind,
            entry.underfd,
            entry.should_cloexec,
            entry.perfdinfo,
        );
    }

    // Bump refcounts using the pre-collected Arc references.
    for bump in &bumps {
        match bump {
            RefBump::Pipe { pipe, is_read } => {
                if *is_read {
                    pipe.incr_read_ref();
                } else {
                    pipe.incr_write_ref();
                }
            }
            RefBump::Socket { sendpipe, recvpipe } => {
                if let Some(sp) = sendpipe {
                    sp.incr_write_ref();
                }
                if let Some(rp) = recvpipe {
                    rp.incr_read_ref();
                }
            }
        }
    }

    ipc::fork_unlock(); // child can now proceed

    child_cage_id as i32
}

/// exec (syscall 59): close cloexec fds, then forward.
pub extern "C" fn exec_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;

    // The first exec may arrive before the cage has an fdtable entry
    // (e.g. right after fork).  Use the lock-protected helper to avoid
    // the TOCTOU race in the raw check + init pattern.
    ipc::ensure_cage_exists(cage_id);

    // Close cloexec fds.
    fdtables::empty_fds_for_exec(cage_id);

    // Reserve fds 0/1/2 (stdin/stdout/stderr) so that pipe() and socket()
    // never allocate them.  Without this, the first pipe() gets fds 0 and 1,
    // which hijacks stdout — every printf goes into a pipe instead of the
    // console.  fdkind=0 marks these as non-IPC (lookup_ipc_fd ignores them).
    for fd in 0..3u64 {
        let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
    }

    forward_syscall(
        SYS_EXEC, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

// =====================================================================
//  Socket handlers
// =====================================================================

/// socket (syscall 41): create a socket descriptor.
///
/// For AF_UNIX and AF_INET loopback, we create a socket in our registry
/// and return a fd via fdtables. For other domains, forward to kernel.
pub extern "C" fn socket_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // domain
    arg2: u64, _arg2cage: u64,   // type
    arg3: u64, _arg3cage: u64,   // protocol
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let domain = arg1 as i32;
    let socktype = arg2 as i32;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    // Only handle AF_UNIX and AF_INET (for potential loopback).
    if domain != socket::AF_UNIX && domain != socket::AF_INET {
        return forward_syscall(SYS_SOCKET, cage_id, &args, &arg_cages);
    }

    if domain == socket::AF_UNIX {
        // AF_UNIX: entirely ours. Create in registry, register in fdtables.
        ensure_cage_exists(cage_id);
        let socket_id = with_ipc(|s| s.sockets.create_socket(domain, socktype, 0));

        return match fdtables::get_unused_virtual_fd(
            cage_id, socket::IPC_SOCKET, socket_id, false, 0,
        ) {
            Ok(fd) => fd as i32,
            Err(_) => {
                with_ipc(|s| s.sockets.remove(socket_id));
                -24 // EMFILE
            }
        };
    }

    // AF_INET: forward to kernel to get a real fd. We don't know yet
    // whether this will be loopback (127.0.0.1) or remote. We'll find
    // out at bind/connect time. If loopback, we close the kernel fd
    // and take over with pipes. If not, we drop our tracking.
    let kernel_fd = forward_syscall(SYS_SOCKET, cage_id, &args, &arg_cages);
    if kernel_fd < 0 {
        return kernel_fd;
    }

    // Create a socket in our registry and track it as pending.
    let socket_id = with_ipc(|s| {
        let sid = s.sockets.create_socket(domain, socktype, 0);
        s.pending_inet.insert((cage_id, kernel_fd as u64), sid);
        sid
    });

    kernel_fd
}

/// socketpair (syscall 53): create a connected pair of unix sockets.
pub extern "C" fn socketpair_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // domain
    arg2: u64, _arg2cage: u64,   // type
    arg3: u64, _arg3cage: u64,   // protocol
    arg4: u64, arg4cage: u64,    // sv[2] pointer
    _arg5: u64, _arg5cage: u64,
    _arg6: u64, _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let domain = arg1 as i32;
    let socktype = arg2 as i32;
    let this_cage = getcageid();

    if domain != socket::AF_UNIX {
        return -97; // EAFNOSUPPORT
    }

    ensure_cage_exists(cage_id);

    // Create connected pair with swapped pipes.
    let (sid1, sid2) = with_ipc(|s| {
        s.sockets.create_socketpair(domain, socktype, 0)
    });

    // Allocate two fds.
    let fd1 = match fdtables::get_unused_virtual_fd(
        cage_id, socket::IPC_SOCKET, sid1, false, 0,
    ) {
        Ok(fd) => fd as i32,
        Err(_) => return -24,
    };

    let fd2 = match fdtables::get_unused_virtual_fd(
        cage_id, socket::IPC_SOCKET, sid2, false, 0,
    ) {
        Ok(fd) => fd as i32,
        Err(_) => {
            let _ = fdtables::close_virtualfd(cage_id, fd1 as u64);
            return -24;
        }
    };

    // Write the two fds back to the cage's sv[2] array.
    let sv: [i32; 2] = [fd1, fd2];
    let _ = copy_data_between_cages(
        this_cage, arg4cage,
        sv.as_ptr() as u64, this_cage,
        arg4, arg4cage,
        8, 0,
    );

    0
}

/// bind (syscall 49): bind a socket to an address.
///
/// For AF_UNIX: stores the path in our registry (already in fdtables).
/// For AF_INET: reads the address to check for loopback.
///   - If 127.0.0.1: close the kernel fd, take over with pipes, register in fdtables.
///   - If not 127.0.0.1: drop from our tracking, forward to kernel.
pub extern "C" fn bind_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // addr
    arg3: u64, _arg3cage: u64,   // addrlen
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    // Read the sockaddr from cage memory to determine the address.
    let addrlen = arg3 as usize;
    if addrlen < 2 {
        return forward_syscall(SYS_BIND, cage_id, &args, &arg_cages);
    }
    let mut addr_buf = vec![0u8; addrlen];
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        arg2, arg2cage,
        addr_buf.as_mut_ptr() as u64, this_cage,
        addrlen as u64, 0,
    );

    let family = u16::from_le_bytes([addr_buf[0], addr_buf[1]]) as i32;

    // Check if this is an AF_UNIX socket already in fdtables.
    if let Some((socket_id, fdkind, _flags)) = lookup_ipc_fd(cage_id, fd) {
        if fdkind == socket::IPC_SOCKET && family == socket::AF_UNIX {
            let path_bytes = &addr_buf[2..];
            let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
            let addr_string = String::from_utf8_lossy(&path_bytes[..len]).to_string();

            return with_ipc(|s| {
                if let Some(sock) = s.sockets.get_mut(socket_id) {
                    sock.local_addr = Some(addr_string.clone());
                }
                s.sockets.bound_paths.insert(addr_string, socket_id);
                0
            });
        }
    }

    // Check if this is a pending AF_INET socket (not yet in fdtables).
    let pending_socket_id = with_ipc(|s| {
        s.pending_inet.get(&(cage_id, fd)).copied()
    });

    if let Some(socket_id) = pending_socket_id {
        if family == socket::AF_INET {
            // Extract the IP address (bytes 4-7) and port (bytes 2-3).
            let port = u16::from_be_bytes([addr_buf[2], addr_buf[3]]);
            let ip = if addrlen >= 8 {
                [addr_buf[4], addr_buf[5], addr_buf[6], addr_buf[7]]
            } else {
                [0, 0, 0, 0]
            };

            let is_loopback = ip == [127, 0, 0, 1] || ip == [0, 0, 0, 0];

            if is_loopback {
                // Take over: close the kernel fd and register in fdtables.
                forward_syscall(SYS_CLOSE, cage_id,
                    &[fd, 0, 0, 0, 0, 0], &[arg1cage, 0, 0, 0, 0, 0]);

                let addr_string = format!("127.0.0.1:{}", port);

                // Register in fdtables at the same fd number.
                let _ = fdtables::get_specific_virtual_fd(
                    cage_id, fd, socket::IPC_SOCKET, socket_id, false, 0,
                );

                return with_ipc(|s| {
                    s.pending_inet.remove(&(cage_id, fd));
                    if let Some(sock) = s.sockets.get_mut(socket_id) {
                        sock.local_addr = Some(addr_string.clone());
                    }
                    s.sockets.bound_paths.insert(addr_string, socket_id);
                    0
                });
            } else {
                // Not loopback — drop our tracking, let kernel own it.
                with_ipc(|s| {
                    s.pending_inet.remove(&(cage_id, fd));
                    s.sockets.remove(socket_id);
                });
                return forward_syscall(SYS_BIND, cage_id, &args, &arg_cages);
            }
        }
    }

    // Not ours — forward.
    forward_syscall(SYS_BIND, cage_id, &args, &arg_cages)
}

/// listen (syscall 50): mark a socket as listening.
pub extern "C" fn listen_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, _arg2cage: u64,   // backlog
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_LISTEN, cage_id, &args, &arg_cages);
    }

    let (socket_id, fdkind, _) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return -88; // ENOTSOCK
    }

    with_ipc(|s| {
        if let Some(sock) = s.sockets.get_mut(socket_id) {
            sock.state = socket::ConnState::Listening;
        }
    });

    0
}

/// connect (syscall 42): connect to a listening socket.
///
/// For AF_UNIX and loopback AF_INET: creates pipe pair, stores them with
/// swapped directions, pushes a pending connection for accept() to consume.
///
/// For pending AF_INET: checks if the target is loopback. If yes, closes
/// kernel fd and takes over. If not, drops tracking and forwards to kernel.
pub extern "C" fn connect_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // addr
    arg3: u64, _arg3cage: u64,   // addrlen
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    // Read the target address from cage memory.
    let addrlen = arg3 as usize;
    if addrlen < 2 {
        return forward_syscall(SYS_CONNECT, cage_id, &args, &arg_cages);
    }
    let mut addr_buf = vec![0u8; addrlen];
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        arg2, arg2cage,
        addr_buf.as_mut_ptr() as u64, this_cage,
        addrlen as u64, 0,
    );

    let family = u16::from_le_bytes([addr_buf[0], addr_buf[1]]) as i32;

    // Resolve the socket_id — either from fdtables (AF_UNIX) or pending_inet (AF_INET).
    let socket_id = if let Some((sid, fdkind, _)) = lookup_ipc_fd(cage_id, fd) {
        if fdkind != socket::IPC_SOCKET {
            return forward_syscall(SYS_CONNECT, cage_id, &args, &arg_cages);
        }
        sid
    } else if let Some(sid) = with_ipc(|s| s.pending_inet.get(&(cage_id, fd)).copied()) {
        // Pending AF_INET socket. Check if target is loopback.
        if family == socket::AF_INET {
            let ip = if addrlen >= 8 {
                [addr_buf[4], addr_buf[5], addr_buf[6], addr_buf[7]]
            } else {
                [0, 0, 0, 0]
            };
            let is_loopback = ip == [127, 0, 0, 1] || ip == [0, 0, 0, 0];

            if is_loopback {
                // Take over: close kernel fd, register in fdtables.
                forward_syscall(SYS_CLOSE, cage_id,
                    &[fd, 0, 0, 0, 0, 0], &[arg1cage, 0, 0, 0, 0, 0]);

                let _ = fdtables::get_specific_virtual_fd(
                    cage_id, fd, socket::IPC_SOCKET, sid, false, 0,
                );
                with_ipc(|s| { s.pending_inet.remove(&(cage_id, fd)); });
                sid
            } else {
                // Not loopback — drop tracking, forward to kernel.
                with_ipc(|s| {
                    s.pending_inet.remove(&(cage_id, fd));
                    s.sockets.remove(sid);
                });
                return forward_syscall(SYS_CONNECT, cage_id, &args, &arg_cages);
            }
        } else {
            return forward_syscall(SYS_CONNECT, cage_id, &args, &arg_cages);
        }
    } else {
        return forward_syscall(SYS_CONNECT, cage_id, &args, &arg_cages);
    };

    // Parse the target address string for our registry.
    let target_addr = if family == socket::AF_UNIX {
        let path_bytes = &addr_buf[2..];
        let len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        String::from_utf8_lossy(&path_bytes[..len]).to_string()
    } else if family == socket::AF_INET {
        let port = u16::from_be_bytes([addr_buf[2], addr_buf[3]]);
        format!("127.0.0.1:{}", port)
    } else {
        return -97;
    };

    with_ipc(|s| {
        // Check that the target is bound and listening.
        if !s.sockets.bound_paths.contains_key(&target_addr) {
            return -111; // ECONNREFUSED
        }

        // Create two pipes for the bidirectional connection.
        let pipe_to_listener = std::sync::Arc::new(pipe::PipeBuffer::new(socket::UDSOCK_CAPACITY));
        let pipe_to_connector = std::sync::Arc::new(pipe::PipeBuffer::new(socket::UDSOCK_CAPACITY));

        // Set up the connecting socket's pipes.
        if let Some(conn_sock) = s.sockets.get_mut(socket_id) {
            conn_sock.sendpipe = Some(pipe_to_listener.clone());
            conn_sock.recvpipe = Some(pipe_to_connector.clone());
            conn_sock.state = socket::ConnState::Connected;
            conn_sock.remote_addr = Some(target_addr.clone());
        }

        // Queue a pending connection for accept().
        let local_addr = s.sockets.get(socket_id)
            .and_then(|sock| sock.local_addr.clone())
            .unwrap_or_default();

        let pending = socket::PendingConnection {
            remote_addr: local_addr,
            pipe_to_listener,
            pipe_to_connector,
        };

        s.sockets.pending_connections
            .entry(target_addr)
            .or_insert_with(Vec::new)
            .push(pending);

        0
    })
}

/// accept (syscall 43): accept a pending connection.
///
/// Pops from the pending connection queue, creates a new connected socket
/// with swapped pipe directions, and returns the new fd.
pub extern "C" fn accept_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd (listening socket)
    arg2: u64, arg2cage: u64,    // addr (output, can be NULL)
    arg3: u64, _arg3cage: u64,   // addrlen (output, can be NULL)
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, _arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_ACCEPT, cage_id, &args, &arg_cages);
    }

    let (socket_id, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return -88;
    }

    let nonblocking = (flags & O_NONBLOCK) != 0;

    // Get the listening address.
    let listen_addr = with_ipc(|s| {
        s.sockets.get(socket_id).and_then(|sock| sock.local_addr.clone())
    });

    let listen_addr = match listen_addr {
        Some(a) => a,
        None => return -22, // EINVAL — not bound
    };

    // Spin-wait for a pending connection (or return EAGAIN if nonblocking).
    loop {
        let pending = with_ipc(|s| {
            if let Some(queue) = s.sockets.pending_connections.get_mut(&listen_addr) {
                if !queue.is_empty() {
                    return Some(queue.remove(0));
                }
            }
            None
        });

        if let Some(conn) = pending {
            // Create a new socket for the accepted connection.
            // Pipe directions are swapped: listener reads what connector writes.
            let new_socket_id = with_ipc(|s| {
                let domain = s.sockets.get(socket_id).map(|sock| sock.domain).unwrap_or(socket::AF_UNIX);
                let socktype = s.sockets.get(socket_id).map(|sock| sock.socktype).unwrap_or(socket::SOCK_STREAM);

                let new_id = s.sockets.create_socket(domain, socktype, 0);
                if let Some(new_sock) = s.sockets.get_mut(new_id) {
                    // Swapped: listener's recv = connector's send pipe
                    new_sock.recvpipe = Some(conn.pipe_to_listener);
                    // Listener's send = connector's recv pipe
                    new_sock.sendpipe = Some(conn.pipe_to_connector);
                    new_sock.state = socket::ConnState::Connected;
                    new_sock.remote_addr = Some(conn.remote_addr);
                }
                new_id
            });

            // Allocate fd for the new socket.
            match fdtables::get_unused_virtual_fd(
                cage_id, socket::IPC_SOCKET, new_socket_id, false, 0,
            ) {
                Ok(new_fd) => return new_fd as i32,
                Err(_) => {
                    with_ipc(|s| s.sockets.remove(new_socket_id));
                    return -24; // EMFILE
                }
            }
        }

        if nonblocking {
            return -11; // EAGAIN
        }

        std::thread::yield_now();
    }
}

/// shutdown (syscall 48): shut down part of a socket connection.
pub extern "C" fn shutdown_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, _arg2cage: u64,   // how (SHUT_RD/SHUT_WR/SHUT_RDWR)
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let how = arg2 as i32;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_syscall(SYS_SHUTDOWN, cage_id, &args, &arg_cages);
    }

    let (socket_id, fdkind, _) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return -88;
    }

    with_ipc(|s| {
        if let Some(sock) = s.sockets.get_mut(socket_id) {
            match how {
                socket::SHUT_RD => {
                    sock.state = match sock.state {
                        socket::ConnState::Connected => socket::ConnState::WriteOnly,
                        _ => socket::ConnState::NotConnected,
                    };
                }
                socket::SHUT_WR => {
                    // Set EOF on the send pipe so the peer's reads return 0.
                    if let Some(ref sendpipe) = sock.sendpipe {
                        sendpipe.decr_write_ref();
                    }
                    sock.state = match sock.state {
                        socket::ConnState::Connected => socket::ConnState::ReadOnly,
                        _ => socket::ConnState::NotConnected,
                    };
                }
                socket::SHUT_RDWR => {
                    if let Some(ref sendpipe) = sock.sendpipe {
                        sendpipe.decr_write_ref();
                    }
                    sock.state = socket::ConnState::NotConnected;
                }
                _ => return -22, // EINVAL
            }
        }
        0
    })
}

// =====================================================================
//  Main
// =====================================================================

fn main() {
    let grate_cage_id = getcageid();
    init(grate_cage_id);
    ipc::init_fork_sem();

    let argv: Vec<String> = std::env::args().skip(1).collect();

    GrateBuilder::new()
        // Pipe syscalls
        .register(SYS_PIPE, pipe_handler)
        .register(SYS_PIPE2, pipe2_handler)
        // I/O syscalls (handle both pipes and sockets)
        .register(SYS_READ, read_handler)
        .register(SYS_WRITE, write_handler)
        .register(SYS_CLOSE, close_handler)
        .register(SYS_DUP, dup_handler)
        .register(SYS_DUP2, dup2_handler)
        .register(SYS_DUP3, dup3_handler)
        .register(SYS_FCNTL, fcntl_handler)
        // Socket syscalls
        .register(SYS_SOCKET, socket_handler)
        .register(SYS_SOCKETPAIR, socketpair_handler)
        .register(SYS_BIND, bind_handler)
        .register(SYS_LISTEN, listen_handler)
        .register(SYS_CONNECT, connect_handler)
        .register(SYS_ACCEPT, accept_handler)
        .register(SYS_SHUTDOWN, shutdown_handler)
        // Lifecycle
        .register(SYS_CLONE, fork_handler)
        .register(SYS_EXEC, exec_handler)
        .teardown(|result: Result<i32, GrateError>| {
            println!("[ipc-grate] exited: {:?}", result);
        })
        .run(argv);
}
