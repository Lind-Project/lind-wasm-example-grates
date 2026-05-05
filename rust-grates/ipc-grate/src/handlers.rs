//! Syscall handlers for the IPC grate.

use grate_rs::constants::*;
use grate_rs::{copy_data_between_cages, copy_handler_table_to_cage, getcageid, is_thread_clone};

use crate::helpers::forward_syscall;
use crate::ipc::*;
use crate::pipe;
use crate::socket;

/// fdkind value for non-IPC fds tracked in fdtables.  `underfd` for these
/// entries is the runtime's (RawPOSIX's) virt fd — it is NOT identical to
/// the grate's virt fd, since the grate and the runtime each maintain
/// their own fdtables instance (wasm linear memory vs host).  We translate
/// grate-vfd → runtime-vfd via `translate_to_underfd` whenever forwarding
/// a syscall to RawPOSIX.
const FDKIND_KERNEL: u32 = 0;

/// EBADF, EMFILE in negative-errno form.
const EBADF_NEG: i32 = -9;
const EMFILE_NEG: i32 = -24;

/// AT_FDCWD is the special "current working directory" sentinel for the
/// *at family of syscalls; it must NOT be translated.
const AT_FDCWD: i64 = -100;

/// Translate a grate virt fd to the runtime's virt fd (the underfd).
/// Returns None if the fd doesn't exist in our fdtable.
fn translate_to_underfd(cage: u64, fd: u64) -> Option<u64> {
    fdtables::translate_virtual_fd(cage, fd).ok().map(|e| e.underfd)
}

/// Translate a possibly-AT_FDCWD dirfd; AT_FDCWD passes through unchanged.
fn translate_dirfd(cage: u64, fd: u64) -> Option<u64> {
    if (fd as i64) == AT_FDCWD {
        return Some(fd);
    }
    translate_to_underfd(cage, fd)
}

/// Forward a syscall whose first argument is an fd, translating that fd
/// to its runtime underfd before forwarding.  Returns -EBADF if the fd
/// isn't tracked in our grate fdtable.
fn forward_with_fd1(syscall: u64, cage: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let under = match translate_to_underfd(cage, args[0]) {
        Some(u) => u,
        None => return EBADF_NEG,
    };
    let mut t = args;
    t[0] = under;
    forward_syscall(syscall, cage, &t, &arg_cages)
}

/// Forward a syscall whose first argument is a dirfd (may be AT_FDCWD).
fn forward_with_dirfd1(syscall: u64, cage: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let under = match translate_dirfd(cage, args[0]) {
        Some(u) => u,
        None => return EBADF_NEG,
    };
    let mut t = args;
    t[0] = under;
    forward_syscall(syscall, cage, &t, &arg_cages)
}

/// Register a runtime-allocated virt fd in the grate's fdtable as a
/// FDKIND_KERNEL entry, returning a fresh grate virt fd that maps to it.
/// On allocation failure, close the runtime fd and return -EMFILE.
fn register_kernel_fd(cage: u64, runtime_vfd: i32, cloexec: bool, perfdinfo: u64) -> i32 {
    match fdtables::get_unused_virtual_fd(
        cage, FDKIND_KERNEL, runtime_vfd as u64, cloexec, perfdinfo,
    ) {
        Ok(grate_vfd) => grate_vfd as i32,
        Err(_) => {
            forward_syscall(
                SYS_CLOSE, cage,
                &[runtime_vfd as u64, 0, 0, 0, 0, 0],
                &[cage, 0, 0, 0, 0, 0],
            );
            EMFILE_NEG
        }
    }
}

/// poll(2) event bits we care about.
const POLLIN: i16   = 0x0001;
const POLLPRI: i16  = 0x0002;
const POLLOUT: i16  = 0x0004;
const POLLERR: i16  = 0x0008;
const POLLHUP: i16  = 0x0010;
const POLLNVAL: i16 = 0x0020;

/// Layout of `struct pollfd` (POSIX): 4-byte fd, 2-byte events, 2-byte revents.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// fdtables-level close handler for IPC_PIPE entries.  Called whenever
/// fdtables decrements an IPC_PIPE entry's refcount — including on
/// `close_virtualfd`, `empty_fds_for_exec`, and `remove_cage_from_fdtable`
/// (cage exit).  This is the single source of truth for pipe-object
/// refcount management, so we don't have to plumb decrements through
/// every code path that might remove an entry.
pub fn ipc_pipe_close_handler(entry: fdtables::FDTableEntry, _count: u64) -> Result<(), i32> {
    if let Some(pipe_arc) = with_ipc(|s| s.get_pipe(entry.underfd)) {
        let flags = entry.perfdinfo as i32;
        if is_read_end(flags) {
            pipe_arc.decr_read_ref();
        } else {
            pipe_arc.decr_write_ref();
        }
    }
    Ok(())
}

/// exit (syscall 60) / exit_group (syscall 231).
///
/// RawPOSIX's exit path calls `fdtables::remove_cage_from_fdtable` on
/// its own fdtables instance, but our IPC grate has its own separate
/// instance.  Without intercepting exit, our fdtables for the exiting
/// cage stays populated with stale IPC entries — pipe refcounts never
/// decrement on process exit, so EOF never fires when a popen child
/// exits without explicitly closing its pipe end.
///
/// We mirror RawPOSIX's behavior: remove the cage from OUR fdtables
/// (which fires close handlers and decrements pipe/socket refs), then
/// forward exit to the runtime.
pub extern "C" fn exit_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;

    if fdtables::check_cage_exists(cage_id) {
        fdtables::remove_cage_from_fdtable(cage_id);
    }

    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    forward_syscall(SYS_EXIT, cage_id, &args, &arg_cages)
}

/// exit_group (syscall 231): same cleanup as exit_handler but forwards
/// SYS_EXIT_GROUP.
pub extern "C" fn exit_group_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;

    if fdtables::check_cage_exists(cage_id) {
        fdtables::remove_cage_from_fdtable(cage_id);
    }

    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    forward_syscall(SYS_EXIT_GROUP, cage_id, &args, &arg_cages)
}

/// fdtables-level close handler for IPC_SOCKET entries.
pub fn ipc_socket_close_handler(entry: fdtables::FDTableEntry, _count: u64) -> Result<(), i32> {
    with_ipc(|s| {
        if let Some(sock) = s.sockets.get(entry.underfd) {
            if let Some(ref sp) = sock.sendpipe { sp.decr_write_ref(); }
            if let Some(ref rp) = sock.recvpipe { rp.decr_read_ref(); }
        }
    });
    Ok(())
}


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
        return forward_with_fd1(SYS_READ, cage_id, args, arg_cages);
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
        return forward_with_fd1(SYS_WRITE, cage_id, args, arg_cages);
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

    let ret = pipe.write(&buf, count, nonblocking);
    ret
}

/// Compute the revents bits for an IPC fd given the requested events.
/// Reads the pipe state directly via has_data / write_refs / read_refs.
fn ipc_pipe_poll_state(underfd: u64, fdkind: u32, flags: i32, requested: i16) -> i16 {
    let mut revents: i16 = 0;
    let pipe_arc = match fdkind {
        IPC_PIPE => with_ipc(|s| s.get_pipe(underfd)),
        socket::IPC_SOCKET => with_ipc(|s| {
            // For socket reads → recvpipe; for writes → sendpipe.
            // We'll fetch both and pick based on the requested events.
            let _ = s; // placate unused if needed
            s.sockets.get(underfd).and_then(|sock| {
                if (requested & POLLIN) != 0 {
                    sock.recvpipe.clone()
                } else if (requested & POLLOUT) != 0 {
                    sock.sendpipe.clone()
                } else {
                    None
                }
            })
        }),
        _ => return POLLNVAL,
    };

    let pipe = match pipe_arc {
        Some(p) => p,
        None => return POLLNVAL,
    };

    // For pipes, check direction matches the request.
    let is_reader = match fdkind {
        IPC_PIPE => is_read_end(flags),
        socket::IPC_SOCKET => (requested & POLLIN) != 0,
        _ => return POLLNVAL,
    };

    if (requested & POLLIN) != 0 && is_reader {
        if pipe.has_data() {
            revents |= POLLIN;
        } else if pipe.write_refs.load(std::sync::atomic::Ordering::Acquire) == 0 {
            // No writers — peer hung up, EOF.  POSIX requires POLLHUP.
            revents |= POLLHUP;
        }
    }
    if (requested & POLLOUT) != 0 && !is_reader {
        if pipe.has_space() {
            revents |= POLLOUT;
        } else if pipe.read_refs.load(std::sync::atomic::Ordering::Acquire) == 0 {
            revents |= POLLERR;
        }
    }

    revents
}

/// poll (syscall 7): handle IPC fds locally; mark them negative so the
/// kernel ignores them when we forward, then merge our IPC revents
/// back in.  Per poll(2) "if fd is less than 0, then events shall be
/// ignored, and revents shall be set to 0 in that entry."
pub extern "C" fn poll_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // pollfd *fds
    arg2: u64, arg2cage: u64,    // nfds
    arg3: u64, arg3cage: u64,    // timeout (ms)
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nfds = arg2 as usize;
    let this_cage = getcageid();

    // Empty / null poll: just forward (kernel handles it).
    if nfds == 0 || arg1 == 0 {
        let args = [arg1, arg2, arg3, arg4, arg5, arg6];
        let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
        return forward_syscall(SYS_POLL, cage_id, &args, &arg_cages);
    }

    // Read pollfd[] from the cage into a local buffer.
    let mut pollfds = vec![PollFd::default(); nfds];
    let bytes = (nfds * core::mem::size_of::<PollFd>()) as u64;
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        arg1, arg1cage,
        pollfds.as_mut_ptr() as u64, this_cage,
        bytes, 0,
    );

    // First pass: classify each entry.  For IPC entries, compute revents
    // immediately and remember so we can replace negative fd back to
    // positive for the result.  Save the original fd values so we can
    // restore them in the result.
    let mut original_fds: Vec<i32> = pollfds.iter().map(|p| p.fd).collect();
    let mut ipc_revents: Vec<i16> = vec![0; nfds];
    let mut ipc_indices: Vec<usize> = Vec::new();
    let mut total_ready: i32 = 0;

    for (i, pfd) in pollfds.iter_mut().enumerate() {
        if pfd.fd < 0 {
            pfd.revents = 0;
            continue;
        }
        if let Some((underfd, fdkind, flags)) = lookup_ipc_fd(cage_id, pfd.fd as u64) {
            let revents = ipc_pipe_poll_state(underfd, fdkind, flags, pfd.events);
            ipc_revents[i] = revents;
            if revents != 0 {
                total_ready += 1;
            }
            ipc_indices.push(i);
            // Mark negative so the kernel ignores this entry on forward.
            pfd.fd = -1;
        } else {
            // Non-IPC fd: translate grate vfd → runtime vfd before forwarding.
            // The original grate vfd is preserved in `original_fds` and
            // restored after the kernel returns.
            match translate_to_underfd(cage_id, pfd.fd as u64) {
                Some(u) => pfd.fd = u as i32,
                None => pfd.fd = -1, // unknown — make kernel ignore it
            }
        }
    }

    // If the only non-trivial fds were IPC (no kernel fds to wait on)
    // AND any of them are ready, return immediately.  Otherwise we'd
    // need the kernel to wait on the timeout — we still forward in
    // that case so the caller's timeout is honored.
    let has_kernel_fd = pollfds.iter().any(|p| p.fd >= 0);

    if has_kernel_fd || total_ready == 0 {
        // Adjust timeout: if we already have IPC entries ready, do a
        // non-blocking kernel check (timeout=0) so we return promptly.
        let kernel_timeout = if total_ready > 0 { 0i32 } else { arg3 as i32 };

        // Write the modified pollfd[] back to the cage so the kernel
        // can read it, then forward.
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            pollfds.as_ptr() as u64, this_cage,
            arg1, arg1cage,
            bytes, 0,
        );
        let args = [arg1, arg2, kernel_timeout as u64, arg4, arg5, arg6];
        let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
        let kernel_ret = forward_syscall(SYS_POLL, cage_id, &args, &arg_cages);
        if kernel_ret < 0 {
            return kernel_ret;
        }
        total_ready += kernel_ret;

        // Read back the cage's modified pollfd[] (kernel filled in
        // revents for the kernel fds; IPC fds have fd=-1 so revents=0).
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg1, arg1cage,
            pollfds.as_mut_ptr() as u64, this_cage,
            bytes, 0,
        );
    }

    // Restore original fd values for ALL entries (kernel saw runtime vfds
    // for kernel-backed entries; user expects their original grate vfds).
    // Then overlay our IPC-computed revents on the IPC entries.
    for i in 0..nfds {
        pollfds[i].fd = original_fds[i];
    }
    for i in &ipc_indices {
        pollfds[*i].revents = ipc_revents[*i];
    }

    // Write final pollfd[] back to the cage.
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        pollfds.as_ptr() as u64, this_cage,
        arg1, arg1cage,
        bytes, 0,
    );

    total_ready
}

/// fd_set is 1024 bits.  Under WASM32, __NFDBITS == 32, so the
/// underlying array is 32 × u32 = 128 bytes.
const FD_SETSIZE: usize = 1024;
const FD_SET_WORDS: usize = FD_SETSIZE / 32;
const FD_SET_BYTES: usize = FD_SET_WORDS * 4;

#[inline] fn fd_isset(fd: usize, set: &[u32; FD_SET_WORDS]) -> bool {
    fd < FD_SETSIZE && (set[fd >> 5] & (1u32 << (fd & 31))) != 0
}
#[inline] fn fd_set_bit(fd: usize, set: &mut [u32; FD_SET_WORDS]) {
    if fd < FD_SETSIZE { set[fd >> 5] |= 1u32 << (fd & 31); }
}
#[inline] fn fd_clr_bit(fd: usize, set: &mut [u32; FD_SET_WORDS]) {
    if fd < FD_SETSIZE { set[fd >> 5] &= !(1u32 << (fd & 31)); }
}

/// select (syscall 23): handle IPC fds locally, forward kernel fds.
///
/// Same shape as poll_handler: classify each fd in the bitmasks; for
/// IPC entries, compute readiness directly from pipe state; clear the
/// bit before forwarding so the kernel doesn't see it; after the
/// kernel returns, merge our IPC bits back in.
pub extern "C" fn select_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // nfds
    arg2: u64, _arg2cage: u64,   // readfds
    arg3: u64, _arg3cage: u64,   // writefds
    arg4: u64, _arg4cage: u64,   // exceptfds
    arg5: u64, arg5cage: u64,    // timeout
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nfds = arg1 as usize;
    let this_cage = getcageid();

    if nfds == 0 || nfds > FD_SETSIZE {
        let args = [arg1, arg2, arg3, arg4, arg5, arg6];
        let arg_cages = [arg1cage, _arg2cage, _arg3cage, _arg4cage, arg5cage, arg6cage];
        return forward_syscall(SYS_SELECT, cage_id, &args, &arg_cages);
    }

    // Read each fd_set (if non-null) into local buffers.  Track which
    // sets are present so we can write only those back later.
    let mut read_set:   [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut write_set:  [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut except_set: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let have_r = arg2 != 0;
    let have_w = arg3 != 0;
    let have_e = arg4 != 0;

    if have_r {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg2, arg1cage,
            read_set.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_w {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg3, arg1cage,
            write_set.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_e {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg4, arg1cage,
            except_set.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }

    // Build kernel-side sets (containing runtime vfds) and a reverse
    // map (runtime_vfd → grate_vfd) so we can reconstruct the user-visible
    // result sets after the kernel returns.  IPC fds are handled locally
    // and never forwarded.
    let mut k_read:   [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut k_write:  [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut k_except: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];

    let mut ipc_read:   [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut ipc_write:  [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut ipc_except: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut ipc_ready: i32 = 0;

    // Reverse map: runtime_vfd → Option<grate_vfd>.  Sized to FD_SETSIZE
    // since runtime vfds are also bounded by the same limit.
    let mut rev_map: Vec<Option<usize>> = vec![None; FD_SETSIZE];
    let mut max_under: usize = 0;

    for fd in 0..nfds {
        let want_r = have_r && fd_isset(fd, &read_set);
        let want_w = have_w && fd_isset(fd, &write_set);
        let want_e = have_e && fd_isset(fd, &except_set);
        if !want_r && !want_w && !want_e { continue; }

        if let Some((underfd, fdkind, flags)) = lookup_ipc_fd(cage_id, fd as u64) {
            let mut requested_events: i16 = 0;
            if want_r { requested_events |= POLLIN; }
            if want_w { requested_events |= POLLOUT; }
            let revents = ipc_pipe_poll_state(underfd, fdkind, flags, requested_events);

            if want_r && (revents & (POLLIN | POLLHUP)) != 0 {
                fd_set_bit(fd, &mut ipc_read);
                ipc_ready += 1;
            }
            if want_w && (revents & (POLLOUT | POLLERR)) != 0 {
                fd_set_bit(fd, &mut ipc_write);
                ipc_ready += 1;
            }
            if want_e && (revents & POLLERR) != 0 {
                fd_set_bit(fd, &mut ipc_except);
                ipc_ready += 1;
            }
            continue;
        }

        // Non-IPC: translate to runtime vfd and place in kernel-side sets.
        let under = match translate_to_underfd(cage_id, fd as u64) {
            Some(u) => u as usize,
            None => continue,  // unknown fd — drop it
        };
        if under < FD_SETSIZE {
            rev_map[under] = Some(fd);
            if under > max_under { max_under = under; }
            if want_r { fd_set_bit(under, &mut k_read); }
            if want_w { fd_set_bit(under, &mut k_write); }
            if want_e { fd_set_bit(under, &mut k_except); }
        }
    }

    // Write the kernel-side sets to a scratch region in cage memory by
    // overwriting the original set buffers.  After we collect kernel
    // results we'll rebuild the grate-side sets and write those back.
    if have_r {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            k_read.as_ptr() as u64, this_cage,
            arg2, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_w {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            k_write.as_ptr() as u64, this_cage,
            arg3, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_e {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            k_except.as_ptr() as u64, this_cage,
            arg4, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }

    // Forward to kernel with runtime_nfds = max_under + 1 (or original nfds
    // if no kernel fds remain so kernel still honors the timeout).
    let runtime_nfds = if max_under > 0 { (max_under + 1) as u64 } else { arg1 };
    let args = [runtime_nfds, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, _arg2cage, _arg3cage, _arg4cage, arg5cage, arg6cage];
    let kernel_ret = forward_syscall(SYS_SELECT, cage_id, &args, &arg_cages);
    if kernel_ret < 0 {
        return kernel_ret;
    }

    // Read back kernel-modified sets, translate runtime vfds → grate vfds,
    // OR in our IPC bits, and write the result back.
    let mut out_r: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut out_w: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut out_e: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];

    if have_r {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg2, arg1cage,
            k_read.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_w {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg3, arg1cage,
            k_write.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_e {
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            arg4, arg1cage,
            k_except.as_mut_ptr() as u64, this_cage,
            FD_SET_BYTES as u64, 0,
        );
    }

    for under in 0..=max_under {
        if let Some(grate_fd) = rev_map[under] {
            if have_r && fd_isset(under, &k_read)   { fd_set_bit(grate_fd, &mut out_r); }
            if have_w && fd_isset(under, &k_write)  { fd_set_bit(grate_fd, &mut out_w); }
            if have_e && fd_isset(under, &k_except) { fd_set_bit(grate_fd, &mut out_e); }
        }
    }

    if have_r {
        for i in 0..FD_SET_WORDS { out_r[i] |= ipc_read[i]; }
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            out_r.as_ptr() as u64, this_cage,
            arg2, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_w {
        for i in 0..FD_SET_WORDS { out_w[i] |= ipc_write[i]; }
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            out_w.as_ptr() as u64, this_cage,
            arg3, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }
    if have_e {
        for i in 0..FD_SET_WORDS { out_e[i] |= ipc_except[i]; }
        let _ = copy_data_between_cages(
            this_cage, arg1cage,
            out_e.as_ptr() as u64, this_cage,
            arg4, arg1cage,
            FD_SET_BYTES as u64, 0,
        );
    }

    kernel_ret + ipc_ready
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
        // Non-IPC fd: translate to runtime vfd, forward SYS_CLOSE so
        // RawPOSIX closes the kernel fd and removes its own entry, then
        // remove our grate-side entry.
        match translate_to_underfd(cage_id, fd) {
            Some(under) => {
                let mut t = args;
                t[0] = under;
                let ret = forward_syscall(SYS_CLOSE, cage_id, &t, &arg_cages);
                let _ = fdtables::close_virtualfd(cage_id, fd);
                ret
            }
            None => {
                // Not in our table at all — forward as-is for runtime to error.
                forward_syscall(SYS_CLOSE, cage_id, &args, &arg_cages)
            }
        }
    } else {
        // IPC pipe/socket: refs decrement via our registered close handler
        // when close_virtualfd removes the entry.
        let _ = fdtables::close_virtualfd(cage_id, fd);
        0
    }
}

/// open (syscall 2): forward to the runtime, then map the runtime virt fd
/// to a fresh grate virt fd via fdtables.
///
/// We allocate a NEW grate vfd (`get_unused_virtual_fd`) so the user-visible
/// fd never collides with a live IPC pipe/socket entry.  The runtime's vfd
/// is stored as the underfd; subsequent grate-side syscall handlers translate
/// grate-vfd → runtime-vfd (underfd) before forwarding.
pub extern "C" fn open_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,    // path
    arg2: u64, arg2cage: u64,    // flags
    arg3: u64, arg3cage: u64,    // mode
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let flags = arg2 as i32;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let runtime_vfd = forward_syscall(SYS_OPEN, cage_id, &args, &arg_cages);
    if runtime_vfd < 0 {
        return runtime_vfd;
    }
    let cloexec = (flags & O_CLOEXEC) != 0;
    register_kernel_fd(cage_id, runtime_vfd, cloexec, flags as u64)
}

/// openat (syscall 257): same as open but with a dirfd that may be AT_FDCWD.
pub extern "C" fn openat_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // dirfd
    arg2: u64, arg2cage: u64,    // path
    arg3: u64, arg3cage: u64,    // flags
    arg4: u64, arg4cage: u64,    // mode
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let flags = arg3 as i32;
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    args[0] = match translate_dirfd(cage_id, arg1) {
        Some(u) => u,
        None => return EBADF_NEG,
    };

    let runtime_vfd = forward_syscall(SYS_OPENAT, cage_id, &args, &arg_cages);
    if runtime_vfd < 0 {
        return runtime_vfd;
    }
    let cloexec = (flags & O_CLOEXEC) != 0;
    register_kernel_fd(cage_id, runtime_vfd, cloexec, flags as u64)
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
        // Non-IPC fd: translate to runtime vfd, forward SYS_DUP, register
        // the new runtime vfd as a fresh grate vfd.
        let under = match translate_to_underfd(cage_id, fd) {
            Some(u) => u,
            None => return EBADF_NEG,
        };
        let mut t = args;
        t[0] = under;
        let new_runtime_vfd = forward_syscall(SYS_DUP, cage_id, &t, &arg_cages);
        if new_runtime_vfd < 0 {
            return new_runtime_vfd;
        }
        return register_kernel_fd(cage_id, new_runtime_vfd, false, 0);
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

    if oldfd == newfd {
        return newfd as i32;
    }

    // Helper closure: if newfd currently maps to a runtime fd, close that
    // runtime fd before we overwrite the grate-side entry.  IPC entries
    // get refcount-decremented by the registered close handler that
    // get_specific_virtual_fd fires; FDKIND_KERNEL entries have no close
    // handler, so we have to forward SYS_CLOSE explicitly.
    let close_old_runtime_if_kernel = || {
        if let Ok(old) = fdtables::translate_virtual_fd(cage_id, newfd) {
            if old.fdkind == FDKIND_KERNEL {
                forward_syscall(SYS_CLOSE, cage_id,
                    &[old.underfd, 0, 0, 0, 0, 0],
                    &[cage_id, 0, 0, 0, 0, 0]);
            }
        }
    };

    let info = lookup_ipc_fd(cage_id, oldfd);
    if info.is_none() {
        // FDKIND_KERNEL oldfd: dup at the runtime to get a fresh runtime
        // vfd, then point grate's newfd at it.
        let old_under = match translate_to_underfd(cage_id, oldfd) {
            Some(u) => u,
            None => return EBADF_NEG,
        };
        let new_runtime_vfd = forward_syscall(
            SYS_DUP, cage_id,
            &[old_under, 0, 0, 0, 0, 0],
            &[cage_id, 0, 0, 0, 0, 0],
        );
        if new_runtime_vfd < 0 {
            return new_runtime_vfd;
        }
        close_old_runtime_if_kernel();
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, newfd, FDKIND_KERNEL, new_runtime_vfd as u64, false, 0,
        );
        return newfd as i32;
    }

    let (pipe_id, fdkind, flags) = info.unwrap();

    close_old_runtime_if_kernel();

    // get_specific_virtual_fd implicitly closes the previous entry on
    // newfd (calls our registered close handler if it was IPC), then
    // installs the new entry.
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

    // F_DUPFD / F_DUPFD_CLOEXEC need the same grate-side bookkeeping as the
    // dup-family syscalls: allocate a grate vfd ≥ arg3 backed by a fresh
    // runtime-side dup.  Handle these first so the path is uniform for both
    // IPC and FDKIND_KERNEL fds.
    if op == F_DUPFD || op == F_DUPFD_CLOEXEC {
        let cloexec = op == F_DUPFD_CLOEXEC;
        let min_fd = arg3;

        let info = lookup_ipc_fd(cage_id, fd);
        if let Some((pipe_id, fdkind, flags)) = info {
            let new_fd = match fdtables::get_unused_virtual_fd_from_startfd(
                cage_id, fdkind, pipe_id, cloexec, flags as u64, min_fd,
            ) {
                Ok(fd) => fd as i32,
                Err(_) => return -24,
            };
            // Bump refs for the duplicated entry so the IPC pipe/socket
            // outlives both the original and the dup.
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
            return new_fd;
        }

        // FDKIND_KERNEL or untracked: forward F_DUPFD(_CLOEXEC) to the
        // runtime to get a fresh runtime vfd ≥ min_fd, then map to a fresh
        // grate vfd ≥ min_fd.
        let under = match translate_to_underfd(cage_id, fd) {
            Some(u) => u,
            None => return EBADF_NEG,
        };
        let mut t = args;
        t[0] = under;
        let new_runtime_vfd = forward_syscall(SYS_FCNTL, cage_id, &t, &arg_cages);
        if new_runtime_vfd < 0 {
            return new_runtime_vfd;
        }
        return match fdtables::get_unused_virtual_fd_from_startfd(
            cage_id, FDKIND_KERNEL, new_runtime_vfd as u64, cloexec, 0, min_fd,
        ) {
            Ok(grate_vfd) => grate_vfd as i32,
            Err(_) => {
                forward_syscall(
                    SYS_CLOSE, cage_id,
                    &[new_runtime_vfd as u64, 0, 0, 0, 0, 0],
                    &[cage_id, 0, 0, 0, 0, 0],
                );
                EMFILE_NEG
            }
        };
    }

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_FCNTL, cage_id, args, arg_cages);
    }

    let (_pipe_id, _fdkind, flags) = info.unwrap();

    match op {
        F_GETFL => flags,
        F_SETFL => {
            // F_SETFL changes only the file status flags (O_APPEND,
            // O_NONBLOCK, O_ASYNC, O_DIRECT, O_NOATIME).  The access
            // mode (O_RDONLY/O_WRONLY/O_RDWR) is immutable.  We MUST
            // preserve those bits — they're how we distinguish pipe
            // read-end from write-end.  Overwriting them with just
            // arg3 (e.g. O_NONBLOCK alone) makes a write-end look like
            // a read-end, so writes return EBADF and postgres's
            // self-pipe wakeup never fires → WaitLatch hangs forever.
            let new_flags = (flags & O_ACCMODE) | (arg3 as i32 & !O_ACCMODE);
            let _ = fdtables::set_perfdinfo(cage_id, fd, new_flags as u64);
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
///   1. Pre-collect parent's pipe Arc refs via with_ipc (needs IPC_STATE).
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

    // Threads share the parent's fd table — only do fork bookkeeping
    // for process forks.
    let is_thread = is_thread_clone(arg1, arg1cage);

    // --- Phase 1: snapshot parent's fdtable and pre-collect pipe/socket
    //     Arc references BEFORE forking.  Uses IPC_STATE (via with_ipc) but
    //     NOT CAGE_INIT_LOCK, so no lock-ordering issue.
    enum RefBump {
        Pipe { pipe: std::sync::Arc<pipe::PipeBuffer>, is_read: bool },
        Socket {
            sendpipe: Option<std::sync::Arc<pipe::PipeBuffer>>,
            recvpipe: Option<std::sync::Arc<pipe::PipeBuffer>>,
        },
    }

    let mut bumps: Vec<RefBump> = Vec::new();

    if !is_thread {
        let parent_fds = fdtables::return_fdtable_copy(cage_id);
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
    }

    // --- Phase 2: fork, bump refcounts, THEN create child cage in fdtables.
    let ret = forward_syscall(SYS_CLONE, cage_id, &args, &arg_cages);

    if ret <= 0 {
        return ret;
    }

    let child_cage_id = ret as u64;

    if !is_thread {
        // Bump refcounts FIRST (child is spinning, can't interfere).
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

        // Copy parent's fdtable to child.  This bumps the (fdkind, underfd)
        // refcount in fdtables for each entry but does NOT fire our
        // registered close handler.  When this succeeds (the normal path)
        // the child cage has all the IPC entries the parent did.
        //
        // We deliberately do NOT re-install the IPC entries via
        // get_specific_virtual_fd on the success path: that call decrements
        // the OLD entry's refcount, which fires our intermediate close
        // handler — which calls decr_read_ref / decr_write_ref.  The
        // post-fork incr_*_ref bumps above expect those refs to land at
        // (parent_count + child_count) after the fork; the spurious
        // close-handler firings drag them back down by one per IPC entry,
        // leaving the read or write end one short.  The first subsequent
        // close in either parent or child then drives the ref to 0 →
        // eof latches / write returns EPIPE.  This was the root cause of
        // pipepong, test_pipe_large, test_pipe_pipeline, test_socketpair_fork,
        // test_popen_exec etc. all failing the same way.
        let copy_ok = fdtables::copy_fdtable_for_cage(cage_id, child_cage_id).is_ok();

        if !copy_ok {
            // Fallback for the rare case copy_fdtable_for_cage fails (e.g.
            // the child cage was somehow created by another path before
            // we got here).  Init empty and overlay IPC entries.  This
            // path WILL fire close handlers, but the entries it overwrites
            // are the empty ones from init_empty_cage so the firings are
            // no-ops on our refs.
            if !fdtables::check_cage_exists(child_cage_id) {
                fdtables::init_empty_cage(child_cage_id);
            }
            let parent_fds = fdtables::return_fdtable_copy(cage_id);
            for (fd, entry) in &parent_fds {
                if entry.fdkind == IPC_PIPE || entry.fdkind == socket::IPC_SOCKET {
                    let _ = fdtables::get_specific_virtual_fd(
                        child_cage_id,
                        *fd,
                        entry.fdkind,
                        entry.underfd,
                        entry.should_cloexec,
                        entry.perfdinfo,
                    );
                }
            }
        }

        // Propagate our registered syscall handlers to the new cage so
        // its read/write/close/etc. continue to flow through us instead
        // of crashing the runtime with "no handler for cage N syscall M".
        let grate_cage = getcageid();
        let _ = copy_handler_table_to_cage(grate_cage, child_cage_id);
    }


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

    // Init cage if missing (vfork-spawn path: posix_spawn child execs
    // before our parent fork_handler can copy_fdtable_for_cage).
    if !fdtables::check_cage_exists(cage_id) {
        fdtables::init_empty_cage(cage_id);
    }

    // Close cloexec fds.  Our registered fdtables close handlers
    // (ipc_pipe_close_handler / ipc_socket_close_handler) fire from
    // empty_fds_for_exec's _decrement_fdcount path, so pipe/socket
    // refcounts get decremented automatically.
    fdtables::empty_fds_for_exec(cage_id);

    // Reserve fds 0/1/2 (stdin/stdout/stderr) so that pipe() and socket()
    // never allocate them.  Without this, the first pipe() gets fds 0 and 1,
    // which hijacks stdout — every printf goes into a pipe instead of the
    // console.  fdkind=0 marks these as non-IPC (lookup_ipc_fd ignores them).
    //
    // Only reserve if not already occupied — popen() dup2's a pipe onto fd 0
    // before exec, and we must not overwrite that mapping.
    for fd in 0..3u64 {
        if fdtables::translate_virtual_fd(cage_id, fd).is_err() {
            let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
        }
    }

    let ret = forward_syscall(
        SYS_EXEC, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );
    ret
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

    // Only handle AF_UNIX and AF_INET (for potential loopback); everything
    // else just gets forwarded to the runtime with a fresh grate vfd wrapping
    // the runtime vfd.
    if domain != socket::AF_UNIX && domain != socket::AF_INET {
        let runtime_vfd = forward_syscall(SYS_SOCKET, cage_id, &args, &arg_cages);
        if runtime_vfd < 0 {
            return runtime_vfd;
        }
        return register_kernel_fd(cage_id, runtime_vfd, false, 0);
    }

    if domain == socket::AF_UNIX {
        // AF_UNIX: entirely ours. Create in registry, register in fdtables.
        // SOCK_CLOEXEC and SOCK_NONBLOCK live in the type arg, mapped to
        // O_CLOEXEC / O_NONBLOCK respectively (Linux convention).
        let cloexec = (socktype & O_CLOEXEC) != 0;
        let perfdinfo = (socktype as u64) & (O_NONBLOCK as u64);
        let socket_id = with_ipc(|s| s.sockets.create_socket(domain, socktype, 0));

        return match fdtables::get_unused_virtual_fd(
            cage_id, socket::IPC_SOCKET, socket_id, cloexec, perfdinfo,
        ) {
            Ok(fd) => fd as i32,
            Err(_) => {
                with_ipc(|s| s.sockets.remove(socket_id));
                EMFILE_NEG
            }
        };
    }

    // AF_INET: forward to runtime to get a real fd. We don't know yet
    // whether this will be loopback (127.0.0.1) or remote. We'll find
    // out at bind/connect time. If loopback, we close the runtime fd
    // and convert our entry to IPC_SOCKET in place at the same grate vfd.
    let runtime_vfd = forward_syscall(SYS_SOCKET, cage_id, &args, &arg_cages);
    if runtime_vfd < 0 {
        return runtime_vfd;
    }
    let grate_vfd = register_kernel_fd(cage_id, runtime_vfd, false, 0);
    if grate_vfd < 0 {
        return grate_vfd;
    }

    // Create a socket in our registry and track it as pending, keyed by grate vfd.
    with_ipc(|s| {
        let sid = s.sockets.create_socket(domain, socktype, 0);
        s.pending_inet.insert((cage_id, grate_vfd as u64), sid);
    });

    grate_vfd
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

    // Create connected pair with swapped pipes.
    let (sid1, sid2) = with_ipc(|s| {
        s.sockets.create_socketpair(domain, socktype, 0)
    });

    // SOCK_CLOEXEC / SOCK_NONBLOCK in the type arg map to O_CLOEXEC / O_NONBLOCK.
    let cloexec = (socktype & O_CLOEXEC) != 0;
    let perfdinfo = (socktype as u64) & (O_NONBLOCK as u64);

    // Allocate two fds.
    let fd1 = match fdtables::get_unused_virtual_fd(
        cage_id, socket::IPC_SOCKET, sid1, cloexec, perfdinfo,
    ) {
        Ok(fd) => fd as i32,
        Err(_) => return -24,
    };

    let fd2 = match fdtables::get_unused_virtual_fd(
        cage_id, socket::IPC_SOCKET, sid2, cloexec, perfdinfo,
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
        return forward_with_fd1(SYS_BIND, cage_id, args, arg_cages);
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

            // Create a placeholder file at the path on the actual
            // filesystem so subsequent chmod / unlink calls (postgres
            // does both) succeed.  Our actual socket I/O is in the
            // userspace pipe registry; this file just satisfies
            // filesystem-level operations on the bind path.
            //
            // The path lives in the cage memory at arg2+2 (sockaddr_un
            // starts with 2-byte sun_family, then sun_path).
            const O_WRONLY: u64 = 1;
            const O_CREAT: u64 = 0o100;
            const O_TRUNC: u64 = 0o1000;
            let placeholder_fd = forward_syscall(
                SYS_OPEN, cage_id,
                &[arg2 + 2, O_WRONLY | O_CREAT | O_TRUNC, 0o666, 0, 0, 0],
                &[arg2cage, arg2cage, arg2cage, 0, 0, 0],
            );
            if placeholder_fd >= 0 {
                let _ = forward_syscall(
                    SYS_CLOSE, cage_id,
                    &[placeholder_fd as u64, 0, 0, 0, 0, 0],
                    &[arg1cage, 0, 0, 0, 0, 0],
                );
            }

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
                // Take over: close the runtime fd backing this grate vfd and
                // overwrite our grate-side entry with IPC_SOCKET.
                if let Some(under) = translate_to_underfd(cage_id, fd) {
                    forward_syscall(SYS_CLOSE, cage_id,
                        &[under, 0, 0, 0, 0, 0], &[cage_id, 0, 0, 0, 0, 0]);
                }

                let addr_string = format!("127.0.0.1:{}", port);

                // Preserve cloexec / perfdinfo from the existing FDKIND_KERNEL entry
                // so SOCK_CLOEXEC / SOCK_NONBLOCK from the original socket() survive
                // the take-over.
                let (preserved_cloexec, preserved_perfdinfo) =
                    match fdtables::translate_virtual_fd(cage_id, fd) {
                        Ok(e) => (e.should_cloexec, e.perfdinfo),
                        Err(_) => (false, 0),
                    };

                // Overwrite grate vfd's FDKIND_KERNEL entry with IPC_SOCKET.
                let _ = fdtables::get_specific_virtual_fd(
                    cage_id, fd, socket::IPC_SOCKET, socket_id,
                    preserved_cloexec, preserved_perfdinfo,
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
                return forward_with_fd1(SYS_BIND, cage_id, args, arg_cages);
            }
        }
    }

    // Not ours — forward with translated fd.
    forward_with_fd1(SYS_BIND, cage_id, args, arg_cages)
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
        return forward_with_fd1(SYS_LISTEN, cage_id, args, arg_cages);
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
        return forward_with_fd1(SYS_CONNECT, cage_id, args, arg_cages);
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
            return forward_with_fd1(SYS_CONNECT, cage_id, args, arg_cages);
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
                // Take over: close runtime fd, overwrite grate entry as IPC_SOCKET.
                // Preserve cloexec / perfdinfo from the existing entry.
                let (preserved_cloexec, preserved_perfdinfo) =
                    match fdtables::translate_virtual_fd(cage_id, fd) {
                        Ok(e) => (e.should_cloexec, e.perfdinfo),
                        Err(_) => (false, 0),
                    };
                if let Some(under) = translate_to_underfd(cage_id, fd) {
                    forward_syscall(SYS_CLOSE, cage_id,
                        &[under, 0, 0, 0, 0, 0], &[cage_id, 0, 0, 0, 0, 0]);
                }
                let _ = fdtables::get_specific_virtual_fd(
                    cage_id, fd, socket::IPC_SOCKET, sid,
                    preserved_cloexec, preserved_perfdinfo,
                );
                with_ipc(|s| { s.pending_inet.remove(&(cage_id, fd)); });
                sid
            } else {
                // Not loopback — drop tracking, forward to kernel.
                with_ipc(|s| {
                    s.pending_inet.remove(&(cage_id, fd));
                    s.sockets.remove(sid);
                });
                return forward_with_fd1(SYS_CONNECT, cage_id, args, arg_cages);
            }
        } else {
            return forward_with_fd1(SYS_CONNECT, cage_id, args, arg_cages);
        }
    } else {
        return forward_with_fd1(SYS_CONNECT, cage_id, args, arg_cages);
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
        // Non-IPC accept: translate listening fd to runtime vfd, forward,
        // register the new runtime vfd as a fresh grate vfd.
        let under = match translate_to_underfd(cage_id, fd) {
            Some(u) => u,
            None => return EBADF_NEG,
        };
        let mut t = args;
        t[0] = under;
        let new_runtime_vfd = forward_syscall(SYS_ACCEPT, cage_id, &t, &arg_cages);
        if new_runtime_vfd < 0 {
            return new_runtime_vfd;
        }
        return register_kernel_fd(cage_id, new_runtime_vfd, false, 0);
    }

    let (socket_id, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return -88;
    }

    // Plain accept() does not set CLOEXEC on the new fd; only accept4 with
    // SOCK_CLOEXEC does (handled by accept4_handler).
    accept_ipc_inner(cage_id, socket_id, flags, /*cloexec=*/false, /*extra_perfdinfo=*/0)
}

/// Body of an IPC-socket accept.  Extracted so accept4_handler can pass
/// cloexec / SOCK_NONBLOCK from its flags arg without duplicating the
/// pending-connection wait loop.
fn accept_ipc_inner(
    cage_id: u64,
    socket_id: u64,
    listen_flags: i32,
    cloexec: bool,
    extra_perfdinfo: u64,
) -> i32 {
    let nonblocking = (listen_flags & O_NONBLOCK) != 0;

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
                cage_id, socket::IPC_SOCKET, new_socket_id, cloexec, extra_perfdinfo,
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
        return forward_with_fd1(SYS_SHUTDOWN, cage_id, args, arg_cages);
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
//  Pure-translation handlers
// =====================================================================
//
//  These handlers exist solely to translate the grate-side virt fd in
//  arg1 (or wherever the fd appears) to the runtime's virt fd before
//  forwarding to RawPOSIX.  Without these, RawPOSIX would receive a
//  grate vfd that means nothing in its own fdtable and return EBADF.
//
//  All of them are simple "translate fd, forward" wrappers; they don't
//  inspect the operation itself.

macro_rules! translate_fd1_handler {
    ($name:ident, $sysno:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
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
            forward_with_fd1($sysno, cage_id, args, arg_cages)
        }
    };
}

// epoll_ctl (arg1 = epfd, arg2 = op, arg3 = fd) — translate both fds.
pub extern "C" fn epoll_ctl_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // epfd
    arg2: u64, arg2cage: u64,    // op
    arg3: u64, arg3cage: u64,    // fd
    arg4: u64, arg4cage: u64,    // event
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    args[0] = match translate_to_underfd(cage_id, arg1) { Some(u) => u, None => return EBADF_NEG };
    args[2] = match translate_to_underfd(cage_id, arg3) { Some(u) => u, None => return EBADF_NEG };
    forward_syscall(SYS_EPOLL_CTL, cage_id, &args, &arg_cages)
}

/// epoll_create / epoll_create1: returns a fresh fd from the runtime —
/// register it as a fresh grate vfd.
pub extern "C" fn epoll_create_handler(
    _cageid: u64,
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
    let runtime_vfd = forward_syscall(SYS_EPOLL_CREATE, cage_id, &args, &arg_cages);
    if runtime_vfd < 0 { return runtime_vfd; }
    register_kernel_fd(cage_id, runtime_vfd, false, 0)
}

pub extern "C" fn epoll_create1_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // flags
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let runtime_vfd = forward_syscall(SYS_EPOLL_CREATE1, cage_id, &args, &arg_cages);
    if runtime_vfd < 0 { return runtime_vfd; }
    let cloexec = (arg1 as i32 & O_CLOEXEC) != 0;
    register_kernel_fd(cage_id, runtime_vfd, cloexec, 0)
}

/// ppoll (syscall 271): same shape as poll but with a timespec timeout
/// and a sigmask.  Same fd-translation logic as poll_handler.
pub extern "C" fn ppoll_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // pollfd *fds
    arg2: u64, arg2cage: u64,    // nfds
    arg3: u64, arg3cage: u64,    // timeout_ts *
    arg4: u64, arg4cage: u64,    // sigmask
    arg5: u64, arg5cage: u64,    // sigsetsize
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nfds = arg2 as usize;
    let this_cage = getcageid();

    if nfds == 0 || arg1 == 0 {
        let args = [arg1, arg2, arg3, arg4, arg5, arg6];
        let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
        return forward_syscall(SYS_PPOLL, cage_id, &args, &arg_cages);
    }

    let mut pollfds = vec![PollFd::default(); nfds];
    let bytes = (nfds * core::mem::size_of::<PollFd>()) as u64;
    let _ = copy_data_between_cages(
        this_cage, arg1cage, arg1, arg1cage,
        pollfds.as_mut_ptr() as u64, this_cage, bytes, 0,
    );

    let original_fds: Vec<i32> = pollfds.iter().map(|p| p.fd).collect();
    let mut ipc_revents: Vec<i16> = vec![0; nfds];
    let mut ipc_indices: Vec<usize> = Vec::new();
    let mut total_ready: i32 = 0;

    for (i, pfd) in pollfds.iter_mut().enumerate() {
        if pfd.fd < 0 {
            pfd.revents = 0;
            continue;
        }
        if let Some((underfd, fdkind, flags)) = lookup_ipc_fd(cage_id, pfd.fd as u64) {
            let revents = ipc_pipe_poll_state(underfd, fdkind, flags, pfd.events);
            ipc_revents[i] = revents;
            if revents != 0 { total_ready += 1; }
            ipc_indices.push(i);
            pfd.fd = -1;
        } else {
            match translate_to_underfd(cage_id, pfd.fd as u64) {
                Some(u) => pfd.fd = u as i32,
                None => pfd.fd = -1,
            }
        }
    }

    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        pollfds.as_ptr() as u64, this_cage, arg1, arg1cage, bytes, 0,
    );
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let kernel_ret = forward_syscall(SYS_PPOLL, cage_id, &args, &arg_cages);
    if kernel_ret < 0 && total_ready == 0 { return kernel_ret; }
    if kernel_ret > 0 { total_ready += kernel_ret; }

    let _ = copy_data_between_cages(
        this_cage, arg1cage, arg1, arg1cage,
        pollfds.as_mut_ptr() as u64, this_cage, bytes, 0,
    );
    for i in 0..nfds { pollfds[i].fd = original_fds[i]; }
    for i in &ipc_indices { pollfds[*i].revents = ipc_revents[*i]; }
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        pollfds.as_ptr() as u64, this_cage, arg1, arg1cage, bytes, 0,
    );

    total_ready
}

// File ops with fd in arg1
translate_fd1_handler!(lseek_handler,            SYS_LSEEK);
translate_fd1_handler!(epoll_wait_handler,       SYS_EPOLL_WAIT);
translate_fd1_handler!(ioctl_handler,            SYS_IOCTL);
translate_fd1_handler!(fstat_handler,            SYS_FSTAT);
translate_fd1_handler!(fsync_handler,            SYS_FSYNC);
translate_fd1_handler!(fdatasync_handler,        SYS_FDATASYNC);
translate_fd1_handler!(ftruncate_handler,        SYS_FTRUNCATE);
translate_fd1_handler!(getdents_handler,         SYS_GETDENTS);
translate_fd1_handler!(fstatfs_handler,          SYS_FSTATFS);
translate_fd1_handler!(fchdir_handler,           SYS_FCHDIR);
translate_fd1_handler!(fchmod_handler,           SYS_FCHMOD);
translate_fd1_handler!(flock_handler,            SYS_FLOCK);
translate_fd1_handler!(pread_handler,            SYS_PREAD);
translate_fd1_handler!(pwrite_handler,           SYS_PWRITE);
translate_fd1_handler!(readv_handler,            SYS_READV);
translate_fd1_handler!(writev_handler,           SYS_WRITEV);
translate_fd1_handler!(preadv_handler,           SYS_PREADV);
translate_fd1_handler!(pwritev_handler,          SYS_PWRITEV);
translate_fd1_handler!(sync_file_range_handler,  SYS_SYNC_FILE_RANGE);

// Socket ops with fd in arg1
translate_fd1_handler!(setsockopt_handler,       SYS_SETSOCKOPT);
translate_fd1_handler!(getsockopt_handler,       SYS_GETSOCKOPT);
translate_fd1_handler!(getsockname_handler,      SYS_GETSOCKNAME);
translate_fd1_handler!(getpeername_handler,      SYS_GETPEERNAME);
translate_fd1_handler!(sendto_handler,           SYS_SENDTO);
translate_fd1_handler!(recvfrom_handler,         SYS_RECVFROM);
translate_fd1_handler!(sendmsg_handler,          SYS_SENDMSG);
translate_fd1_handler!(recvmsg_handler,          SYS_RECVMSG);

/// accept4 (syscall 288): like accept but with flags.  IPC sockets get
/// handled in accept_handler logic; for non-IPC sockets we translate +
/// register a fresh grate vfd just like accept.
pub extern "C" fn accept4_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // listening fd
    arg2: u64, arg2cage: u64,    // addr
    arg3: u64, arg3cage: u64,    // addrlen
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if let Some((socket_id, fdkind, listen_flags)) = info {
        if fdkind != socket::IPC_SOCKET {
            return -88;
        }
        // SOCK_CLOEXEC and SOCK_NONBLOCK are in arg4 (Linux convention:
        // SOCK_CLOEXEC == O_CLOEXEC, SOCK_NONBLOCK == O_NONBLOCK).
        let cloexec = (arg4 as i32 & O_CLOEXEC) != 0;
        let extra_perfdinfo = (arg4) & (O_NONBLOCK as u64);
        return accept_ipc_inner(cage_id, socket_id, listen_flags, cloexec, extra_perfdinfo);
    }

    let under = match translate_to_underfd(cage_id, fd) {
        Some(u) => u,
        None => return EBADF_NEG,
    };
    let mut t = args;
    t[0] = under;
    let new_runtime_vfd = forward_syscall(SYS_ACCEPT4, cage_id, &t, &arg_cages);
    if new_runtime_vfd < 0 {
        return new_runtime_vfd;
    }
    let cloexec = (arg4 as i32 & O_CLOEXEC) != 0;
    register_kernel_fd(cage_id, new_runtime_vfd, cloexec, 0)
}

/// mmap (syscall 9): the fd is in arg5; translate it.  Pass through
/// when the mapping is anonymous (MAP_ANON set in arg4) — fd is unused
/// in that case and may be -1.
pub extern "C" fn mmap_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // addr
    arg2: u64, arg2cage: u64,    // length
    arg3: u64, arg3cage: u64,    // prot
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,    // fd
    arg6: u64, arg6cage: u64,    // offset
) -> i32 {
    let cage_id = arg1cage;
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let is_anon = (arg4 as i32) & grate_rs::constants::mman::MAP_ANON != 0;
    if !is_anon {
        match translate_to_underfd(cage_id, arg5) {
            Some(u) => args[4] = u,
            None => return EBADF_NEG,
        }
    }
    forward_syscall(SYS_MMAP, cage_id, &args, &arg_cages)
}
