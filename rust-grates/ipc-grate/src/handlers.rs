//! Syscall handlers for the IPC grate.

use std::collections::HashMap;

use grate_rs::constants::*;
use grate_rs::{copy_data_between_cages, copy_handler_table_to_cage, getcageid, is_thread_clone};

use crate::helpers::forward_syscall;
use crate::ipc::{self, *};
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
const ENOTSOCK_NEG: i32 = -88;
const ENOTCONN_NEG: i32 = -107;
const ENOPROTOOPT_NEG: i32 = -92;

/// AT_FDCWD is the special "current working directory" sentinel for the
/// *at family of syscalls; it must NOT be translated.
const AT_FDCWD: i64 = -100;

/// Translation flag for the cageid argument in `make_threei_call`.  When
/// the MSB of a per-arg cageid is set, glibc's `TRANSLATE_ARG_TO_HOST`
/// macro converts the corresponding arg from a wasm32 guest offset to a
/// host pointer (`__lind_base + uaddr`) before passing it to the host
/// trampoline.  Use this when forwarding a buffer that lives in our own
/// wasm linear memory (e.g. a `Vec` we own) — without it, the host
/// receives a tiny wasm offset and segfaults dereferencing it.
const ARG_TRANSLATE_FLAG: u64 = 1u64 << 63;

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

/// Host-layout `struct msghdr` (Linux x86_64), 56 bytes.  glibc's
/// `sendmsg`/`recvmsg` wrappers translate guest pointers to host
/// addresses and pack them via the split-pointer trick into a
/// wasm32-padded msghdr that, when read as 56 raw bytes, exactly
/// matches this layout.  We copy those bytes from the user cage and
/// reinterpret as `HostMsghdr` to read the iov pointer + count.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct HostMsghdr {
    msg_name:        u64,
    msg_namelen:     u32,
    _pad_namelen:    u32,
    msg_iov:         u64,
    msg_iovlen:      u64,
    msg_control:     u64,
    msg_controllen:  u64,
    msg_flags:       i32,
    _pad_flags:      u32,
}

/// Host-layout `struct iovec` (Linux x86_64), 16 bytes.  Same
/// reasoning as `HostMsghdr` — glibc packs split host pointers so the
/// raw 16-byte representation matches this layout.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct HostIovec {
    iov_base: u64,
    iov_len:  u64,
}

/// Defensive cap on iov entries we'll process per sendmsg/recvmsg.
/// Linux's UIO_MAXIOV is 1024; matching it keeps malicious or
/// uninitialized iovlen values from causing huge allocations.
const MAX_IOV: usize = 1024;

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
    // Drop any IPC-epoll target maps owned by this cage.
    with_ipc(|s| {
        s.epoll_targets.retain(|(c, _), _| *c != cage_id);
    });

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
    // Drop any IPC-epoll target maps owned by this cage.
    with_ipc(|s| {
        s.epoll_targets.retain(|(c, _), _| *c != cage_id);
    });

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
        socket::IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.recvpipe.clone())
        }),
        _ => return -9,
    };

    let pipe = match pipe {
        Some(p) => p,
        None => return -9,
    };

    if count == 0 || arg2 == 0 {
        return 0;
    }
    // Single-copy fast path: ringbuf storage is filled directly from
    // the user cage via copy_data_between_cages (host-side memcpy),
    // skipping the staging vec the previous design needed.
    pipe.read_to_cage(arg2cage, arg2, count, nonblocking, this_cage)
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
        socket::IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.sendpipe.clone())
        }),
        _ => return -9,
    };

    let pipe = match pipe {
        Some(p) => p,
        None => return -9,
    };

    if count == 0 || arg2 == 0 {
        return 0;
    }
    // Single-copy fast path: copy_data_between_cages writes directly
    // into ringbuf storage; no grate-side staging vec.
    pipe.write_from_cage(arg2cage, arg2, count, nonblocking, this_cage)
}

/// Compute the revents bits for an IPC fd given the requested events.
/// Reads the pipe state directly via has_data / write_refs / read_refs.
fn ipc_pipe_poll_state(underfd: u64, fdkind: u32, flags: i32, requested: i16) -> i16 {
    let mut revents: i16 = 0;

    // Listening IPC sockets have no recv/send pipes — those are minted
    // at accept() time.  Readability on a listen fd means "there is a
    // pending connection queued for accept()".  Without this special
    // case we'd fall through to the recvpipe-is-None branch and return
    // POLLNVAL, so any select/poll(POLLIN) on a listen fd would never
    // report readability.  postmaster-style servers (postgres, anything
    // that selects before accepting) would then never call accept() and
    // clients would hang.
    if fdkind == socket::IPC_SOCKET {
        let listen_pending = with_ipc(|s| {
            let sk = s.sockets.get(underfd)?;
            if sk.state != socket::ConnState::Listening { return None; }
            let addr = sk.local_addr.clone()?;
            let has_pending = s.sockets.pending_connections
                .get(&addr)
                .map(|q| !q.is_empty())
                .unwrap_or(false);
            Some(has_pending)
        });
        if let Some(has_pending) = listen_pending {
            if (requested & POLLIN) != 0 && has_pending {
                revents |= POLLIN;
            }
            return revents;
        }
    }

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

/// Re-classify the IPC entries of a `pollfds` slice against current
/// pipe / connection state.  Used by poll_handler / ppoll_handler when
/// they're waiting on IPC-only fds: instead of forwarding all-negative
/// fds to the kernel (which would sleep for the full timeout without
/// noticing IPC-side wakeups), we sample the IPC state in a loop and
/// catch transitions like "client connected to a listening UDS".
///
/// Pollfds are walked at the indices listed in `ipc_indices`; original
/// fd values are read from `original_fds` (since `pollfds[i].fd` was
/// already flipped negative for the kernel).  Returns the number of
/// IPC entries with non-zero revents this iteration.
fn reclassify_ipc_pollfds(
    cage_id: u64,
    pollfds: &[PollFd],
    original_fds: &[i32],
    ipc_indices: &[usize],
    ipc_revents: &mut [i16],
) -> i32 {
    let mut ready = 0i32;
    for &i in ipc_indices {
        let fd = original_fds[i] as u64;
        let events = pollfds[i].events;
        if let Some((underfd, fdkind, flags)) = lookup_ipc_fd(cage_id, fd) {
            let revents = ipc_pipe_poll_state(underfd, fdkind, flags, events);
            ipc_revents[i] = revents;
            if revents != 0 {
                ready += 1;
            }
        } else {
            ipc_revents[i] = 0;
        }
    }
    ready
}

/// EINTR in negative-errno form.
const EINTR_NEG: i32 = -4;

/// Sleep ~1ms in a way that's interruptible by signals queued for the
/// calling user cage.  Returns `true` if the sleep was interrupted by
/// a signal (caller should bail with EINTR so the cage's signal
/// handler can run on the way out).
///
/// Mechanism: `libc::nanosleep` forwards to RawPOSIX's
/// `nanosleep_time64_syscall` which calls the host's `clock_nanosleep`.
/// `cage::signal::lind_send_signal` interrupts blocking host syscalls
/// on the user cage's main thread by sending SIGUSR2 via `tkill`; the
/// no-op handler causes `clock_nanosleep` to return -EINTR.  Since
/// the grate is invoked on the user cage's main thread (the thread
/// that issued the original syscall), *our* nanosleep is the target —
/// no extra primitive needed.
///
/// Without this, the grate's IPC wait loops are signal-deaf for the
/// entire timeout: while we spin, the cage is parked in our handler
/// and its own user-code path that would observe the epoch flip can't
/// run.  postgres' WaitLatch + SetLatch self-pipe pattern wedges as a
/// direct result (postmaster hangs on ProcSignalBarrier waiting for a
/// SIGUSR1 handler that never gets to run).
fn ipc_wait_nap_signal_aware() -> bool {
    unsafe {
        // Request 50µs.  Was 1µs on the theory that the kernel rounds
        // up to timer granularity anyway, so smaller is free.  That
        // broke once the IPC fast-path made the per-iteration work
        // cheap — `self_pipe_signal.c` regressed because the cage's
        // signal-handler dispatch didn't get a chance to run between
        // iterations.  10µs wasn't enough; 50µs reliably gives the
        // dispatch room without measurable throughput impact on
        // pipe-style waits.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000 };
        // For a valid timespec the only error nanosleep can return is
        // EINTR, so a negative return is conclusive.
        libc::nanosleep(&ts, std::ptr::null_mut()) < 0
    }
}

/// Local poll-loop for IPC-only poll/ppoll calls (i.e. no kernel fds).
/// Sleeps in 1ms chunks, re-classifying IPC entries each iteration,
/// until either a fd becomes ready, the calling cage has a signal
/// pending, or `timeout_ms` elapses.  Negative `timeout_ms` blocks
/// forever (matches poll(2) semantics).  Returns:
///   > 0  number of ready IPC entries
///   0    timeout
///   -EINTR  cage has a signal pending — handler should return so the
///           cage's signal handler can run on the way out
fn ipc_only_poll_wait(
    cage_id: u64,
    pollfds: &[PollFd],
    original_fds: &[i32],
    ipc_indices: &[usize],
    ipc_revents: &mut [i16],
    timeout_ms: i32,
) -> i32 {
    // Each ipc_wait_nap_signal_aware() iteration sleeps ~50µs, so the
    // total wait is ~iters * 50µs.  Convert timeout (ms) to an
    // iteration budget instead of carrying an `Instant` around — both
    // because the per-iteration `Instant::now()` call has measurable
    // overhead vs. the nap, and because the iteration-count form makes
    // the no-timeout branch (`timeout_ms < 0` → loop forever) fall out
    // as a single `if` on the budget instead of being an extra branch
    // every iteration.
    //
    // 1ms ≈ 20 iterations of 50µs.  Use saturating math so a huge
    // timeout doesn't overflow.
    const ITERS_PER_MS: u64 = 20;
    let mut remaining: Option<u64> = if timeout_ms < 0 {
        None
    } else {
        Some((timeout_ms as u64).saturating_mul(ITERS_PER_MS))
    };

    loop {
        let ready = reclassify_ipc_pollfds(
            cage_id, pollfds, original_fds, ipc_indices, ipc_revents,
        );
        if ready > 0 {
            return ready;
        }
        if let Some(r) = remaining {
            if r == 0 {
                return 0;
            }
            remaining = Some(r - 1);
        }
        if ipc_wait_nap_signal_aware() {
            return EINTR_NEG;
        }
    }
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

    let has_kernel_fd = pollfds.iter().any(|p| p.fd >= 0);

    if has_kernel_fd {
        // Mixed (or kernel-only) case: forward SYS_POLL with a pointer
        // into the grate's own pollfds Vec tagged with
        // `this_cage | ARG_TRANSLATE_FLAG`.  The MSB tells glibc's
        // `make_threei_call` wrapper to convert the wasm32 offset to a
        // host pointer before it reaches RawPOSIX.  Without the flag
        // the host dereferences a tiny wasm offset and segfaults.  This
        // avoids two `copy_data_between_cages` round-trips per poll.
        // If we already have IPC entries ready, do a non-blocking
        // kernel check (timeout=0) so we return promptly.
        let kernel_timeout = if total_ready > 0 { 0i32 } else { arg3 as i32 };
        let args = [
            pollfds.as_mut_ptr() as u64,
            arg2,
            kernel_timeout as u64,
            arg4,
            arg5,
            arg6,
        ];
        let arg_cages = [
            this_cage | ARG_TRANSLATE_FLAG,
            arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,
        ];
        let kernel_ret = forward_syscall(SYS_POLL, cage_id, &args, &arg_cages);
        if kernel_ret < 0 {
            return kernel_ret;
        }
        total_ready += kernel_ret;
    } else if total_ready == 0 {
        // IPC-only and nothing ready: do a local poll-loop instead of
        // forwarding to the kernel.  RawPOSIX's poll with all-negative
        // fds would sleep for the full timeout without ever noticing
        // IPC-side wakeups (e.g. a client connecting to a listening
        // UDS), so a server polling its listen fd would never wake.
        total_ready = ipc_only_poll_wait(
            cage_id, &pollfds, &original_fds, &ipc_indices,
            &mut ipc_revents, arg3 as i32,
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
    // Tracks whether any kernel-backed fd was added.  We can't infer this
    // from `max_under` alone since a kernel fd with underfd 0 leaves it
    // at the initial 0.  Without this flag, an all-IPC select would
    // forward to RawPOSIX with empty kernel fd_sets — `prepare_bitmasks_for_select`
    // returns an error in that case, surfacing as EINVAL.
    let mut have_kernel_fds = false;

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
            have_kernel_fds = true;
        }
    }

    // No kernel fds at all: skip the kernel forward and wait locally.
    // RawPOSIX's select_syscall would reject empty fd_sets with EINVAL
    // via `prepare_bitmasks_for_select`, so we can't just hand the
    // timeout off to the kernel.  Instead, if no IPC fds are ready
    // yet, poll-loop on the IPC state until either one becomes ready
    // or the caller's timeout elapses.  Without this loop a server
    // that select()s on a UDS listen fd before the client connect()s
    // would return 0 immediately, never see the connection, and hang.
    if !have_kernel_fds {
        if ipc_ready == 0 {
            // Read the user's timeval (8-byte tv_sec + 4-byte tv_usec
            // + 4 bytes padding on wasm32; we read the full 16 bytes
            // and mask tv_usec).  NULL pointer means block forever.
            //
            // Convert the timeout into an iteration budget against our
            // ~50µs nap, mirroring `ipc_only_poll_wait`.  Avoids the
            // per-iteration `Instant::now()` overhead and keeps the
            // no-timeout (block-forever) branch as a single `if` on
            // the budget.
            let mut iters_remaining: Option<u64> = if arg5 == 0 {
                None
            } else {
                let mut tv = [0u8; 16];
                let _ = copy_data_between_cages(
                    this_cage, arg5cage,
                    arg5, arg5cage,
                    tv.as_mut_ptr() as u64, this_cage,
                    16, 0,
                );
                let secs  = u64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
                let usecs = u32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]) as u64;
                // 50µs per iteration → 20 iters/ms → 20_000 iters/sec.
                let total_us = secs.saturating_mul(1_000_000).saturating_add(usecs);
                Some(total_us.saturating_div(50))
            };

            loop {
                // Re-classify IPC fds against current pipe / connection
                // state.  read_set / write_set / except_set are
                // already populated from the user; only the IPC bits
                // change as connections / data arrive.
                ipc_read = [0; FD_SET_WORDS];
                ipc_write = [0; FD_SET_WORDS];
                ipc_except = [0; FD_SET_WORDS];
                ipc_ready = 0;
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
                    }
                }
                if ipc_ready > 0 { break; }
                if let Some(r) = iters_remaining {
                    if r == 0 { break; }
                    iters_remaining = Some(r - 1);
                }
                if ipc_wait_nap_signal_aware() {
                    return EINTR_NEG;
                }
            }
        }

        if have_r {
            let _ = copy_data_between_cages(
                this_cage, arg1cage,
                ipc_read.as_ptr() as u64, this_cage,
                arg2, arg1cage,
                FD_SET_BYTES as u64, 0,
            );
        }
        if have_w {
            let _ = copy_data_between_cages(
                this_cage, arg1cage,
                ipc_write.as_ptr() as u64, this_cage,
                arg3, arg1cage,
                FD_SET_BYTES as u64, 0,
            );
        }
        if have_e {
            let _ = copy_data_between_cages(
                this_cage, arg1cage,
                ipc_except.as_ptr() as u64, this_cage,
                arg4, arg1cage,
                FD_SET_BYTES as u64, 0,
            );
        }
        return ipc_ready;
    }

    // Forward SYS_SELECT with pointers into the grate's own k_* arrays
    // tagged with `this_cage | ARG_TRANSLATE_FLAG`.  The MSB tells
    // glibc's `make_threei_call` wrapper to convert each wasm32 offset
    // to a host pointer before it reaches RawPOSIX (without it, the
    // host dereferences a tiny wasm offset and segfaults).  RawPOSIX
    // reads the input bitmaps in place and writes the result back into
    // the same arrays — this saves 6 cross-cage copies (3 input
    // pre-call and 3 result post-call).
    //
    // Pass 0/this_cage for any set that's NULL — the kernel ignores
    // that set, but we keep the position so the cage tags match.
    let runtime_nfds = if max_under > 0 { (max_under + 1) as u64 } else { arg1 };
    let r_ptr = if have_r { k_read.as_mut_ptr() as u64 } else { 0 };
    let w_ptr = if have_w { k_write.as_mut_ptr() as u64 } else { 0 };
    let e_ptr = if have_e { k_except.as_mut_ptr() as u64 } else { 0 };
    let args = [runtime_nfds, r_ptr, w_ptr, e_ptr, arg5, arg6];
    let translated_cage = this_cage | ARG_TRANSLATE_FLAG;
    let arg_cages = [
        arg1cage,
        translated_cage, translated_cage, translated_cage,
        arg5cage, arg6cage,
    ];
    let kernel_ret = forward_syscall(SYS_SELECT, cage_id, &args, &arg_cages);
    if kernel_ret < 0 {
        return kernel_ret;
    }

    // k_read / k_write / k_except now hold the kernel's results
    // (RawPOSIX wrote in place).  Translate runtime vfds → grate vfds,
    // OR in our IPC bits, and write the final user-visible result back.
    let mut out_r: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut out_w: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];
    let mut out_e: [u32; FD_SET_WORDS] = [0; FD_SET_WORDS];

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
    accept_ipc_inner(
        cage_id, socket_id, flags, /*cloexec=*/false, /*extra_perfdinfo=*/0,
        arg2, arg2cage, arg3, _arg3cage,
    )
}

/// Body of an IPC-socket accept.  Extracted so accept4_handler can pass
/// cloexec / SOCK_NONBLOCK from its flags arg without duplicating the
/// pending-connection wait loop.
///
/// `addr_arg` / `addr_cage` and `addrlen_arg` / `addrlen_cage` are the
/// caller's `accept(fd, &addr, &addrlen)` out-params.  They may both be
/// NULL, in which case we skip the peer-address writeback.  When set,
/// we synthesise a sockaddr from the new socket's domain + remote_addr
/// (set when the connection was queued by connect()) and copy it back,
/// so callers like postgres that read raddr after accept() see a real
/// sa_family instead of a zero-initialised buffer.
fn accept_ipc_inner(
    cage_id: u64,
    socket_id: u64,
    listen_flags: i32,
    cloexec: bool,
    extra_perfdinfo: u64,
    addr_arg: u64, addr_cage: u64,
    addrlen_arg: u64, addrlen_cage: u64,
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
            let new_fd = match fdtables::get_unused_virtual_fd(
                cage_id, socket::IPC_SOCKET, new_socket_id, cloexec, extra_perfdinfo,
            ) {
                Ok(new_fd) => new_fd as i32,
                Err(_) => {
                    with_ipc(|s| s.sockets.remove(new_socket_id));
                    return -24; // EMFILE
                }
            };

            // Write the peer address back to the user's addr / addrlen
            // out-params, mirroring kernel accept().  NULL pointers are
            // legal (caller doesn't want the address) — skip in that case.
            if addr_arg != 0 && addrlen_arg != 0 {
                let (domain, remote_addr) = with_ipc(|s| {
                    s.sockets.get(new_socket_id)
                        .map(|sk| (sk.domain, sk.remote_addr.clone()))
                        .unwrap_or((0, None))
                });
                let (sock_buf, sock_len) = build_ipc_sockaddr(domain, &remote_addr);
                let _ = ipc_writeback_sockaddr(
                    &sock_buf, sock_len,
                    addr_arg, addr_cage,
                    addrlen_arg, addrlen_cage,
                    getcageid(),
                );
            }

            return new_fd;
        }

        if nonblocking {
            return -11; // EAGAIN
        }

        if ipc_wait_nap_signal_aware() {
            return EINTR_NEG;
        }
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
// epoll constants (Linux x86_64).
const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

const EPOLLIN:  u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;

/// Register a runtime-allocated epoll vfd as IPC_EPOLL on the grate side.
/// We use a distinct fdkind (instead of FDKIND_KERNEL) so that close on
/// this fd fires `ipc_epoll_close_handler`, which cleans up our per-epfd
/// IPC target map.
fn register_ipc_epoll_fd(cage: u64, runtime_vfd: i32, cloexec: bool) -> i32 {
    match fdtables::get_unused_virtual_fd(cage, IPC_EPOLL, runtime_vfd as u64, cloexec, 0) {
        Ok(grate_vfd) => {
            // Initialize an empty IPC-target map for this (cage, grate_epfd).
            with_ipc(|s| {
                s.epoll_targets.insert((cage, grate_vfd), HashMap::new());
            });
            grate_vfd as i32
        }
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

/// Close handler for IPC_EPOLL entries — drops our per-(cage, grate_epfd)
/// target map.  fdtables fires this on close_virtualfd, exec cleanup, and
/// cage exit, so leftover state never lingers.
pub fn ipc_epoll_close_handler(
    entry: fdtables::FDTableEntry,
    _count: u64,
) -> Result<(), i32> {
    // We don't have the cage_id directly, but the close handler fires for
    // every cage that had an entry pointing at this underfd.  Walk all
    // tracked epfds and prune the one whose underfd matches; this keeps
    // us correct without plumbing cage_id through fdtables.
    with_ipc(|s| {
        s.epoll_targets.retain(|_key, _targets| {
            // We can't compare against entry directly here without the
            // cage_id; leave entries for other cages alone.  The entry
            // we want to drop is the one whose underfd matches AND the
            // grate_epfd that fdtables just removed.  fdtables doesn't
            // give us the grate_vfd in the close handler, so we tolerate
            // a small leak of stale entries.  On cage exit
            // (remove_cage_from_fdtable), exit_handler clears the cage's
            // epoll_targets in bulk.
            let _ = entry;
            true
        });
    });
    Ok(())
}

/// epoll_create / epoll_create1: returns a fresh fd from the runtime —
/// register it as a grate IPC_EPOLL vfd and seed our target map.
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
    register_ipc_epoll_fd(cage_id, runtime_vfd, false)
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
    register_ipc_epoll_fd(cage_id, runtime_vfd, cloexec)
}

/// epoll_ctl: route IPC fds into our per-epfd target map; forward kernel
/// fds to the runtime epoll.
pub extern "C" fn epoll_ctl_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // epfd
    arg2: u64, arg2cage: u64,    // op
    arg3: u64, arg3cage: u64,    // fd
    arg4: u64, arg4cage: u64,    // event*
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let grate_epfd = arg1;
    let op = arg2 as i32;
    let target_fd = arg3;
    let this_cage = getcageid();

    // Verify this is a grate-managed epoll fd.
    let epfd_entry = match fdtables::translate_virtual_fd(cage_id, grate_epfd) {
        Ok(e) if e.fdkind == IPC_EPOLL => e,
        Ok(_) => return EBADF_NEG,    // not an epoll fd
        Err(_) => return EBADF_NEG,
    };
    let runtime_epfd = epfd_entry.underfd;

    // Is the target an IPC fd?  If so, manage in our state map.
    let target_is_ipc = lookup_ipc_fd(cage_id, target_fd).is_some();

    if target_is_ipc {
        match op {
            EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
                // Read the user's epoll_event from cage memory.
                if arg4 == 0 {
                    return -22; // EINVAL
                }
                let mut ev = ipc::EpollEvent::default();
                let _ = copy_data_between_cages(
                    this_cage, arg1cage,
                    arg4, arg4cage,
                    &mut ev as *mut _ as u64, this_cage,
                    core::mem::size_of::<ipc::EpollEvent>() as u64, 0,
                );
                with_ipc(|s| {
                    let entry = s.epoll_targets
                        .entry((cage_id, grate_epfd))
                        .or_insert_with(HashMap::new);
                    if op == EPOLL_CTL_ADD && entry.contains_key(&target_fd) {
                        return -17; // EEXIST
                    }
                    if op == EPOLL_CTL_MOD && !entry.contains_key(&target_fd) {
                        return -2;  // ENOENT
                    }
                    entry.insert(target_fd, ev);
                    0
                })
            }
            EPOLL_CTL_DEL => {
                with_ipc(|s| {
                    if let Some(entry) = s.epoll_targets.get_mut(&(cage_id, grate_epfd)) {
                        if entry.remove(&target_fd).is_some() {
                            return 0;
                        }
                    }
                    -2 // ENOENT
                })
            }
            _ => -22, // EINVAL
        }
    } else {
        // Kernel fd: translate both arg1 and arg3 to underfds, forward.
        let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
        let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
        args[0] = runtime_epfd;
        args[2] = match translate_to_underfd(cage_id, target_fd) {
            Some(u) => u,
            None => return EBADF_NEG,
        };
        forward_syscall(SYS_EPOLL_CTL, cage_id, &args, &arg_cages)
    }
}

/// epoll_wait: check IPC fds first, fill the user's events array with any
/// that are ready, then forward to the runtime epoll for the remaining
/// slots.  Returns the combined count.
pub extern "C" fn epoll_wait_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // epfd
    arg2: u64, arg2cage: u64,    // events*
    arg3: u64, arg3cage: u64,    // maxevents
    arg4: u64, arg4cage: u64,    // timeout (ms)
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let grate_epfd = arg1;
    let maxevents = arg3 as i32;
    let user_timeout = arg4 as i32;
    let this_cage = getcageid();

    if maxevents <= 0 {
        return -22; // EINVAL
    }

    // Verify this is a grate-managed epoll fd.
    let epfd_entry = match fdtables::translate_virtual_fd(cage_id, grate_epfd) {
        Ok(e) if e.fdkind == IPC_EPOLL => e,
        Ok(_) => return EBADF_NEG,
        Err(_) => return EBADF_NEG,
    };
    let runtime_epfd = epfd_entry.underfd;

    // Snapshot the IPC targets for this epfd.  We need to copy them out
    // of the lock so we don't hold IPC_STATE while we evaluate readiness
    // (which doesn't strictly need it but keeps the critical section short).
    let ipc_entries: Vec<(u64, ipc::EpollEvent)> = with_ipc(|s| {
        s.epoll_targets.get(&(cage_id, grate_epfd))
            .map(|m| m.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default()
    });

    // Compute IPC readiness up to maxevents.  Build into a grate-local Vec.
    let mut ready: Vec<ipc::EpollEvent> = Vec::with_capacity(maxevents as usize);
    for (ipc_fd, ev) in &ipc_entries {
        if ready.len() >= maxevents as usize { break; }
        let info = match lookup_ipc_fd(cage_id, *ipc_fd) {
            Some(t) => t,
            None => continue,  // fd was closed since being added
        };
        let (underfd, fdkind, flags) = info;
        // Translate epoll event mask to a poll-style request, reuse the
        // pipe poll-state helper, then translate the result back.
        let mut requested: i16 = 0;
        if (ev.events & EPOLLIN)  != 0 { requested |= POLLIN;  }
        if (ev.events & EPOLLOUT) != 0 { requested |= POLLOUT; }
        let revents = ipc_pipe_poll_state(underfd, fdkind, flags, requested);
        let mut out_events: u32 = 0;
        if revents & POLLIN  != 0 { out_events |= EPOLLIN;  }
        if revents & POLLOUT != 0 { out_events |= EPOLLOUT; }
        if revents & POLLERR != 0 { out_events |= EPOLLERR; }
        if revents & POLLHUP != 0 { out_events |= EPOLLHUP; }
        // Mask against what the user requested (plus always-on EPOLLERR/HUP).
        let reported = out_events & (ev.events | EPOLLERR | EPOLLHUP);
        if reported != 0 {
            ready.push(ipc::EpollEvent {
                events: reported,
                data: ev.data,
            });
        }
    }
    let ipc_count = ready.len() as i32;

    // Decide kernel timeout: if any IPC fds are ready, do a non-blocking
    // kernel check so we return promptly.  Otherwise honor the caller's
    // timeout.
    let kernel_timeout = if ipc_count > 0 { 0i32 } else { user_timeout };
    let kernel_max = maxevents - ipc_count;

    let mut kernel_count = 0i32;
    if kernel_max > 0 {
        // Forward to the runtime with a grate-local slice tagged
        // `this_cage | ARG_TRANSLATE_FLAG` for the remaining slots.  The
        // MSB tells glibc's `make_threei_call` wrapper to convert the
        // wasm32 offset to a host pointer before it reaches RawPOSIX —
        // without it, the host dereferences a tiny wasm offset and
        // segfaults.  RawPOSIX writes results in place.
        let kernel_buf = vec![ipc::EpollEvent::default(); kernel_max as usize];
        let args = [
            runtime_epfd,
            kernel_buf.as_ptr() as u64,
            kernel_max as u64,
            kernel_timeout as u64,
            arg5,
            arg6,
        ];
        let arg_cages = [
            arg1cage,
            this_cage | ARG_TRANSLATE_FLAG,
            arg3cage, arg4cage, arg5cage, arg6cage,
        ];
        kernel_count = forward_syscall(SYS_EPOLL_WAIT, cage_id, &args, &arg_cages);
        if kernel_count < 0 && ipc_count == 0 {
            return kernel_count;
        }
        if kernel_count < 0 { kernel_count = 0; }
        // Append kernel-reported events into our merged buffer.
        for i in 0..(kernel_count as usize) {
            ready.push(kernel_buf[i]);
        }
    }

    // Write the merged events to the user's buffer.
    let total = ready.len();
    if total > 0 && arg2 != 0 {
        let bytes = (total * core::mem::size_of::<ipc::EpollEvent>()) as u64;
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            ready.as_ptr() as u64, this_cage,
            arg2, arg2cage,
            bytes, 0,
        );
    }
    total as i32
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
    let mut has_kernel_fd = false;

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
                Some(u) => { pfd.fd = u as i32; has_kernel_fd = true; }
                None => pfd.fd = -1,
            }
        }
    }

    if has_kernel_fd {
        // Mixed (or kernel-only): forward SYS_PPOLL with a pointer into
        // the grate's own pollfds Vec tagged with
        // `this_cage | ARG_TRANSLATE_FLAG`.  The MSB tells glibc's
        // `make_threei_call` wrapper to convert the wasm32 offset to a
        // host pointer before it reaches RawPOSIX.  RawPOSIX reads and
        // writes the buffer in place, saving two cross-cage copies.
        let args = [
            pollfds.as_mut_ptr() as u64,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6,
        ];
        let arg_cages = [
            this_cage | ARG_TRANSLATE_FLAG,
            arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,
        ];
        let kernel_ret = forward_syscall(SYS_PPOLL, cage_id, &args, &arg_cages);
        if kernel_ret < 0 && total_ready == 0 { return kernel_ret; }
        if kernel_ret > 0 { total_ready += kernel_ret; }
    } else if total_ready == 0 {
        // IPC-only and nothing ready: local poll-loop on IPC state.
        // Forwarding to RawPOSIX with all-negative fds would sleep for
        // the full timeout without noticing IPC-side wakeups (e.g.
        // a connect() to a listening UDS in another cage).  glibc has
        // already converted the timespec to int ms in arg3 (-1 for
        // NULL timeout = block forever).
        total_ready = ipc_only_poll_wait(
            cage_id, &pollfds, &original_fds, &ipc_indices,
            &mut ipc_revents, arg3 as i32,
        );
    }

    // Restore original (grate-side) fd values for ALL entries and overlay
    // our IPC-computed revents on the IPC entries.  Then write the final
    // pollfd[] back to the cage so the user sees its own grate vfds.
    for i in 0..nfds { pollfds[i].fd = original_fds[i]; }
    for i in &ipc_indices { pollfds[*i].revents = ipc_revents[*i]; }
    let _ = copy_data_between_cages(
        this_cage, arg1cage,
        pollfds.as_ptr() as u64, this_cage, arg1, arg1cage, bytes, 0,
    );

    total_ready
}

// File ops with fd in arg1
// File ops on a fd: kernel-fd path translates + forwards.  IPC pipes
// and sockets are unsupported here, so we either reject (ESPIPE) or
// stub via the IPC-aware handlers defined later in this file.
translate_fd1_handler!(fsync_handler,            SYS_FSYNC);
translate_fd1_handler!(fdatasync_handler,        SYS_FDATASYNC);
translate_fd1_handler!(ftruncate_handler,        SYS_FTRUNCATE);
translate_fd1_handler!(getdents_handler,         SYS_GETDENTS);
translate_fd1_handler!(fstatfs_handler,          SYS_FSTATFS);
translate_fd1_handler!(fchdir_handler,           SYS_FCHDIR);
translate_fd1_handler!(fchmod_handler,           SYS_FCHMOD);
translate_fd1_handler!(flock_handler,            SYS_FLOCK);

// SOL_* / SO_* constants used in setsockopt/getsockopt below.
// Values match Linux x86_64 ABI.
const SOL_SOCKET:   i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE:      i32 = 3;
const SO_ERROR:     i32 = 4;
const SO_DONTROUTE: i32 = 5;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF:    i32 = 7;
const SO_RCVBUF:    i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_LINGER:    i32 = 13;
const SO_REUSEPORT: i32 = 15;
const SO_PASSCRED:  i32 = 16;
const SO_RCVLOWAT:  i32 = 18;
const SO_SNDLOWAT:  i32 = 19;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL:  i32 = 38;
const SO_DOMAIN:    i32 = 39;

/// sendto (syscall 44): IPC-aware.  For IPC sockets, write to sendpipe
/// (ignoring `dest_addr` — IPC sockets are always connected).  For IPC
/// pipes, return ENOTSOCK.  Otherwise translate fd and forward.
///
/// `send()` in glibc is a wrapper around sendto with NULL/0 sockaddr.
pub extern "C" fn sendto_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // buf (already a host addr — translated by glibc)
    arg3: u64, arg3cage: u64,    // count
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,    // dest_addr (ignored for IPC)
    arg6: u64, arg6cage: u64,    // addrlen
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_SENDTO, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let pipe = with_ipc(|s| {
        s.sockets.get(underfd).and_then(|sock| sock.sendpipe.clone())
    });
    let pipe = match pipe {
        Some(p) => p,
        None => return ENOTCONN_NEG,
    };

    let nonblocking = (flags & O_NONBLOCK) != 0;

    if count == 0 || arg2 == 0 {
        return 0;
    }
    pipe.write_from_cage(arg2cage, arg2, count, nonblocking, this_cage)
}

/// recvfrom (syscall 45): IPC-aware mirror of sendto_handler.  For IPC
/// sockets, read from recvpipe; for IPC pipes, return ENOTSOCK; else
/// forward.
///
/// If a non-NULL `src_addr` was provided, we don't synthesize a peer
/// address — we set `*addrlen` to 0 so the caller sees "no address",
/// which matches AF_UNIX socketpair semantics on Linux (peer is unnamed).
pub extern "C" fn recvfrom_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // buf
    arg3: u64, arg3cage: u64,    // count
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,    // src_addr (out)
    arg6: u64, arg6cage: u64,    // addrlen (in/out)
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_RECVFROM, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let pipe = with_ipc(|s| {
        s.sockets.get(underfd).and_then(|sock| sock.recvpipe.clone())
    });
    let pipe = match pipe {
        Some(p) => p,
        None => return ENOTCONN_NEG,
    };

    let nonblocking = (flags & O_NONBLOCK) != 0;

    let ret = if count == 0 || arg2 == 0 {
        0
    } else {
        pipe.read_to_cage(arg2cage, arg2, count, nonblocking, this_cage)
    };
    // If caller supplied src_addr/addrlen, write addrlen=0 so they see
    // "no peer address available" rather than uninitialized bytes.
    if ret >= 0 && arg6 != 0 {
        let zero: u32 = 0;
        let _ = copy_data_between_cages(
            this_cage, arg6cage,
            &zero as *const u32 as u64, this_cage,
            arg6, arg6cage,
            4, 0,
        );
    }
    ret
}

/// sendmsg (syscall 46): IPC-aware.  Reads the msghdr + iovec array
/// from the user cage, gathers all iov segments into one buffer, and
/// writes to the IPC socket's sendpipe.  msg_name (destination) and
/// msg_control (ancillary data) are ignored for IPC sockets.
pub extern "C" fn sendmsg_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // msghdr*
    arg3: u64, arg3cage: u64,    // flags
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_SENDMSG, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let pipe = with_ipc(|s| {
        s.sockets.get(underfd).and_then(|sock| sock.sendpipe.clone())
    });
    let pipe = match pipe {
        Some(p) => p,
        None => return ENOTCONN_NEG,
    };

    // Pull the msghdr (56 bytes) out of the user cage.
    let mut hdr = HostMsghdr::default();
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        arg2, arg2cage,
        &mut hdr as *mut _ as u64, this_cage,
        core::mem::size_of::<HostMsghdr>() as u64, 0,
    );

    let iov_count = hdr.msg_iovlen as usize;
    if iov_count == 0 {
        return 0;
    }
    if iov_count > MAX_IOV {
        return -22; // EINVAL
    }

    // Walk the iov array (still in user-cage memory).  For each entry,
    // read 16 bytes (iov_base + iov_len), then copy `iov_len` bytes
    // from `iov_base` into one growing local buffer.
    let mut gathered: Vec<u8> = Vec::new();
    for i in 0..iov_count {
        let mut iov = HostIovec::default();
        let entry_addr = hdr.msg_iov.wrapping_add((i as u64) * 16);
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            entry_addr, arg2cage,
            &mut iov as *mut _ as u64, this_cage,
            core::mem::size_of::<HostIovec>() as u64, 0,
        );
        let len = iov.iov_len as usize;
        if len == 0 { continue; }
        let mut chunk = vec![0u8; len];
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            iov.iov_base, arg2cage,
            chunk.as_mut_ptr() as u64, this_cage,
            len as u64, 0,
        );
        gathered.extend_from_slice(&chunk);
    }

    let nonblocking = (flags & O_NONBLOCK) != 0;
    let total = gathered.len();
    if total == 0 {
        return 0;
    }
    pipe.write(&gathered, total, nonblocking)
}

/// recvmsg (syscall 47): IPC-aware.  Reads from the IPC socket's
/// recvpipe into one buffer, then scatters bytes into the user's iov
/// segments.  Returns total bytes received.
pub extern "C" fn recvmsg_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // msghdr*
    arg3: u64, arg3cage: u64,    // flags
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_RECVMSG, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let pipe = with_ipc(|s| {
        s.sockets.get(underfd).and_then(|sock| sock.recvpipe.clone())
    });
    let pipe = match pipe {
        Some(p) => p,
        None => return ENOTCONN_NEG,
    };

    // Pull the msghdr in from the user cage and walk the iov array
    // up front to compute total recv capacity.
    let mut hdr = HostMsghdr::default();
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        arg2, arg2cage,
        &mut hdr as *mut _ as u64, this_cage,
        core::mem::size_of::<HostMsghdr>() as u64, 0,
    );

    let iov_count = hdr.msg_iovlen as usize;
    if iov_count == 0 {
        return 0;
    }
    if iov_count > MAX_IOV {
        return -22; // EINVAL
    }

    let mut iovs: Vec<HostIovec> = Vec::with_capacity(iov_count);
    let mut total_capacity: usize = 0;
    for i in 0..iov_count {
        let mut iov = HostIovec::default();
        let entry_addr = hdr.msg_iov.wrapping_add((i as u64) * 16);
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            entry_addr, arg2cage,
            &mut iov as *mut _ as u64, this_cage,
            core::mem::size_of::<HostIovec>() as u64, 0,
        );
        total_capacity = total_capacity.saturating_add(iov.iov_len as usize);
        iovs.push(iov);
    }
    if total_capacity == 0 {
        return 0;
    }

    let nonblocking = (flags & O_NONBLOCK) != 0;
    let mut buf = vec![0u8; total_capacity];
    let ret = pipe.read(&mut buf, total_capacity, nonblocking);
    if ret <= 0 {
        return ret;
    }
    // Scatter `ret` bytes into the user iov segments.
    let mut remaining = ret as usize;
    let mut offset = 0usize;
    for iov in &iovs {
        if remaining == 0 { break; }
        let chunk = core::cmp::min(iov.iov_len as usize, remaining);
        if chunk == 0 { continue; }
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            buf.as_ptr().wrapping_add(offset) as u64, this_cage,
            iov.iov_base, arg2cage,
            chunk as u64, 0,
        );
        offset += chunk;
        remaining -= chunk;
    }
    ret
}

/// setsockopt (syscall 54): IPC-aware.  For IPC sockets, accept (no-op)
/// a recognised set of SO_* options at SOL_SOCKET so apps can call
/// setsockopt without failing.  Reject unknown options with
/// ENOPROTOOPT.  For IPC pipes, return ENOTSOCK.  Otherwise forward.
pub extern "C" fn setsockopt_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // level
    arg3: u64, arg3cage: u64,    // optname
    arg4: u64, arg4cage: u64,    // optval
    arg5: u64, arg5cage: u64,    // optlen
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_SETSOCKOPT, cage_id, args, arg_cages);
    }
    let (_underfd, fdkind, _flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let level   = arg2 as i32;
    let optname = arg3 as i32;
    if level != SOL_SOCKET {
        return ENOPROTOOPT_NEG;
    }
    match optname {
        SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_PASSCRED
        | SO_BROADCAST | SO_DONTROUTE | SO_LINGER
        | SO_SNDBUF | SO_RCVBUF | SO_SNDLOWAT | SO_RCVLOWAT => 0,
        _ => ENOPROTOOPT_NEG,
    }
}

/// getsockopt (syscall 55): IPC-aware.  For IPC sockets, return canned
/// values for the SO_* options apps actually inspect.  We know the
/// domain/socktype from socket-create time, so SO_TYPE / SO_DOMAIN /
/// SO_PROTOCOL / SO_ACCEPTCONN are answered from our socket registry.
/// Buffer-related options report a fixed size; flag options report 0.
/// Unknown options return ENOPROTOOPT.
pub extern "C" fn getsockopt_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // level
    arg3: u64, arg3cage: u64,    // optname
    arg4: u64, arg4cage: u64,    // optval (out)
    arg5: u64, arg5cage: u64,    // optlen (in/out)
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_GETSOCKOPT, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, _flags) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }

    let level   = arg2 as i32;
    let optname = arg3 as i32;
    if level != SOL_SOCKET {
        return ENOPROTOOPT_NEG;
    }

    // SOCK_TYPE_MASK on Linux: low 4 bits of `type` are the actual
    // socket type; SOCK_CLOEXEC / SOCK_NONBLOCK live in higher bits.
    const SOCK_TYPE_MASK: i32 = 0xf;

    // Compute the i32 value to report based on optname + socket info.
    let val: i32 = match optname {
        SO_TYPE => with_ipc(|s| {
            s.sockets.get(underfd)
                .map(|x| x.socktype & SOCK_TYPE_MASK)
                .unwrap_or(0)
        }),
        SO_DOMAIN => with_ipc(|s| s.sockets.get(underfd).map(|x| x.domain).unwrap_or(0)),
        SO_PROTOCOL => 0,
        SO_ACCEPTCONN => with_ipc(|s| {
            s.sockets.get(underfd)
                .map(|x| if x.state == socket::ConnState::Listening { 1 } else { 0 })
                .unwrap_or(0)
        }),
        SO_ERROR => 0,
        SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_PASSCRED
        | SO_BROADCAST | SO_DONTROUTE => 0,
        // Buffer sizes — match the IPC pipe's capacity (see socket.rs).
        SO_SNDBUF | SO_RCVBUF => 65536,
        SO_SNDLOWAT | SO_RCVLOWAT => 1,
        _ => return ENOPROTOOPT_NEG,
    };

    // Honour the caller's optlen: write min(4, *optlen) bytes, then
    // write 4 back to *optlen.
    if arg5 == 0 || arg4 == 0 {
        return -22; // EINVAL
    }
    let mut user_optlen: u32 = 0;
    let _ = copy_data_between_cages(
        this_cage, arg5cage,
        arg5, arg5cage,
        &mut user_optlen as *mut u32 as u64, this_cage,
        4, 0,
    );
    let write_bytes = core::cmp::min(user_optlen, 4) as u64;
    if write_bytes > 0 {
        let _ = copy_data_between_cages(
            this_cage, arg4cage,
            &val as *const i32 as u64, this_cage,
            arg4, arg4cage,
            write_bytes, 0,
        );
    }
    let four: u32 = 4;
    let _ = copy_data_between_cages(
        this_cage, arg5cage,
        &four as *const u32 as u64, this_cage,
        arg5, arg5cage,
        4, 0,
    );
    0
}

/// Serialize an IPC socket's local/remote address into the host
/// sockaddr layout the kernel uses.  Returns `(buf, len)` where
/// `buf[..len]` is the sockaddr bytes that should be copied to user.
///
/// AF_UNIX:
///   - bound/named: 2-byte sun_family + path bytes + 1 null terminator.
///   - unnamed (e.g. socketpair / unbound): 2-byte sun_family only.
/// AF_INET (loopback):
///   - 16-byte sockaddr_in: family(2) + port(2, network order) +
///     in_addr(4) + zero(8).  `addr` is `"a.b.c.d:port"`.
fn build_ipc_sockaddr(domain: i32, addr: &Option<String>) -> ([u8; 110], u32) {
    let mut buf = [0u8; 110];
    if domain == socket::AF_UNIX {
        buf[0..2].copy_from_slice(&(socket::AF_UNIX as u16).to_le_bytes());
        if let Some(path) = addr {
            let pb = path.as_bytes();
            let n = pb.len().min(107);
            buf[2..2 + n].copy_from_slice(&pb[..n]);
            return (buf, (2 + n + 1) as u32);
        }
        (buf, 2)
    } else if domain == socket::AF_INET {
        buf[0..2].copy_from_slice(&(socket::AF_INET as u16).to_le_bytes());
        if let Some(s) = addr {
            if let Some(colon) = s.rfind(':') {
                if let Ok(port) = s[colon + 1..].parse::<u16>() {
                    buf[2..4].copy_from_slice(&port.to_be_bytes());
                }
                let parts: Vec<&str> = s[..colon].split('.').collect();
                if parts.len() == 4 {
                    for (i, p) in parts.iter().enumerate() {
                        if let Ok(v) = p.parse::<u8>() { buf[4 + i] = v; }
                    }
                }
            }
        }
        (buf, 16)
    } else {
        (buf, 0)
    }
}

/// Common implementation for getsockname / getpeername on IPC sockets.
/// Reads the user's addrlen, builds the sockaddr from the IPC socket
/// info, writes `min(sock_len, user_addrlen)` bytes to the user's
/// addr buffer, and writes the actual `sock_len` back to addrlen
/// (Linux semantics: indicates the real length, even if truncated).
fn ipc_writeback_sockaddr(
    sock_buf: &[u8], sock_len: u32,
    addr_arg: u64, addrcage: u64,
    addrlen_arg: u64, addrlencage: u64,
    this_cage: u64,
) -> i32 {
    if addr_arg == 0 || addrlen_arg == 0 {
        return -22; // EINVAL
    }
    let mut user_addrlen: u32 = 0;
    let _ = copy_data_between_cages(
        this_cage, addrlencage,
        addrlen_arg, addrlencage,
        &mut user_addrlen as *mut u32 as u64, this_cage,
        4, 0,
    );
    let copy_len = core::cmp::min(sock_len, user_addrlen);
    if copy_len > 0 {
        let _ = copy_data_between_cages(
            this_cage, addrcage,
            sock_buf.as_ptr() as u64, this_cage,
            addr_arg, addrcage,
            copy_len as u64, 0,
        );
    }
    let _ = copy_data_between_cages(
        this_cage, addrlencage,
        &sock_len as *const u32 as u64, this_cage,
        addrlen_arg, addrlencage,
        4, 0,
    );
    0
}

/// getsockname (syscall 51): IPC-aware.  For IPC sockets, synthesize
/// the local sockaddr from our SocketInfo registry.  For IPC pipes,
/// return ENOTSOCK.  Otherwise forward.
pub extern "C" fn getsockname_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // addr (out)
    arg3: u64, arg3cage: u64,    // addrlen (in/out)
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_GETSOCKNAME, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, _) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }
    let (domain, local_addr) = with_ipc(|s| {
        s.sockets.get(underfd)
            .map(|x| (x.domain, x.local_addr.clone()))
            .unwrap_or((0, None))
    });
    let (sock_buf, sock_len) = build_ipc_sockaddr(domain, &local_addr);
    ipc_writeback_sockaddr(
        &sock_buf, sock_len,
        arg2, arg2cage, arg3, arg3cage, this_cage,
    )
}

/// getpeername (syscall 52): IPC-aware.  Mirror of getsockname using
/// the remote_addr field.  For an unconnected IPC socket, returns
/// ENOTCONN to match Linux semantics.
pub extern "C" fn getpeername_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_GETPEERNAME, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, _) = info.unwrap();
    if fdkind != socket::IPC_SOCKET {
        return ENOTSOCK_NEG;
    }
    let (domain, remote_addr, connected) = with_ipc(|s| {
        s.sockets.get(underfd)
            .map(|x| (x.domain, x.remote_addr.clone(), x.state == socket::ConnState::Connected))
            .unwrap_or((0, None, false))
    });
    if !connected {
        return ENOTCONN_NEG;
    }
    let (sock_buf, sock_len) = build_ipc_sockaddr(domain, &remote_addr);
    ipc_writeback_sockaddr(
        &sock_buf, sock_len,
        arg2, arg2cage, arg3, arg3cage, this_cage,
    )
}

/// Walk an iov array (host-layout, in user-cage memory) and gather all
/// segments into one Vec.  Used by writev on IPC fds.
fn gather_iov_into_buf(
    iov_ptr: u64, iovcnt: usize,
    iov_cage: u64, this_cage: u64,
) -> Result<Vec<u8>, i32> {
    if iovcnt > MAX_IOV { return Err(-22); }
    let mut gathered: Vec<u8> = Vec::new();
    for i in 0..iovcnt {
        let mut iov = HostIovec::default();
        let entry_addr = iov_ptr.wrapping_add((i as u64) * 16);
        let _ = copy_data_between_cages(
            this_cage, iov_cage,
            entry_addr, iov_cage,
            &mut iov as *mut _ as u64, this_cage,
            core::mem::size_of::<HostIovec>() as u64, 0,
        );
        let len = iov.iov_len as usize;
        if len == 0 { continue; }
        let mut chunk = vec![0u8; len];
        let _ = copy_data_between_cages(
            this_cage, iov_cage,
            iov.iov_base, iov_cage,
            chunk.as_mut_ptr() as u64, this_cage,
            len as u64, 0,
        );
        gathered.extend_from_slice(&chunk);
    }
    Ok(gathered)
}

/// Scatter `data` into a host-layout iov array (in user-cage memory).
/// Returns the number of bytes scattered (`<= data.len()`).
fn scatter_buf_into_iov(
    data: &[u8],
    iov_ptr: u64, iovcnt: usize,
    iov_cage: u64, this_cage: u64,
) -> Result<usize, i32> {
    if iovcnt > MAX_IOV { return Err(-22); }
    let mut written = 0usize;
    let mut remaining = data.len();
    for i in 0..iovcnt {
        if remaining == 0 { break; }
        let mut iov = HostIovec::default();
        let entry_addr = iov_ptr.wrapping_add((i as u64) * 16);
        let _ = copy_data_between_cages(
            this_cage, iov_cage,
            entry_addr, iov_cage,
            &mut iov as *mut _ as u64, this_cage,
            core::mem::size_of::<HostIovec>() as u64, 0,
        );
        let chunk = core::cmp::min(iov.iov_len as usize, remaining);
        if chunk == 0 { continue; }
        let _ = copy_data_between_cages(
            this_cage, iov_cage,
            data.as_ptr().wrapping_add(written) as u64, this_cage,
            iov.iov_base, iov_cage,
            chunk as u64, 0,
        );
        written += chunk;
        remaining -= chunk;
    }
    Ok(written)
}

/// writev (syscall 20): IPC-aware.  For IPC pipes/sockets, gather all
/// iov segments and write to the appropriate pipe.  Otherwise forward.
pub extern "C" fn writev_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // iov*
    arg3: u64, arg3cage: u64,    // iovcnt
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let iovcnt = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_WRITEV, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();

    let pipe = match fdkind {
        IPC_PIPE => {
            if !is_write_end(flags) { return EBADF_NEG; }
            with_ipc(|s| s.get_pipe(underfd))
        }
        socket::IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.sendpipe.clone())
        }),
        _ => return EBADF_NEG,
    };
    let pipe = match pipe { Some(p) => p, None => return ENOTCONN_NEG };

    let gathered = match gather_iov_into_buf(arg2, iovcnt, arg2cage, this_cage) {
        Ok(g) => g,
        Err(e) => return e,
    };
    if gathered.is_empty() { return 0; }
    let nonblocking = (flags & O_NONBLOCK) != 0;
    pipe.write(&gathered, gathered.len(), nonblocking)
}

/// readv (syscall 19): IPC-aware mirror of writev.  Read up to total
/// iov capacity from the pipe; scatter into user iov segments.
pub extern "C" fn readv_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let iovcnt = arg3 as usize;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_READV, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();

    let pipe = match fdkind {
        IPC_PIPE => {
            if !is_read_end(flags) { return EBADF_NEG; }
            with_ipc(|s| s.get_pipe(underfd))
        }
        socket::IPC_SOCKET => with_ipc(|s| {
            s.sockets.get(underfd).and_then(|sock| sock.recvpipe.clone())
        }),
        _ => return EBADF_NEG,
    };
    let pipe = match pipe { Some(p) => p, None => return ENOTCONN_NEG };

    // Compute total iov capacity by walking the iov array once.
    if iovcnt > MAX_IOV { return -22; }
    let mut total_capacity = 0usize;
    let mut iov_lens: Vec<usize> = Vec::with_capacity(iovcnt);
    for i in 0..iovcnt {
        let mut iov = HostIovec::default();
        let entry_addr = arg2.wrapping_add((i as u64) * 16);
        let _ = copy_data_between_cages(
            this_cage, arg2cage,
            entry_addr, arg2cage,
            &mut iov as *mut _ as u64, this_cage,
            core::mem::size_of::<HostIovec>() as u64, 0,
        );
        iov_lens.push(iov.iov_len as usize);
        total_capacity = total_capacity.saturating_add(iov.iov_len as usize);
    }
    if total_capacity == 0 { return 0; }

    let nonblocking = (flags & O_NONBLOCK) != 0;
    let mut buf = vec![0u8; total_capacity];
    let ret = pipe.read(&mut buf, total_capacity, nonblocking);
    if ret <= 0 { return ret; }

    match scatter_buf_into_iov(&buf[..ret as usize], arg2, iovcnt, arg2cage, this_cage) {
        Ok(_) => ret,
        Err(e) => e,
    }
}

/// ioctl (syscall 16): IPC-aware.  Handles FIONBIO (set/clear
/// non-blocking) and FIONREAD (bytes available to read) for IPC fds.
/// Other ioctl requests on IPC fds return ENOTTY.  Non-IPC fds
/// translate + forward as before.
pub extern "C" fn ioctl_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // request
    arg3: u64, arg3cage: u64,    // argp
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    const FIONREAD: u64 = 0x541B;
    const FIONBIO:  u64 = 0x5421;

    let cage_id = arg1cage;
    let fd = arg1;
    let request = arg2;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_IOCTL, cage_id, args, arg_cages);
    }
    let (underfd, fdkind, flags) = info.unwrap();

    match request {
        FIONBIO => {
            // *argp is an int: nonzero = set O_NONBLOCK, zero = clear.
            if arg3 == 0 { return -22; }
            let mut user_val: i32 = 0;
            let _ = copy_data_between_cages(
                this_cage, arg3cage,
                arg3, arg3cage,
                &mut user_val as *mut i32 as u64, this_cage,
                4, 0,
            );
            let new_flags = if user_val != 0 {
                (flags as u64) | (O_NONBLOCK as u64)
            } else {
                (flags as u64) & !(O_NONBLOCK as u64)
            };
            // Update perfdinfo on the fdtables entry.  translate_virtual_fd
            // gives us the existing entry; we re-overlay with new perfdinfo.
            if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
                let _ = fdtables::get_specific_virtual_fd(
                    cage_id, fd, entry.fdkind, entry.underfd,
                    entry.should_cloexec, new_flags,
                );
            }
            0
        }
        FIONREAD => {
            // *argp <- bytes available to read.
            if arg3 == 0 { return -22; }
            let avail: i32 = match fdkind {
                IPC_PIPE => with_ipc(|s| {
                    s.get_pipe(underfd).map(|p| p.bytes_available() as i32).unwrap_or(0)
                }),
                socket::IPC_SOCKET => with_ipc(|s| {
                    s.sockets.get(underfd)
                        .and_then(|sock| sock.recvpipe.clone())
                        .map(|p| p.bytes_available() as i32)
                        .unwrap_or(0)
                }),
                _ => 0,
            };
            let _ = copy_data_between_cages(
                this_cage, arg3cage,
                &avail as *const i32 as u64, this_cage,
                arg3, arg3cage,
                4, 0,
            );
            0
        }
        _ => -25, // ENOTTY — ioctl request not supported on IPC fds
    }
}

/// fstat (syscall 5): IPC-aware.  For IPC pipes/sockets, fill in a
/// minimal stat struct with `st_mode = S_IFIFO | 0600` (pipe) or
/// `S_IFSOCK | 0666` (socket).  Other fields are zeroed.  Apps mainly
/// use fstat on these fds to detect type via S_ISFIFO/S_ISSOCK.
pub extern "C" fn fstat_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    // lind-wasm WASM32 / host `StatData` layout: st_dev (u64) at 0,
    // st_ino (4 bytes on wasm32 / 8 on host but written by RawPOSIX
    // with 4-byte effective stride) + 4 bytes padding put st_mode
    // (u32) at offset 16.  Total struct is 144 bytes including
    // timespecs.  Only st_mode is meaningful for our purposes.
    const STAT_SIZE: usize = 144;
    const ST_MODE_OFFSET: usize = 16;
    const S_IFIFO:  u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    let cage_id = arg1cage;
    let fd = arg1;
    let this_cage = getcageid();
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let info = lookup_ipc_fd(cage_id, fd);
    if info.is_none() {
        return forward_with_fd1(SYS_FSTAT, cage_id, args, arg_cages);
    }
    let (_underfd, fdkind, _) = info.unwrap();
    if arg2 == 0 { return -22; }

    let mut buf = [0u8; STAT_SIZE];
    let mode: u32 = match fdkind {
        IPC_PIPE => S_IFIFO | 0o600,
        socket::IPC_SOCKET => S_IFSOCK | 0o666,
        _ => return -22,
    };
    buf[ST_MODE_OFFSET..ST_MODE_OFFSET + 4].copy_from_slice(&mode.to_le_bytes());
    let _ = copy_data_between_cages(
        this_cage, arg2cage,
        buf.as_ptr() as u64, this_cage,
        arg2, arg2cage,
        STAT_SIZE as u64, 0,
    );
    0
}

/// For syscalls that don't apply to pipes/sockets (lseek, pread,
/// pwrite, preadv, pwritev, sync_file_range): if the fd is an IPC fd,
/// return ESPIPE per Linux/POSIX semantics; otherwise translate and
/// forward to the kernel like a normal fd1 operation.
macro_rules! ipc_espipe_handler {
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
            if lookup_ipc_fd(cage_id, arg1).is_some() {
                return -29; // ESPIPE
            }
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
            forward_with_fd1($sysno, cage_id, args, arg_cages)
        }
    };
}

ipc_espipe_handler!(lseek_handler,            SYS_LSEEK);
ipc_espipe_handler!(pread_handler,            SYS_PREAD);
ipc_espipe_handler!(pwrite_handler,           SYS_PWRITE);
ipc_espipe_handler!(preadv_handler,           SYS_PREADV);
ipc_espipe_handler!(pwritev_handler,          SYS_PWRITEV);
ipc_espipe_handler!(sync_file_range_handler,  SYS_SYNC_FILE_RANGE);

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
        return accept_ipc_inner(
            cage_id, socket_id, listen_flags, cloexec, extra_perfdinfo,
            arg2, arg2cage, arg3, arg3cage,
        );
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
