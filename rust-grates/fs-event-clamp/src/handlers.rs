//! 3i handlers for fs-event-clamp.
//!
//! Lifecycle handlers (exec, clone, exit, register_handler) are installed on the clamp's child
//! and are inherited by everything forked from it. Clamped grates that interpose on these calls
//! forward them through their own (inherited) handler tables, so they still reach us.

use grate_rs::constants::error::EFAULT;
use grate_rs::constants::*;
use grate_rs::{
    GrateError, SyscallHandler, copy_data_between_cages, copy_handler_table_to_cage,
    is_thread_clone, make_threei_call, register_handler,
};

use crate::state::{self, HandlerSet};

const MAX_PATH_LEN: usize = 4096;

/// Some lind-wasm glibc builds issue fork as clone3 instead of clone; both take a `clone_args`
/// pointer in arg1.
pub const SYS_CLONE3: u64 = 435;

/// Forward a syscall through the clamp's own handler table (i.e. to the grates outside of it).
fn do_syscall(calling_cage: u64, nr: u64, args: &[u64; 6], cages: &[u64; 6]) -> i64 {
    match make_threei_call(
        nr as u32,
        0,
        state::ns_cage(),
        calling_cage,
        args[0],
        cages[0],
        args[1],
        cages[1],
        args[2],
        cages[2],
        args[3],
        cages[3],
        args[4],
        cages[4],
        args[5],
        cages[5],
        0,
    ) {
        Ok(ret) => ret as i64,
        Err(GrateError::MakeSyscallError(ret)) => ret as i64,
        Err(_) => -1,
    }
}

/// Issue register_handler on behalf of `grate_id`, exactly as that grate requested it.
fn forward_registration(target: u64, nr: u64, grate_id: u64, handler_fn: u64) -> i64 {
    do_syscall(
        grate_id,
        SYS_REGISTER_HANDLER,
        &[target, 0, handler_fn, 0, 0, 0],
        &[nr, grate_id, 0, 0, 0, 0],
    )
}

fn read_bytes(ptr: u64, cage: u64, len: usize, nul_terminated: bool) -> Option<Vec<u8>> {
    let ns_cage = state::ns_cage();
    let mut buf = vec![0u8; len];
    copy_data_between_cages(
        ns_cage,
        cage,
        ptr,
        cage,
        buf.as_mut_ptr() as u64,
        ns_cage,
        len as u64,
        nul_terminated as u64,
    )
    .ok()?;
    if nul_terminated {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(len);
        buf.truncate(end);
    }
    Some(buf)
}

// =====================================================================
//  Lifecycle handlers
// =====================================================================

/// syscall 1001 (register_handler): record registrations from the clamped grates. Registrations
/// targeting a program cage that has not opened a matching path yet are deferred.
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target: u64,
    nr: u64,
    _arg2: u64,
    grate_id: u64,
    handler_fn: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i64 {
    if state::with(|s| s.is_pending(target)) {
        state::with(|s| s.record_registration(target, nr, grate_id, handler_fn));
        return 0;
    }
    let ret = forward_registration(target, nr, grate_id, handler_fn);
    if ret == 0 {
        state::with(|s| s.record_registration(target, nr, grate_id, handler_fn));
    }
    ret
}

/// syscall 59 (exec): tracks nested `%{`/`%}` markers. When our own `%}` is reached, the cage
/// becomes the program: it gets the clamp's outer handler table plus open observers, and then
/// execs the real program (argv shifted past `%}`).
pub extern "C" fn exec_handler(
    _cageid: u64,
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
) -> i64 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let forward = || do_syscall(arg1cage, SYS_EXEC, &args, &cages);

    if state::with(|s| s.is_program(arg1cage)) {
        return forward();
    }
    let Some(path) = read_bytes(arg1, arg1cage, MAX_PATH_LEN, true) else {
        return -(EFAULT as i64);
    };
    match path.as_slice() {
        b"%{" => {
            state::with(|s| s.enter_block());
            forward()
        }
        b"%}" if state::with(|s| s.exit_block()) => {
            let ret = start_program(arg1cage);
            if ret != 0 {
                return ret;
            }
            // argv is { "%}", program, args..., NULL }: exec argv[1] with argv + 1.
            const PTR_SIZE: u64 = 8;
            let argv1 = arg2 + PTR_SIZE;
            let Some(ptr) = read_bytes(argv1, arg2cage, PTR_SIZE as usize, false) else {
                return -(EFAULT as i64);
            };
            let program = u64::from_le_bytes(ptr.try_into().unwrap());
            do_syscall(
                arg1cage,
                SYS_EXEC,
                &[program, argv1, arg3, arg4, arg5, arg6],
                &cages,
            )
        }
        _ => forward(),
    }
}

/// Replace the program's handler table with the clamp's outer table, and observe opens.
fn start_program(cage: u64) -> i64 {
    let ns_cage = state::ns_cage();
    if let Err(e) = copy_handler_table_to_cage(ns_cage, cage) {
        eprintln!("[fs-event-clamp] failed to reset handler table of cage {cage}: {e:?}");
        return -1;
    }
    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_OPEN, open_handler::<SYS_OPEN>),
        (SYS_OPENAT, open_handler::<SYS_OPENAT>),
        (SYS_EXEC, exec_handler),
        (SYS_CLONE, fork_handler::<SYS_CLONE>),
        (SYS_CLONE3, fork_handler::<SYS_CLONE3>),
        (SYS_EXIT_GROUP, exit_handler),
        (SYS_REGISTER_HANDLER, register_handler_handler),
    ];
    for &(nr, handler) in handlers {
        if let Err(e) = register_handler(cage, nr, ns_cage, handler) {
            eprintln!("[fs-event-clamp] failed to register handler {nr} on cage {cage}: {e:?}");
            return -1;
        }
    }
    state::with(|s| s.start_program(cage));
    0
}

/// syscalls 56/435 (clone/clone3): propagate the parent's clamp state to a forked child.
pub extern "C" fn fork_handler<const NR: u64>(
    _cageid: u64,
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
) -> i64 {
    let is_thread = is_thread_clone(arg1, arg1cage);
    let ret = do_syscall(
        arg1cage,
        NR,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );
    if ret > 0 && !is_thread {
        state::with(|s| s.on_fork(arg1cage, ret as u64));
    }
    ret
}

/// syscall 231 (exit_group): drop the cage's state and forward.
pub extern "C" fn exit_handler(
    _cageid: u64,
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
) -> i64 {
    state::with(|s| s.on_exit(arg1cage));
    do_syscall(
        arg1cage,
        SYS_EXIT_GROUP,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

// =====================================================================
//  Trigger
// =====================================================================

/// syscalls 2/257 (open/openat): forward the open; if it succeeded on a pending program cage and
/// the pathname argument matches the regex, route the cage to the clamped grates from now on.
extern "C" fn open_handler<const NR: u64>(
    _cageid: u64,
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
) -> i64 {
    let (path_ptr, path_cage) = if NR == SYS_OPEN {
        (arg1, arg1cage)
    } else {
        (arg2, arg2cage)
    };
    let path = read_bytes(path_ptr, path_cage, MAX_PATH_LEN, true);
    let ret = do_syscall(
        arg1cage,
        NR,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );
    if ret < 0 {
        return ret;
    }
    let Some(path) = path else {
        eprintln!("[fs-event-clamp] unable to read open pathname of cage {arg1cage}");
        return ret;
    };
    match state::with(|s| s.take_activation(arg1cage, &path, state::regex())) {
        Some(handlers) => match activate(arg1cage, handlers) {
            0 => ret,
            err => err,
        },
        None => ret,
    }
}

/// Install the deferred handlers of the clamped grates on `cage`.
fn activate(cage: u64, handlers: HandlerSet) -> i64 {
    for (nr, (grate_id, handler_fn)) in handlers {
        let ret = forward_registration(cage, nr, grate_id, handler_fn);
        if ret != 0 {
            eprintln!("[fs-event-clamp] failed to route syscall {nr} of cage {cage}: {ret}");
            return ret;
        }
    }
    0
}
