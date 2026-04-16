//! fdtables stress-test grate
//!
//! Exercises fdtables operations under single-cage and cross-fork scenarios
//! to isolate Lind-WASM threading/DashMap issues from grate-specific logic.
//!
//! Intercepts: open, close, dup, dup2, fork, exec, read, write
//! All handlers do fdtables bookkeeping + forward the real syscall.
//! Minimal output — only prints on errors.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, copy_data_between_cages, getcageid, make_threei_call};

const FDT_KIND: u32 = 1;

// =====================================================================
//  Mutex / atomic contention probes
//
//  The write handler increments these on every call. After fork, both
//  parent and child cage write through this grate, so the counters get
//  hit from two runtime threads.
//
//  MUTEX_COUNT: incremented under std::sync::Mutex.
//  ATOMIC_COUNT: incremented with AtomicU64::fetch_add.
//  UNSYNC_COUNT: incremented with NO synchronisation (plain read-modify-write).
//
//  If Mutex actually works cross-thread:
//    MUTEX_COUNT == ATOMIC_COUNT == total writes
//  If Mutex is a no-op across threads:
//    MUTEX_COUNT < ATOMIC_COUNT  (lost updates)
//  If atomics don't work either:
//    ATOMIC_COUNT < total writes
//  UNSYNC_COUNT is the control — expected to lose updates under concurrency.
// =====================================================================

static MUTEX_COUNTER: Mutex<u64> = Mutex::new(0);
static ATOMIC_COUNTER: AtomicU64 = AtomicU64::new(0);
static UNSYNC_COUNTER: AtomicU64 = AtomicU64::new(0); // abused as plain u64 via load+store

/// Read counter values and write them back to the cage's buffer.
/// Triggered by read() on fd 99 (magic fd, see C test).
fn report_counters(cage_id: u64, buf_ptr: u64, buf_cage: u64) -> i32 {
    let mutex_val = *MUTEX_COUNTER.lock().unwrap();
    let atomic_val = ATOMIC_COUNTER.load(Ordering::SeqCst);
    let unsync_val = UNSYNC_COUNTER.load(Ordering::Relaxed);

    let report = format!("mutex={} atomic={} unsync={}\n", mutex_val, atomic_val, unsync_val);
    let bytes = report.as_bytes();

    let grate_cage = getcageid();
    let _ = copy_data_between_cages(
        grate_cage, buf_cage,
        bytes.as_ptr() as u64, grate_cage,
        buf_ptr, buf_cage,
        bytes.len() as u64, 0,
    );

    bytes.len() as i32
}

fn forward(
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
//  Handlers — quiet fdtables bookkeeping + forward
// =====================================================================

pub extern "C" fn open_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let ret = forward(SYS_OPEN, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage]);
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, ret as u64, FDT_KIND, ret as u64, false, arg2);
    }
    ret
}

pub extern "C" fn close_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    // Translate before close to stress fdtables lookups.
    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::translate_virtual_fd(cage_id, fd);
    }
    let ret = forward(SYS_CLOSE, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage]);
    if ret >= 0 && fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::close_virtualfd(cage_id, fd);
    }
    ret
}

pub extern "C" fn dup_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let ret = forward(SYS_DUP, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage]);
    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, ret as u64, entry.fdkind, entry.underfd,
                entry.should_cloexec, entry.perfdinfo);
        }
    }
    ret
}

pub extern "C" fn dup2_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let oldfd = arg1;
    let newfd = arg2;
    let ret = forward(SYS_DUP2, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage]);
    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, oldfd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, newfd, entry.fdkind, entry.underfd,
                entry.should_cloexec, entry.perfdinfo);
        }
    }
    ret
}

pub extern "C" fn fork_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let ret = forward(SYS_CLONE, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage]);
    if ret <= 0 { return ret; }

    let child_cage_id = ret as u64;
    let _ = fdtables::copy_fdtable_for_cage(cage_id, child_cage_id);
    child_cage_id as i32
}

pub extern "C" fn exec_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    fdtables::empty_fds_for_exec(cage_id);
    for fd in 0..3u64 {
        let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
    }
    forward(SYS_EXEC, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage])
}

pub extern "C" fn read_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;

    // Magic fd 99: report counter values instead of forwarding.
    if fd == 99 {
        return report_counters(cage_id, arg2, arg2cage);
    }

    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::translate_virtual_fd(cage_id, fd);
    }
    forward(SYS_READ, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage])
}

pub extern "C" fn write_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;

    // Bump contention counters on every write (except stdout/stderr).
    if fd > 2 {
        // Mutex-protected increment.
        {
            let mut count = MUTEX_COUNTER.lock().unwrap();
            *count += 1;
        }
        // Atomic increment.
        ATOMIC_COUNTER.fetch_add(1, Ordering::SeqCst);
        // Unsynchronised increment (deliberate race — control group).
        let v = UNSYNC_COUNTER.load(Ordering::Relaxed);
        UNSYNC_COUNTER.store(v + 1, Ordering::Relaxed);
    }

    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::translate_virtual_fd(cage_id, fd);
    }
    forward(SYS_WRITE, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage])
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    GrateBuilder::new()
        .register(SYS_OPEN, open_handler)
        .register(SYS_CLOSE, close_handler)
        .register(SYS_DUP, dup_handler)
        .register(SYS_DUP2, dup2_handler)
        .register(SYS_READ, read_handler)
        .register(SYS_WRITE, write_handler)
        .register(SYS_CLONE, fork_handler)
        .register(SYS_EXEC, exec_handler)
        .preexec(|child_cage: i32| {
            let cage_id = child_cage as u64;
            fdtables::init_empty_cage(cage_id);
            for fd in 0..3u64 {
                let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
            }
        })
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[fdt-test] error: {:?}", e);
            }
        })
        .run(argv);
}
