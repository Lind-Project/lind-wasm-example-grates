//! fdtables stress-test grate
//!
//! Exercises fdtables operations under single-cage and cross-fork scenarios
//! to isolate Lind-WASM threading/DashMap issues from grate-specific logic.
//!
//! Intercepts: open, close, dup, dup2, fork, exec
//! All handlers do fdtables bookkeeping + forward the real syscall.
//! The test cage exercises every combination to surface races and corruption.

use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, copy_data_between_cages, getcageid, make_threei_call};

const FDT_KIND: u32 = 1; // our fdkind for tracked fds

// =====================================================================
//  Helpers
// =====================================================================

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

fn ensure_cage(cage_id: u64) {
    if !fdtables::check_cage_exists(cage_id) {
        fdtables::init_empty_cage(cage_id);
    }
}

// =====================================================================
//  Handlers — pure fdtables bookkeeping + forward
// =====================================================================

/// open: forward, then track the returned fd.
pub extern "C" fn open_handler(
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

    let ret = forward(SYS_OPEN, cage_id, &args, &arg_cages);

    if ret >= 0 {
        ensure_cage(cage_id);
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, ret as u64, FDT_KIND, ret as u64, false, arg2,
        );
        println!("[fdt-test] open cage={} fd={}", cage_id, ret);
    }

    ret
}

/// close: look up fd, forward, then remove from fdtables.
pub extern "C" fn close_handler(
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
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Test translate before close.
    if fdtables::check_cage_exists(cage_id) {
        match fdtables::translate_virtual_fd(cage_id, fd) {
            Ok(entry) => {
                println!("[fdt-test] close cage={} fd={} kind={} underfd={}",
                    cage_id, fd, entry.fdkind, entry.underfd);
            }
            Err(_) => {
                println!("[fdt-test] close cage={} fd={} (not in fdtables)", cage_id, fd);
            }
        }
    } else {
        println!("[fdt-test] close cage={} fd={} (cage not in fdtables)", cage_id, fd);
    }

    let ret = forward(SYS_CLOSE, cage_id, &args, &arg_cages);

    if ret >= 0 && fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::close_virtualfd(cage_id, fd);
    }

    ret
}

/// dup: forward, then register the new fd.
pub extern "C" fn dup_handler(
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
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let ret = forward(SYS_DUP, cage_id, &args, &arg_cages);

    if ret >= 0 {
        // Copy the old fd's entry to the new fd number.
        ensure_cage(cage_id);
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, ret as u64, entry.fdkind, entry.underfd,
                entry.should_cloexec, entry.perfdinfo,
            );
        }
        println!("[fdt-test] dup cage={} oldfd={} newfd={}", cage_id, fd, ret);
    }

    ret
}

/// dup2: forward, then register the target fd.
pub extern "C" fn dup2_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let oldfd = arg1;
    let newfd = arg2;
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let ret = forward(SYS_DUP2, cage_id, &args, &arg_cages);

    if ret >= 0 {
        ensure_cage(cage_id);
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, oldfd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, newfd, entry.fdkind, entry.underfd,
                entry.should_cloexec, entry.perfdinfo,
            );
        }
        println!("[fdt-test] dup2 cage={} oldfd={} newfd={}", cage_id, oldfd, newfd);
    }

    ret
}

/// fork: forward, then copy fdtable for child.
pub extern "C" fn fork_handler(
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

    let ret = forward(SYS_CLONE, cage_id, &args, &arg_cages);

    if ret <= 0 {
        return ret;
    }

    let child_cage_id = ret as u64;

    println!("[fdt-test] fork cage={} -> child={}", cage_id, child_cage_id);

    // Copy parent's fdtable to child.
    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::copy_fdtable_for_cage(cage_id, child_cage_id);
        println!("[fdt-test] copied fdtable {} -> {}", cage_id, child_cage_id);
    } else {
        println!("[fdt-test] WARNING: parent cage {} not in fdtables at fork time", cage_id);
        ensure_cage(child_cage_id);
    }

    // Verify child cage exists and has entries.
    if fdtables::check_cage_exists(child_cage_id) {
        let child_fds = fdtables::return_fdtable_copy(child_cage_id);
        println!("[fdt-test] child {} has {} fds after copy", child_cage_id, child_fds.len());
    } else {
        println!("[fdt-test] ERROR: child cage {} missing after copy!", child_cage_id);
    }

    child_cage_id as i32
}

/// exec: ensure cage exists, reserve 0/1/2, forward.
pub extern "C" fn exec_handler(
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

    ensure_cage(cage_id);
    fdtables::empty_fds_for_exec(cage_id);

    // Reserve stdin/stdout/stderr.
    for fd in 0..3u64 {
        let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
    }

    println!("[fdt-test] exec cage={}", cage_id);

    forward(SYS_EXEC, cage_id, &args, &arg_cages)
}

// =====================================================================
//  Read/Write — just log + forward (test that fdtables isn't corrupted)
// =====================================================================

pub extern "C" fn read_handler(
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

    // Stress test: translate_virtual_fd on every read.
    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::translate_virtual_fd(cage_id, fd);
    }

    forward(
        SYS_READ, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

pub extern "C" fn write_handler(
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

    // Stress test: translate_virtual_fd on every write.
    if fdtables::check_cage_exists(cage_id) {
        let _ = fdtables::translate_virtual_fd(cage_id, fd);
    }

    forward(
        SYS_WRITE, cage_id,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

// =====================================================================
//  Main
// =====================================================================

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    println!("[fdt-test] starting fdtables test grate");

    GrateBuilder::new()
        .register(SYS_OPEN, open_handler)
        .register(SYS_CLOSE, close_handler)
        .register(SYS_DUP, dup_handler)
        .register(SYS_DUP2, dup2_handler)
        .register(SYS_READ, read_handler)
        .register(SYS_WRITE, write_handler)
        .register(SYS_CLONE, fork_handler)
        .register(SYS_EXEC, exec_handler)
        .teardown(|result: Result<i32, GrateError>| {
            println!("[fdt-test] exited: {:?}", result);
        })
        .run(argv);
}
