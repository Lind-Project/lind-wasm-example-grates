use grate_rs::constants::{SYS_CLONE, SYS_EXEC};
use grate_rs::{GrateBuilder, GrateError, getcageid, is_thread_clone, make_threei_call};
use fdtables;

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
    if !is_thread_clone(arg1, arg1cage) {
        let _ = fdtables::copy_fdtable_for_cage(cage_id, child_cage_id);
    }
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

fn main() {
    println!("[Grate Init]: Initializing FD Translate Grate");

    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    GrateBuilder::new()
        .enable_fd_translate_policy(None)
        .register(SYS_CLONE, fork_handler)
        .register(SYS_EXEC, exec_handler)
        .preexec(|child_cage: i32| {
            let cage_id = child_cage as u64;
            println!("[fdt-test] preexec: cage_id={}", cage_id);
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