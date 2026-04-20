//! Lifecycle handlers: register_handler, exec, fork, exit.
//! Identical to the FS namespace grate — port routing is handled
//! in ns_handlers.rs, not here.

use grate_rs::{
    SyscallHandler,
    constants::{SYS_CLONE, SYS_EXEC, SYS_EXIT, SYS_REGISTER_HANDLER},
    copy_data_between_cages, register_handler,
};

use crate::handlers::get_ns_handler;
use crate::helpers;

pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target_cage: u64, syscall_nr: u64,
    _arg2: u64, grate_id: u64,
    handler_fn_ptr: u64, _arg3cage: u64,
    _arg4: u64, _arg4cage: u64,
    _arg5: u64, _arg5cage: u64,
    _arg6: u64, _arg6cage: u64,
) -> i32 {
    let ns_cage = helpers::get_ns_cage_id();

    if !helpers::is_cage_clamped(grate_id) {
        return helpers::do_syscall(
            grate_id,
            SYS_REGISTER_HANDLER,
            &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
            &[syscall_nr, grate_id, 0, 0, 0, 0],
        );
    }

    let already_registered = helpers::get_route(target_cage, syscall_nr).is_some();

    if !already_registered {
        if let Some(ns_handler) = get_ns_handler(syscall_nr) {
            let alt_nr = helpers::alloc_alt_syscall();

            let ret = helpers::do_syscall(
                grate_id,
                SYS_REGISTER_HANDLER,
                &[ns_cage, 0, handler_fn_ptr, 0, 0, 0],
                &[alt_nr, grate_id, 0, 0, 0, 0],
            );

            let _ = helpers::set_route(target_cage, syscall_nr, alt_nr);

            if ret != 0 {
                return ret;
            }

            match register_handler(target_cage, syscall_nr, ns_cage, ns_handler) {
                Ok(_) => {}
                Err(_) => return -1,
            }
        } else {
            return helpers::do_syscall(
                grate_id,
                SYS_REGISTER_HANDLER,
                &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
                &[syscall_nr, grate_id, 0, 0, 0, 0],
            );
        }
    }

    helpers::register_clamped_cage(target_cage);
    0
}

pub extern "C" fn exec_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let ns_cage = helpers::get_ns_cage_id();

    if let Some(path) = helpers::read_path_from_cage(arg1, arg1cage) {
        if path == "%}" {
            helpers::deregister_clamped_cage(arg1cage);

            const PTR_SIZE: usize = 8;
            let mut real_ptr = [0u8; PTR_SIZE];
            let argv1_addr = arg2 + PTR_SIZE as u64;

            match copy_data_between_cages(
                ns_cage, arg2cage,
                argv1_addr, arg2cage,
                real_ptr.as_mut_ptr() as u64, ns_cage,
                8, 0,
            ) {
                Ok(_) => {}
                Err(_) => return -2,
            };

            let real_path = u64::from_le_bytes(real_ptr);

            return helpers::do_syscall(
                arg2cage, SYS_EXEC,
                &[real_path, argv1_addr, arg3, arg4, arg5, arg6],
                &[arg2cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            );
        }
    }

    helpers::do_syscall(
        arg1cage, SYS_EXEC,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

pub extern "C" fn fork_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let child_cage_id = helpers::do_syscall(arg1cage, SYS_CLONE, &args, &arg_cages) as u64;

    if helpers::is_cage_clamped(arg1cage) {
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);
        helpers::clone_cage_routes(arg1cage, child_cage_id);
    }

    register_lifecycle_handlers(child_cage_id);
    child_cage_id as i32
}

pub extern "C" fn exit_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    helpers::remove_cage_state(arg1cage);
    fdtables::remove_cage_from_fdtable(arg1cage);

    helpers::do_syscall(
        arg1cage, SYS_EXIT,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

pub fn register_lifecycle_handlers(cage_id: u64) {
    let ns_cage = helpers::get_ns_cage_id();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_EXEC, exec_handler),
        (SYS_CLONE, fork_handler),
        (SYS_EXIT, exit_handler),
        (SYS_REGISTER_HANDLER, register_handler_handler),
    ];

    for &(syscall_nr, handler) in handlers {
        let _ = register_handler(cage_id, syscall_nr, ns_cage, handler);
    }
}
