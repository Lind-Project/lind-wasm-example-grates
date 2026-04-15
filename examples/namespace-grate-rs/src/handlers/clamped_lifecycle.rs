use grate_rs::{
    SyscallHandler,
    constants::{SYS_CLONE, SYS_EXEC, SYS_EXIT, SYS_REGISTER_HANDLER},
    copy_data_between_cages, register_handler,
};

use fdtables;

use crate::handlers::get_ns_handler;
use crate::helpers;

// =====================================================================
//  1. LIFECYCLE HANDLERS
// =====================================================================

/// Handler for syscall 1001 (register_handler).
///
/// When a clamped grate calls register_handler(cage, syscall, grate_id, fn_ptr),
/// we intercept it to:
///   1. Allocate an alt syscall number
///   2. Register the clamped grate's handler at that alt number on the ns grate's cage
///   3. Register the ns grate's handler for that syscall on the target cage
///   4. Store the route: (cage, syscall) -> alt number
///
/// After the clamp phase ends (%} is exec'd), register_handler calls pass through.
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target_cage: u64,
    syscall_nr: u64,
    _arg2: u64,
    grate_id: u64,
    handler_fn_ptr: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let ns_cage = helpers::get_ns_cage_id();
    // After clamp phase, pass through — we only intercept registrations
    // from clamped grates (before %} boundary).
    if !helpers::is_cage_clamped(grate_id) {
        return helpers::do_syscall(
            grate_id,
            SYS_REGISTER_HANDLER,
            &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
            &[syscall_nr, grate_id, 0, 0, 0, 0],
        );
    }

    // Step 0: Check if this syscall, target pair is already registered.
    let already_registered = match helpers::get_route(target_cage, syscall_nr) {
        Some(_) => true,
        _ => false,
    };

    // First registration.
    if !already_registered {
        // This syscall is ns_syscall
        if let Some(ns_handler) = get_ns_handler(syscall_nr) {
            // Step 1: Allocate a unique alt syscall number for this handler.
            let alt_nr = helpers::alloc_alt_syscall();

            // Step 2: Register the clamped grate's handler at the alt number on the
            // namespace grate's own cage. This way, when we later call
            // do_syscall(alt_nr, ...) it routes to the clamped grate's handler.
            let ret = helpers::do_syscall(
                grate_id,
                SYS_REGISTER_HANDLER,
                &[ns_cage, 0, handler_fn_ptr, 0, 0, 0],
                &[alt_nr, grate_id, 0, 0, 0, 0],
            );

            let _ = helpers::set_route(target_cage, syscall_nr, alt_nr);

            if ret != 0 {
                println!("[ns-grate] failed to register alt handler: ret={}", ret);
                return ret;
            }

            // Step 3: Registered the regular call number to go to ns_grate.
            match register_handler(target_cage, syscall_nr, ns_cage, ns_handler) {
                Ok(_) => {}
                Err(e) => {
                    println!("[ns-grate] failed to register ns handler: {:?}", e);
                    return -1;
                }
            }
        } else {
            // We don't have a handler for this syscall number. Pass through
            // the clamped grate's registration directly — we can't interpose.
            return helpers::do_syscall(
                grate_id,
                SYS_REGISTER_HANDLER,
                &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
                &[syscall_nr, grate_id, 0, 0, 0, 0],
            );
        }
    }

    // Track this cage as clamped (also inits its fdtables entry).
    helpers::register_clamped_cage(target_cage);

    0
}

/// Handler for syscall 59 (exec).
///
/// Detects the `%}` sentinel in the exec path. When found:
///   1. Ends the clamp phase (no more register_handler interception)
///   2. Rewrites the exec to skip past `%}` and run the real program
///
/// For all other exec calls, passes through unchanged.
///
/// Arguments: arg1 = path_ptr, arg2 = argv_ptr
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
) -> i32 {
    let ns_cage = helpers::get_ns_cage_id();

    // Read the exec path from the cage's memory to check for %}.
    if let Some(path) = helpers::read_path_from_cage(arg1, arg1cage) {
        if path == "%}" {
            println!("[ns-grate] detected %}} boundary — ending clamp phase");
            // Remove cageid from clamped cages.
            helpers::deregister_clamped_cage(arg1cage);

            // We've detected the clamp boundary, we need to left shift all argv[] and update the
            // path to the binary to be argv[1].
            //
            // Current state: { "%}", {...argv[]...} }
            // Desired state: { argv[1], {...argv[1]...} }

            // argv[] pointers are stored as host-coded u64 pointers.
            const PTR_SIZE: usize = 8;

            // This stores the value in argv[1]
            let mut real_ptr = [0u8; PTR_SIZE];

            // Address to argv[1]
            let argv1_addr = arg2 + PTR_SIZE as u64;

            // Copy argv[1] into real_ptr
            match copy_data_between_cages(
                ns_cage,
                arg2cage,
                argv1_addr,
                arg2cage,
                real_ptr.as_mut_ptr() as u64,
                ns_cage,
                8,
                0,
            ) {
                Ok(_) => {}
                Err(_) => {
                    println!("Invalid command line arguments detected.");
                    return -2;
                }
            };

            // Convert real_ptr bytes to address.
            let real_path = u64::from_le_bytes(real_ptr) as u64;

            // Call exec with updated arguments.
            return helpers::do_syscall(
                arg2cage,
                SYS_EXEC,
                &[real_path, argv1_addr, arg3, arg4, arg5, arg6],
                &[arg2cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            );
        } else {
            // In any other case, call exec without argument management.
            return helpers::do_syscall(
                arg1cage,
                SYS_EXEC,
                &[arg1, arg2, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            );
        }
    } else {
        panic!("[ns-grate] Unable to read the execve path");
    }
}

/// Handler for syscall 57 (fork).
///
/// Forwards the fork, then if the parent was clamped:
///   - Clones the routing table to the child cage
///   - Clones the fdtables state to the child cage
///   - Registers lifecycle handlers on the child cage
pub extern "C" fn fork_handler(
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
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Forward the fork to the runtime. Returns child cage ID to parent, 0 to child.
    let child_cage_id = helpers::do_syscall(arg1cage, SYS_CLONE, &args, &arg_cages) as u64;

    // If the forking cage is inside the clamp, the child inherits that status.
    if helpers::is_cage_clamped(arg1cage) {
        // Copy the fd table so the child knows which fds are clamped.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);
    }

    // Register our lifecycle handlers on the child so we can track it.
    register_lifecycle_handlers(child_cage_id);

    child_cage_id as i32
}

/// Handler for syscall 60 (exit).
///
/// Cleans up routing and fd state for the exiting cage, then forwards the exit.
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
) -> i32 {
    // Remove this cage's routing table entries.
    helpers::remove_cage_state(arg1cage);

    // Remove this cage's fd table.
    fdtables::remove_cage_from_fdtable(arg1cage);

    // Forward exit to the runtime.
    helpers::do_syscall(
        arg1cage,
        SYS_EXIT,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

/// Register the four lifecycle handlers on a cage.
///
/// Called on the initial child cage at startup, and on every new child
/// created by fork_handler.
pub fn register_lifecycle_handlers(cage_id: u64) {
    let ns_cage = helpers::get_ns_cage_id();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_EXEC, exec_handler),
        (SYS_CLONE, fork_handler),
        (SYS_EXIT, exit_handler),
        (SYS_REGISTER_HANDLER, register_handler_handler),
    ];

    for &(syscall_nr, handler) in handlers {
        match register_handler(cage_id, syscall_nr, ns_cage, handler) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "[ns-grate] failed to register lifecycle handler {} on cage {}: {:?}",
                    syscall_nr, cage_id, e
                );
            }
        }
    }
}
