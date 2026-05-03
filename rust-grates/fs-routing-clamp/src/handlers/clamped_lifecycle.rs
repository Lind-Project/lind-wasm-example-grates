use grate_rs::{
    SyscallHandler, constants::*, copy_data_between_cages, getcageid, is_thread_clone,
    register_handler,
};

use fdtables;

use crate::handlers::get_ns_handler;
use crate::helpers::{self};
use crate::log;

// =====================================================================
//  1. LIFECYCLE HANDLERS
// =====================================================================

/// Handler for syscall 1001 (register_handler).
///
/// Records each inner-grate registration so the target cage can be rewired
/// after the `%}` boundary, then forwards the original registration call.
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target_cage: u64,
    syscall_nr: u64,
    _arg2: u64,
    grate_id: u64,
    handler_fn_ptr: u64,
    arg3cage: u64,
    _arg4: u64,
    arg4cage: u64,
    _arg5: u64,
    arg5cage: u64,
    _arg6: u64,
    arg6cage: u64,
) -> i32 {
    // Record the interposition request. This table is read later before execing the target cage to
    // register clamped syscall handlers.
    //.push((target_cage, syscall_nr, grate_id, handler_fn_ptr));

    helpers::push_interposition_request((target_cage, syscall_nr, grate_id, handler_fn_ptr));

    helpers::do_syscall(
        grate_id,
        SYS_REGISTER_HANDLER,
        &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
        &[syscall_nr, grate_id, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

pub fn register_target_handlers(target_cage: u64) -> i32 {
    // These are all the calls that the fs-namespace grate cares about, all the following calls from the target
    // must be routed through the grate regardless of whether the clamp interposed on them.
    const FS_CALLS: [u64; 29] = [
        SYS_OPEN,
        SYS_XSTAT,
        SYS_ACCESS,
        SYS_UNLINK,
        SYS_MKDIR,
        SYS_RMDIR,
        SYS_RENAME,
        SYS_TRUNCATE,
        SYS_CHMOD,
        SYS_CHDIR,
        SYS_READLINK,
        SYS_UNLINKAT,
        SYS_READLINKAT,
        // FD-based
        SYS_READ,
        SYS_WRITE,
        SYS_CLOSE,
        SYS_PREAD,
        SYS_PWRITE,
        SYS_LSEEK,
        SYS_FXSTAT,
        SYS_FCNTL,
        SYS_FTRUNCATE,
        SYS_FCHMOD,
        SYS_READV,
        SYS_WRITEV,
        // FD-based with fd-tracking side effects
        SYS_DUP,
        SYS_DUP2,
        SYS_DUP3,
        // Lifecycle — interpose so we track child cages
        SYS_CLONE,
    ];

    let ns_cage = getcageid();

    // Reinstall namespace-grate handlers for the syscall set we clamp.
    //
    // Two cases are possible:
    //  1. The `entry` grate for the clamp interposed on this syscall. In this case, the alternate
    //     path is to route the call to that handler.
    //  2. The `entry` grate does not interpose on this syscall. In this case, the alternate path
    //     is to route the call with (self_cageid=entry_grate, calling_cageid=target_cage).
    //
    //  The rationale for this can be seen with the following example:
    //
    //  namespace --prefix /tmp %{ interpose-open-write interpose-open %} target
    //
    //  target calls: open("/tmp",...); write(fd, ...);
    //
    //  For open, the call goes the namespace grate and then to the handler in interpose-open.
    //
    //  For write, the call goes to the namespace grate and is determined to be a clamped FD. Since
    //  interpose-open does not have a handler for write, using (self_cageid=entry_grate) ensures
    //  that the call still goes to interpose-open-write.
    //
    //  The routing logic is handled in the `ns_handlers.rs` helpers.
    for fs_syscall in FS_CALLS {
        let ns_handler = get_ns_handler(fs_syscall);

        // Find Interposition Requests aimed at the child_cage.
        if let Some((grate_id, handler_fn)) =
            helpers::get_interposition_request(target_cage, fs_syscall)
        {
            // Handler for this syscall exists...

            // ... Allocate alt syscall...
            let alt_nr = helpers::alloc_alt_syscall();

            // ... Register that to the namespace grate...
            let ret = helpers::do_syscall(
                grate_id,
                SYS_REGISTER_HANDLER,
                &[ns_cage, 0, handler_fn, 0, 0, 0],
                &[alt_nr, grate_id, 0, 0, 0, 0],
            );

            if ret != 0 {
                return ret;
            }

            // ... Add to routing table.
            let _ = helpers::set_route(target_cage, fs_syscall, alt_nr);
        }

        // The visible handler on the target cage always points at ns-grate.
        match register_handler(target_cage, fs_syscall, ns_cage, ns_handler.unwrap()) {
            Ok(_) => {}
            Err(e) => {
                log!("[ns-grate] failed to register ns handler: {:?}", e);
                return -1;
            }
        }
    }

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
            // This cage is going to be the target cage, register the fs-clamped routing syscalls
            // to this cage_id.
            register_target_handlers(arg1cage);

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
                    log!("Invalid command line arguments detected.");
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
            // The current method to detect the "entry" grate to the clamp is to track the last
            // exec'd process, and update this state variable. Once we hit the clamp end boundary
            // (%}), we stop updating this variable.
            helpers::set_clamp_entry(arg1cage);

            // In any other case, call exec without argument management.
            return helpers::do_syscall(
                arg1cage,
                SYS_EXEC,
                &[arg1, arg2, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            );
        }
    }

    panic!("[ns-grate] unable to read execve path");
}

/// Handler for syscall 57 (fork).
///
/// Forwards the fork, then if the parent was clamped:
///   - Clones the routing table to the child cage
///   - Clones the fdtables state to the child cage
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

    if !is_thread_clone(arg1, arg1cage) {
        // Copy fdtables — child always needs an entry for inner grates
        // to track fds, regardless of clamp status.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);

        // If the forking cage is inside the clamp, clone routes too.
        if helpers::is_cage_clamped(arg1cage) {
            helpers::clone_cage_routes(arg1cage, child_cage_id);
        }
    }

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
/// Called on the initial child cage at startup.
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
                log!(
                    "[ns-grate] failed to register lifecycle handler {} on cage {}: {:?}",
                    syscall_nr, cage_id, e
                );
            }
        }
    }
}
