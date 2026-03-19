//! Syscall handler functions for the namespace clamping grate.
//!
//! This file contains every handler that the namespace grate registers on cages.
//! There are three categories:
//!
//! 1. **Lifecycle handlers** — registered on every cage in the clamp chain.
//!    These intercept register_handler (1001), exec (59), fork (57), and exit (60)
//!    to manage the clamp boundary, routing table, and cage lineage.
//!
//! 2. **Path-based handlers** — for syscalls whose first arg is a path pointer.
//!    These read the path from cage memory, check if it matches the prefix,
//!    and route to the clamped grate's alt syscall or passthrough to kernel.
//!
//! 3. **FD-based handlers** — for syscalls whose first arg is a file descriptor.
//!    These look up the fd in fdtables to check if it was opened under the
//!    clamped prefix (perfdinfo == 1), and route accordingly.
//!    Some (open, close, dup) also update fdtables as a side effect.

use grate_rs::constants::*;
use grate_rs::{SyscallHandler, copy_data_between_cages, register_handler};

use crate::helpers;

// =====================================================================
//  Standard handler signature type alias for readability.
//
//  Every handler has the same extern "C" signature:
//    (cageid, arg1, arg1cage, arg2, arg2cage, ..., arg6, arg6cage) -> i32
//
//  - cageid:   the cage that made the syscall
//  - argN:     the Nth syscall argument
//  - argNcage: the cage that owns argN's memory (for cross-cage copies)
// =====================================================================

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
///
/// Syscall 1001 arguments:
///   arg1 = target_cage_id
///   arg2 = syscall_nr
///   arg3 = grate_id
///   arg4 = handler_fn_ptr
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    arg1: u64,
    _arg1cage: u64,
    arg2: u64,
    _arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let target_cage = arg1;
    let syscall_nr = arg2;
    let grate_id = arg3;
    let handler_fn_ptr = arg4;
    let ns_cage = helpers::get_ns_cage_id();

    // After clamp phase, pass through — we only intercept registrations
    // from clamped grates (before %} boundary).
    if !helpers::is_in_clamp_phase() {
        return helpers::do_syscall(
            SYS_REGISTER_HANDLER,
            &[target_cage, syscall_nr, grate_id, handler_fn_ptr, 0, 0],
            &[0; 6],
        );
    }

    println!(
        "[ns-grate] intercept register_handler: cage={}, syscall={}, grate={}",
        target_cage, syscall_nr, grate_id
    );

    // Step 1: Allocate a unique alt syscall number for this handler.
    let alt_nr = helpers::alloc_alt_syscall();

    // Step 2: Register the clamped grate's handler at the alt number on the
    // namespace grate's own cage. This way, when we later call
    // do_syscall(alt_nr, ...) it routes to the clamped grate's handler.
    let ret = helpers::do_syscall(
        SYS_REGISTER_HANDLER,
        &[ns_cage, alt_nr, grate_id, handler_fn_ptr, 0, 0],
        &[0; 6],
    );
    if ret != 0 {
        println!("[ns-grate] failed to register alt handler: ret={}", ret);
        return ret;
    }

    // Step 3: Store the route so our handlers know which alt to dispatch to.
    // Returns true if a route already existed (ns handler already registered).
    let already_registered = helpers::set_route(target_cage, syscall_nr, alt_nr);

    // Step 4: If this is the first registration for this syscall on this cage,
    // register the namespace grate's own handler on the target cage.
    if !already_registered {
        if let Some(ns_handler) = get_ns_handler(syscall_nr) {
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
            println!(
                "[ns-grate] no ns handler for syscall {} — passing through registration",
                syscall_nr
            );
            return helpers::do_syscall(
                SYS_REGISTER_HANDLER,
                &[target_cage, syscall_nr, grate_id, handler_fn_ptr, 0, 0],
                &[0; 6],
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
    // Read the exec path from the cage's memory to check for %}.
    if let Some(path) = helpers::read_path_from_cage(arg1, arg1cage) {
        if path == "%}" {
            println!("[ns-grate] detected %}} boundary — ending clamp phase");
            helpers::end_clamp_phase();

            // The command line looks like: [..., "%}", "python", ...]
            // argv[0] = "%}", argv[1] = the real program to exec.
            // We need to read argv[1]'s pointer and shift argv forward by one.

            // wasm32 pointers are 4 bytes wide.
            let ptr_size: u64 = 4;

            // argv[1] is at argv_base + 4 bytes.
            let argv1_ptr_addr = arg2 + ptr_size;

            // Read the 4-byte pointer value at argv[1] from cage memory.
            let ns_cage = helpers::get_ns_cage_id();
            let mut argv1_ptr_buf = [0u8; 4];
            match copy_data_between_cages(
                ns_cage, arg2cage,
                argv1_ptr_buf.as_mut_ptr() as u64, ns_cage,
                argv1_ptr_addr, arg2cage,
                4, 0,
            ) {
                Ok(_) => {}
                Err(_) => {
                    println!("[ns-grate] failed to read argv[1] pointer");
                    return -1;
                }
            }

            // The real program path pointer (in cage address space).
            let real_path_ptr = u32::from_le_bytes(argv1_ptr_buf) as u64;

            // Exec the real program with argv shifted past %}.
            // argv[1..] becomes the new argv (argv1_ptr_addr = &argv[1]).
            return helpers::do_syscall(
                SYS_EXEC,
                &[real_path_ptr, argv1_ptr_addr, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            );
        }
    }

    // Not %} — pass through the exec normally.
    helpers::do_syscall(
        SYS_EXEC,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

/// Handler for syscall 57 (fork).
///
/// Forwards the fork, then if the parent was clamped:
///   - Clones the routing table to the child cage
///   - Clones the fdtables state to the child cage
///   - Registers lifecycle handlers on the child cage
pub extern "C" fn fork_handler(
    cageid: u64,
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
    let ret = helpers::do_syscall(SYS_FORK, &args, &arg_cages);

    // Only the parent (ret > 0) needs to set up state for the new child.
    let child_cage_id = match ret {
        r if r > 0 => r as u64,
        _ => return ret,
    };

    // If the forking cage is inside the clamp, the child inherits that status.
    if helpers::is_cage_clamped(cageid) {
        // Copy the routing table entries for this cage to the child.
        helpers::clone_cage_state(cageid, child_cage_id);

        // Copy the fd table so the child knows which fds are clamped.
        let _ = fdtables::copy_fdtable_for_cage(cageid, child_cage_id);
    }

    // Register our lifecycle handlers on the child so we can track it.
    register_lifecycle_handlers(child_cage_id);

    child_cage_id as i32
}

/// Handler for syscall 60 (exit).
///
/// Cleans up routing and fd state for the exiting cage, then forwards the exit.
pub extern "C" fn exit_handler(
    cageid: u64,
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
    helpers::remove_cage_state(cageid);

    // Remove this cage's fd table.
    fdtables::remove_cage_from_fdtable(cageid);

    // Forward exit to the runtime.
    helpers::do_syscall(
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
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
        (SYS_FORK, fork_handler),
        (SYS_EXIT, exit_handler),
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

// =====================================================================
//  2. PATH-BASED SYSCALL HANDLERS
//
//  These handle syscalls where arg1 is a pointer to a path string in the
//  calling cage's memory. The handler reads the path, checks if it starts
//  with the clamped prefix, and either:
//    - Routes to the alt syscall (prefix matches → clamped grate handles it)
//    - Passes through to kernel (no match → kernel handles it)
// =====================================================================

/// stat (syscall 4): get file status by path.
pub extern "C" fn ns_stat_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Check if the path matches the clamped prefix.
    let nr = match helpers::get_route(cageid, SYS_XSTAT) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_XSTAT,
        },
        None => SYS_XSTAT,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// access (syscall 21): check file permissions by path.
pub extern "C" fn ns_access_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_ACCESS) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_ACCESS,
        },
        None => SYS_ACCESS,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// unlink (syscall 87): delete a file by path.
pub extern "C" fn ns_unlink_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_UNLINK) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_UNLINK,
        },
        None => SYS_UNLINK,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// mkdir (syscall 83): create a directory by path.
pub extern "C" fn ns_mkdir_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_MKDIR) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_MKDIR,
        },
        None => SYS_MKDIR,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// rmdir (syscall 84): remove a directory by path.
pub extern "C" fn ns_rmdir_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_RMDIR) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_RMDIR,
        },
        None => SYS_RMDIR,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// rename (syscall 82): rename a file by path.
pub extern "C" fn ns_rename_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_RENAME) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_RENAME,
        },
        None => SYS_RENAME,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// truncate (syscall 76): truncate a file by path.
pub extern "C" fn ns_truncate_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_TRUNCATE) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_TRUNCATE,
        },
        None => SYS_TRUNCATE,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// chmod (syscall 90): change file permissions by path.
pub extern "C" fn ns_chmod_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_CHMOD) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_CHMOD,
        },
        None => SYS_CHMOD,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// chdir (syscall 80): change working directory by path.
pub extern "C" fn ns_chdir_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_CHDIR) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_CHDIR,
        },
        None => SYS_CHDIR,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// readlink (syscall 89): read a symbolic link by path.
pub extern "C" fn ns_readlink_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_READLINK) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_READLINK,
        },
        None => SYS_READLINK,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// unlinkat (syscall 263): delete a file relative to a directory fd.
pub extern "C" fn ns_unlinkat_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_UNLINKAT) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_UNLINKAT,
        },
        None => SYS_UNLINKAT,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// readlinkat (syscall 267): read a symbolic link relative to a directory fd.
pub extern "C" fn ns_readlinkat_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_READLINKAT) {
        Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
            Some(path) if helpers::path_matches_prefix(&path) => alt,
            _ => SYS_READLINKAT,
        },
        None => SYS_READLINKAT,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

// =====================================================================
//  3. FD-BASED SYSCALL HANDLERS
//
//  These handle syscalls where arg1 is a file descriptor. The handler
//  checks fdtables to see if the fd was opened under the clamped prefix
//  (perfdinfo == 1). If so, it routes to the clamped grate via the alt
//  syscall. Otherwise it passes through to kernel.
//
//  Some handlers (open, close, dup) also update fdtables as a side effect.
// =====================================================================

/// open (syscall 2): open a file by path.
///
/// This is both path-based (checks prefix) AND updates fdtables:
/// after a successful open, records the new fd with perfdinfo=1 if the
/// path matched the prefix, or perfdinfo=0 if it didn't.
pub extern "C" fn ns_open_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Check if the path matches the clamped prefix.
    let matches = helpers::read_path_from_cage(arg1, arg1cage)
        .map(|p| helpers::path_matches_prefix(&p))
        .unwrap_or(false);

    // Route to alt if prefix matches, otherwise passthrough.
    let nr = match helpers::get_route(cageid, SYS_OPEN) {
        Some(alt) if matches => alt,
        _ => SYS_OPEN,
    };

    let ret = helpers::do_syscall(nr, &args, &arg_cages);

    // On success, record the fd in fdtables with the clamped flag.
    // perfdinfo=1 means "this fd was opened under the clamped prefix."
    if ret >= 0 {
        let clamped = if matches { 1u64 } else { 0 };
        let _ = fdtables::get_specific_virtual_fd(
            cageid,
            ret as u64, // virtual fd = the returned fd
            0,          // fdkind (unused)
            ret as u64, // underfd = same (identity mapping)
            false,      // should_cloexec
            clamped,    // perfdinfo: 1=clamped, 0=not
        );
    }

    ret
}

/// close (syscall 3): close a file descriptor.
///
/// Routes based on fdtables (is this fd clamped?), then removes the fd
/// from fdtables regardless of the result.
pub extern "C" fn ns_close_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Check if this fd is clamped (perfdinfo != 0).
    let is_clamped = fdtables::translate_virtual_fd(cageid, arg1)
        .map(|e| e.perfdinfo != 0)
        .unwrap_or(false);

    let nr = match helpers::get_route(cageid, SYS_CLOSE) {
        Some(alt) if is_clamped => alt,
        _ => SYS_CLOSE,
    };

    let ret = helpers::do_syscall(nr, &args, &arg_cages);

    // Always remove the fd from our tracking.
    let _ = fdtables::close_virtualfd(cageid, arg1);

    ret
}

/// read (syscall 0): read from a file descriptor.
pub extern "C" fn ns_read_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Check if this fd is clamped.
    let nr = match helpers::get_route(cageid, SYS_READ) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false) => alt,
        _ => SYS_READ,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// write (syscall 1): write to a file descriptor.
pub extern "C" fn ns_write_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = match helpers::get_route(cageid, SYS_WRITE) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false) => alt,
        _ => SYS_WRITE,
    };

    helpers::do_syscall(nr, &args, &arg_cages)
}

/// pread (syscall 17): read from fd at offset.
pub extern "C" fn ns_pread_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_PREAD) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_PREAD,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// pwrite (syscall 18): write to fd at offset.
pub extern "C" fn ns_pwrite_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_PWRITE) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_PWRITE,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// lseek (syscall 8): reposition fd read/write offset.
pub extern "C" fn ns_lseek_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_LSEEK) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_LSEEK,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// fstat (syscall 5): get file status by fd.
pub extern "C" fn ns_fstat_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_FXSTAT) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_FXSTAT,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// fcntl (syscall 72): file descriptor control.
pub extern "C" fn ns_fcntl_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_FCNTL) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_FCNTL,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// ftruncate (syscall 77): truncate a file by fd.
pub extern "C" fn ns_ftruncate_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_FTRUNCATE) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_FTRUNCATE,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// fchmod (syscall 91): change file permissions by fd.
pub extern "C" fn ns_fchmod_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_FCHMOD) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_FCHMOD,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// readv (syscall 19): scatter read from fd.
pub extern "C" fn ns_readv_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_READV) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_READV,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// writev (syscall 20): gather write to fd.
pub extern "C" fn ns_writev_handler(
    cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    let nr = match helpers::get_route(cageid, SYS_WRITEV) {
        Some(alt) if fdtables::translate_virtual_fd(cageid, arg1).map(|e| e.perfdinfo != 0).unwrap_or(false) => alt,
        _ => SYS_WRITEV,
    };
    helpers::do_syscall(nr, &args, &arg_cages)
}

/// dup (syscall 32): duplicate a file descriptor.
///
/// Routes based on fdtables, then copies the perfdinfo to the new fd.
pub extern "C" fn ns_dup_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Look up the old fd's clamped status before dispatching.
    let perfdinfo = fdtables::translate_virtual_fd(cageid, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(cageid, SYS_DUP) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP,
    };

    let ret = helpers::do_syscall(nr, &args, &arg_cages);

    // On success, record the new fd with the same clamped status as the old one.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            cageid, ret as u64, 0, ret as u64, false, perfdinfo,
        );
    }

    ret
}

/// dup2 (syscall 33): duplicate fd to a specific target fd.
///
/// Routes based on fdtables, then copies perfdinfo to the target fd.
pub extern "C" fn ns_dup2_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let perfdinfo = fdtables::translate_virtual_fd(cageid, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(cageid, SYS_DUP2) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP2,
    };

    let ret = helpers::do_syscall(nr, &args, &arg_cages);

    // arg2 is the target fd for dup2.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            cageid, arg2, 0, arg2, false, perfdinfo,
        );
    }

    ret
}

/// dup3 (syscall 292): duplicate fd to a specific target fd with flags.
///
/// Same as dup2 but with an additional flags argument (arg3).
pub extern "C" fn ns_dup3_handler(
    cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let perfdinfo = fdtables::translate_virtual_fd(cageid, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(cageid, SYS_DUP3) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP3,
    };

    let ret = helpers::do_syscall(nr, &args, &arg_cages);

    // arg2 is the target fd for dup3.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            cageid, arg2, 0, arg2, false, perfdinfo,
        );
    }

    ret
}

// =====================================================================
//  HANDLER LOOKUP
//
//  Maps syscall numbers to their namespace handler function pointers.
//  Used by register_handler_handler to know which handler to register
//  on a target cage when a clamped grate registers for that syscall.
// =====================================================================

pub fn get_ns_handler(syscall_nr: u64) -> Option<SyscallHandler> {
    match syscall_nr {
        // Path-based
        SYS_OPEN      => Some(ns_open_handler),
        SYS_XSTAT     => Some(ns_stat_handler),
        SYS_ACCESS    => Some(ns_access_handler),
        SYS_UNLINK    => Some(ns_unlink_handler),
        SYS_MKDIR     => Some(ns_mkdir_handler),
        SYS_RMDIR     => Some(ns_rmdir_handler),
        SYS_RENAME    => Some(ns_rename_handler),
        SYS_TRUNCATE  => Some(ns_truncate_handler),
        SYS_CHMOD     => Some(ns_chmod_handler),
        SYS_CHDIR     => Some(ns_chdir_handler),
        SYS_READLINK  => Some(ns_readlink_handler),
        SYS_UNLINKAT  => Some(ns_unlinkat_handler),
        SYS_READLINKAT => Some(ns_readlinkat_handler),

        // FD-based
        SYS_READ      => Some(ns_read_handler),
        SYS_WRITE     => Some(ns_write_handler),
        SYS_CLOSE     => Some(ns_close_handler),
        SYS_PREAD     => Some(ns_pread_handler),
        SYS_PWRITE    => Some(ns_pwrite_handler),
        SYS_LSEEK     => Some(ns_lseek_handler),
        SYS_FXSTAT    => Some(ns_fstat_handler),
        SYS_FCNTL     => Some(ns_fcntl_handler),
        SYS_FTRUNCATE => Some(ns_ftruncate_handler),
        SYS_FCHMOD    => Some(ns_fchmod_handler),
        SYS_READV     => Some(ns_readv_handler),
        SYS_WRITEV    => Some(ns_writev_handler),

        // FD-based with fd-tracking side effects
        SYS_DUP       => Some(ns_dup_handler),
        SYS_DUP2      => Some(ns_dup2_handler),
        SYS_DUP3      => Some(ns_dup3_handler),

        _ => None,
    }
}
