use std::collections::HashSet;

use crate::handlers::FS_CALL_TABLE;
use crate::tee::*;
use crate::utils::{do_syscall, get_interposition_request};
use grate_rs::{
    constants::*, copy_data_between_cages, copy_handler_table_to_cage, getcageid, make_threei_call,
    register_handler, SyscallHandler,
};

pub fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = getcageid();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
    ];

    for &(syscall_nr, handler) in handlers {
        if let Err(e) = register_handler(cage_id, syscall_nr, tee_cage, handler) {
            eprintln!(
                "[tee-grate] failed to register lifecycle handler {} on cage {}: {:?}",
                syscall_nr, cage_id, e
            );
        }
    }
}

/// Fork handler installed on the secondary-top cage once the target phase begins.
///
/// The secondary path should report the primary fork result instead of creating another child.
pub extern "C" fn fork_lifecycle_handler(
    _cageid: u64,
    _arg1: u64,
    _arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    // Consider the following layout:
    //
    // fs-tee %{ imfs %} target
    //
    // When `target` calls `fork()`, the primary path must fork as usual and the secondary path
    // must still observe the same returned cage ID.
    //
    // If `imfs` were allowed to run its own `SYS_CLONE`, it would create a duplicate child whose
    // cage ID is not meaningful to the target stack.
    //
    // To avoid that, once the target has been exec'd, the secondary-top fork handler simply
    // returns the cage ID produced by the primary path.
    with_tee(|s| s.fork_return) as i32
}

/// Intercept `register_handler` so fs-tee can remember how the secondary stack interposed.
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target_cage: u64,
    syscall_nr: u64,
    _arg2: u64,
    grate_id: u64,
    fn_ptr: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    // Record the interposition so it can be replayed against the real target cage at exec time.
    with_tee(|s| {
        s.interposition_map
            .push((target_cage, syscall_nr, grate_id, fn_ptr))
    });

    // Forward the original registration now. Cross-boundary registrations are rewritten later by
    // `copy_handler_table_to_cage()` and `register_target_handler()`.
    return do_syscall(
        grate_id,
        SYS_REGISTER_HANDLER,
        &[target_cage, _arg2, fn_ptr, _arg4, _arg5, _arg6],
        &[
            syscall_nr, grate_id, _arg3cage, _arg4cage, _arg5cage, _arg6cage,
        ],
    );
}

/// Install fs-tee handlers on the first target cage before its initial exec.
///
/// This replays the secondary stack's interpositions and routes relevant filesystem syscalls
/// through fs-tee.
pub fn register_target_handler(target_cage: u64) {
    let tee_cage = getcageid();

    // Register all filesystem syscalls handled by fs-tee.
    for (fs_syscall, handler) in FS_CALL_TABLE {
        // Ensure the target cage has a route entry for this syscall.
        with_tee(|s| {
            s.tee_routes
                .entry((target_cage, *fs_syscall))
                .or_insert(TeeRoute {
                    secondary_alt: None,
                });
        });

        // If the secondary entry cage interposed on this syscall...
        if let Some((secondary_grate, secondary_fn)) =
            get_interposition_request(target_cage, *fs_syscall)
        {
            // ... allocate and register an alternate syscall number that reaches the same
            // secondary handler through fs-tee.
            let alt_nr = with_tee(|s| s.alloc_alt());
            with_tee(|s| {
                s.tee_routes
                    .entry((target_cage, *fs_syscall))
                    .and_modify(|route| route.secondary_alt = Some(alt_nr));
            });

            do_syscall(
                tee_cage,
                SYS_REGISTER_HANDLER,
                &[tee_cage, 0, secondary_fn, 0, 0, 0],
                &[alt_nr, secondary_grate, 0, 0, 0, 0],
            );
        }

        // Register fs-tee's handler for the target cage.
        register_handler(target_cage, *fs_syscall, tee_cage, *handler).unwrap();
    }

    // Register default fdtables handlers.
    let except: HashSet<u64> = FS_CALL_TABLE.iter().map(|(x, _)| *x).collect();
    grate_rs::register_default_fd_handlers_except(target_cage, tee_cage, Some(except)).unwrap();

    // Override the secondary-top `fork()` so it returns the primary result instead of forking
    // again inside the tee boundary.
    let secondary_top = with_tee(|s| s.secondary_top);
    register_handler(secondary_top, SYS_CLONE, tee_cage, fork_lifecycle_handler).unwrap();
}

/// Intercept `exec()` so fs-tee can detect boundary markers and wire up target routing.
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
    // Step 0. Read the exec path into fs-tee so the boundary markers can be inspected locally.
    //
    // Step 1. If the path is `%}`, advance the phase. Entering `Target` means the next real cage
    // becomes fs-tee's routed target child.
    //
    // Step 2. If the path is `%{`, record this cage as the top of the secondary chain.
    //
    // Step 3. If the path is a boundary marker (`%{` or `%}`), shift `argv` left to remove that
    // marker and recursively reissue `exec()`.
    //
    // Step 4. Otherwise, if we are still building the secondary stack, keep updating
    // `secondary_entry` to the most recent normal exec cage.
    //
    // Step 5. For all non-marker paths, forward the original `exec()` unchanged.

    // Read the exec path so fs-tee can inspect the `%{` / `%}` boundary markers.
    let tee_cage = getcageid();

    let mut buf = vec![0u8; 256];
    if copy_data_between_cages(
        tee_cage,
        arg1cage,
        arg1,
        arg1cage,
        buf.as_mut_ptr() as u64,
        tee_cage,
        256,
        0,
    )
    .is_err()
    {
        panic!("[tee-grate] Unable to read the execve path");
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(256);
    let path = String::from_utf8_lossy(&buf[..len]);

    // `%}` advances the phase. Entering `Target` means the next real cage becomes the routed
    // target child of fs-tee.
    if path == "%}" {
        with_tee(|s| s.phase = s.phase.next());

        let phase = with_tee(|s| s.phase);

        match phase {
            TeePhase::Target => {
                // Initialize bookkeeping for the first real target cage.

                // Seed the target cage's FD table with stdin/stdout/stderr.
                fdtables::init_empty_cage(arg1cage as u64);

                for fd in 0..3 {
                    let _ = fdtables::get_specific_virtual_fd(arg1cage, fd, 1, fd, false, 0);
                }

                // Make the cage look like a direct child of fs-tee.
                copy_handler_table_to_cage(tee_cage, arg1cage).unwrap();

                // Route filesystem syscalls through fs-tee.
                register_target_handler(arg1cage);

                with_tee(|s| s.target_cage = arg1cage);
            }
            _ => {}
        };
    }

    if path == "%{" {
        // `%{` marks the top of the secondary chain inside the tee boundary.
        match with_tee(|s| s.phase) {
            TeePhase::Secondary => with_tee(|s| s.secondary_top = arg1cage),
            _ => {}
        };
    }

    // Boundary markers are consumed by shifting `argv` left and recursively reissuing `exec()`.
    if path == "%}" || path == "%{" {
        const PTR_SIZE: usize = 8;

        // Local buffer for the `argv[1]` pointer.
        let mut real_ptr = [0u8; PTR_SIZE];

        // Address of `argv[1]`.
        let argv1_addr = arg2 + PTR_SIZE as u64;

        // Load `argv[1]` so the marker can be removed from the forwarded exec call.
        match copy_data_between_cages(
            tee_cage,
            arg2cage,
            argv1_addr,
            arg2cage,
            real_ptr.as_mut_ptr() as u64,
            tee_cage,
            8,
            0,
        ) {
            Ok(_) => {}
            Err(_) => {
                println!("Invalid command line arguments detected.");
                return -2;
            }
        };

        // Decode the copied pointer value.
        let real_path = u64::from_le_bytes(real_ptr) as u64;

        // Reissue `exec()` with the shifted argv.
        match make_threei_call(
            SYS_EXEC as u32,
            0,
            arg2cage,
            arg2cage,
            real_path,
            arg2cage,
            argv1_addr,
            arg2cage,
            arg3,
            arg3cage,
            arg4,
            arg4cage,
            arg5,
            arg5cage,
            arg6,
            arg6cage,
            0,
        ) {
            Ok(r) => return r,
            Err(grate_rs::GrateError::MakeSyscallError(e)) => {
                return e;
            }
            Err(_) => {
                return -1;
            }
        };
    } else {
        // While still building the secondary stack, keep the most recent normal exec as the entry
        // cage for later tee dispatch.
        let phase = with_tee(|s| s.phase);

        match phase {
            TeePhase::Secondary => with_tee(|s| s.secondary_entry = arg1cage),
            _ => {}
        };

        return do_syscall(
            arg1cage,
            SYS_EXEC,
            &[arg1, arg2, arg3, arg4, arg5, arg6],
            &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
    }
}
