use crate::handlers::tee::get_tee_handler;
use crate::tee::*;
use crate::utils::do_syscall;
use grate_rs::{
    SyscallHandler, constants::*, copy_data_between_cages, copy_handler_table_to_cage, getcageid,
    is_thread_clone, make_threei_call, register_handler,
};

pub fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = getcageid();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
        (SYS_CLONE, fork_handler),
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
    let child_cage_id = do_syscall(arg1cage, SYS_CLONE, &args, &arg_cages) as u64;

    if !is_thread_clone(arg1, arg1cage) {
        // Copy the fd table so the child knows which fds are clamped.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);

        // Register our lifecycle handlers on the child so we can track it.
        // register_lifecycle_handlers(child_cage_id);
    }

    child_cage_id as i32
}

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
    // Record the interposition.
    //
    // This map is used to later re-write handlers from perceived targetcageid from primary and
    // secondary stacks' perspectives to the actual target cageid.
    with_tee(|s| {
        s.interposition_map
            .push((target_cage, syscall_nr, grate_id, fn_ptr))
    });

    // Perform the interposition. We don't want to interfere within interpositions within primary
    // and secondary stacks. For calls that cross the boundary, these are overwritten later in exec
    // through copy_handler_table.
    return do_syscall(
        grate_id,
        SYS_REGISTER_HANDLER,
        &[target_cage, _arg2, fn_ptr, _arg4, _arg5, _arg6],
        &[
            syscall_nr, grate_id, _arg3cage, _arg4cage, _arg5cage, _arg6cage,
        ],
    );
}

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
    // Step 0. Copy path to grate.
    //
    // Step 1.1 If path is %}, move to the next phase (Primary -> Secondary -> Target)
    //
    // Step 1.2 If path is %} and in Secondary phase, we are about to start the secondary stack on
    // this cage, use copy_handler_table to reset this cage to act like the child of the
    // fs-tee-grate, and then register lifecycle handlers.
    //
    // Step 1.3 If path is %} and in Target phase, make this the child of fs-tee-grate, read
    // interposition_map to populate tee_routes.
    //
    // Step 2. If path is %{ or %}, shift args and call recursively.
    //
    // Step 3. If none of these match, carry on.

    // Copy path to grate.
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

    // Is path == %} ? Switch phase to next.
    if path == "%}" {
        with_tee(|s| s.phase = s.phase.next());

        let phase = with_tee(|s| s.phase);

        match phase {
            TeePhase::Secondary => {
                copy_handler_table_to_cage(tee_cage, arg1cage).unwrap();
                register_lifecycle_handlers(arg1cage);

                // Register that this cageid is what primary stack assumes to be the target cageid.
                with_tee(|s| s.primary_target = arg1cage);
            }
            TeePhase::Target => {
                fdtables::init_empty_cage(arg1cage as u64);
                for _fd in 0..3 {
                    let _ = fdtables::get_unused_virtual_fd(
                        arg1cage, 1,
                        _fd, // underfd: which FD to use for secondary grate chain.
                        false, 0,
                    );
                }

                copy_handler_table_to_cage(tee_cage, arg1cage).unwrap();
                // Check interposition map for target == primary_target.
                let primary_registers: Vec<(u64, u64, u64, u64)> = with_tee(|s| {
                    s.interposition_map
                        .iter()
                        .copied()
                        .filter(|(target_cage, _, _, _)| *target_cage == s.primary_target)
                        .collect()
                });

                for (_target, syscall, grate, func) in primary_registers {
                    if get_tee_handler(syscall).is_none() {
                        continue;
                    }

                    let handler = get_tee_handler(syscall).unwrap();

                    // Allocate alternate syscall number.
                    let alt_nr = with_tee(|s| s.alloc_alt());

                    // Insert into tee_routes (arg1cage, syscallnumber)'s primary_alt
                    with_tee(|s| {
                        let tee_route =
                            s.tee_routes.entry((arg1cage, syscall)).or_insert(TeeRoute {
                                primary_alt: Some(alt_nr),
                                secondary_alt: None,
                            });

                        tee_route.primary_alt = Some(alt_nr);
                    });

                    do_syscall(
                        tee_cage,
                        SYS_REGISTER_HANDLER,
                        &[tee_cage, 0, func, 0, 0, 0],
                        &[alt_nr, grate, 0, 0, 0, 0],
                    );

                    // Register to tee_grate.
                    register_handler(arg1cage, syscall, tee_cage, handler).unwrap();
                }

                // Check map for target == secondary_target (which is arg1cage).
                let secondary_registers: Vec<(u64, u64, u64, u64)> = with_tee(|s| {
                    s.interposition_map
                        .iter()
                        .copied()
                        .filter(|(target_cage, _, _, _)| *target_cage == arg1cage)
                        .collect()
                });

                for (_target, syscall, grate, func) in secondary_registers {
                    if get_tee_handler(syscall).is_none() {
                        continue;
                    }

                    let handler = get_tee_handler(syscall).unwrap();

                    // Allocate alternate syscall number.
                    let alt_nr = with_tee(|s| s.alloc_alt());

                    // Insert into tee_routes (arg1cage, syscallnumber)'s primary_alt
                    with_tee(|s| {
                        let _tee_route = s
                            .tee_routes
                            .entry((arg1cage, syscall))
                            .and_modify(|v| v.secondary_alt = Some(alt_nr));
                    });

                    do_syscall(
                        tee_cage,
                        SYS_REGISTER_HANDLER,
                        &[tee_cage, 0, func, 0, 0, 0],
                        &[alt_nr, grate, 0, 0, 0, 0],
                    );

                    // Register to tee_grate.
                    register_handler(arg1cage, syscall, tee_cage, handler).unwrap();
                }
            }
            _ => {}
        }
    }

    // If path == %} or %{ shift args left continue.
    if path == "%}" || path == "%{" {
        const PTR_SIZE: usize = 8;

        // This stores the value in argv[1]
        let mut real_ptr = [0u8; PTR_SIZE];

        // Address to argv[1]
        let argv1_addr = arg2 + PTR_SIZE as u64;

        // Copy argv[1] into real_ptr
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

        // Convert real_ptr bytes to address.
        let real_path = u64::from_le_bytes(real_ptr) as u64;

        // Call exec with updated arguments.
        return make_threei_call(
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
        )
        .unwrap();
    } else {
        return do_syscall(
            arg1cage,
            SYS_EXEC,
            &[arg1, arg2, arg3, arg4, arg5, arg6],
            &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
    }
}
