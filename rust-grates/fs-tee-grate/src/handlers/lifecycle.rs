use crate::handlers::tee::get_tee_handler;
use crate::tee::*;
use crate::utils::do_syscall;
use grate_rs::SyscallHandler;
use grate_rs::constants::*;
use grate_rs::copy_data_between_cages;
use grate_rs::copy_handler_table_to_cage;
use grate_rs::getcageid;
use grate_rs::make_threei_call;
use grate_rs::register_handler;

pub fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = getcageid();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
        // (SYS_CLONE, fork_handler),
        // (SYS_EXIT, exit_handler),
    ];

    for &(syscall_nr, handler) in handlers {
        if let Err(e) = register_handler(cage_id, syscall_nr, tee_cage, handler) {
            eprintln!(
                "[tee-grate] failed to register lifecycle handler {} on cage {}: {:?}",
                syscall_nr, cage_id, e
            );
        } else {
            println!(
                "[tetrs] registered: {} {} {}",
                cage_id, syscall_nr, tee_cage
            );
        }
    }
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
    println!(
        "[tetrs | register_handler_handler] {} {} {} {}",
        target_cage, syscall_nr, grate_id, fn_ptr
    );

    // Record the interposition.
    with_tee(|s| {
        s.interposition_map
            .push((target_cage, syscall_nr, grate_id, fn_ptr))
    });

    // Performe the interposition.
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

    println!("[tetrs | exec_handler] Path: {}", path);

    // Is path == %} ? Switch phase to next.
    if path == "%}" {
        with_tee(|s| s.phase = s.phase.next());

        let phase = with_tee(|s| s.phase);

        // If secondary: copy_handler_table_to_cage, re-register lifecycle handlers.

        match phase {
            TeePhase::Secondary => {
                println!(
                    "[tetrs | exec_handler] Secondary phase, COPY_HANDLER_TABLE({tee_cage} => {arg1cage})"
                );
                copy_handler_table_to_cage(tee_cage, arg1cage).unwrap();
                register_lifecycle_handlers(arg1cage);
                // Register that primary_target is getcageid();
                with_tee(|s| s.primary_target = arg1cage);
            }
            TeePhase::Target => {
                println!(
                    "[tetrs | exec_handler] Target phase, COPY_HANDLER_TABLE({tee_cage} => {arg1cage})"
                );
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

                // Check map for target == secondary_target.
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

        // return do_syscall(
        //    arg2cage,
        //    SYS_EXEC,
        //    &[real_path, argv1_addr, arg3, arg4, arg5, arg6],
        //    &[arg2cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        //);
    } else {
        println!("\n===== Actual Cage Exec: {path} ========\n");
        return do_syscall(
            arg1cage,
            SYS_EXEC,
            &[arg1, arg2, arg3, arg4, arg5, arg6],
            &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
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
    0
}

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
    0
}
