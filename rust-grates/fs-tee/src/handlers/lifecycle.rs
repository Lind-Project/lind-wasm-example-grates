use std::collections::HashSet;

use crate::handlers::{FS_CALLS, tee::get_tee_handler};
use crate::tee::*;
use crate::utils::{do_syscall, get_interposition_request};
use grate_rs::{
    SyscallHandler, constants::*, copy_data_between_cages, copy_handler_table_to_cage, getcageid,
    is_thread_clone, make_threei_call, register_handler,
};

pub fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = getcageid();

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
        // (SYS_CLONE, fork_lifecycle_handler),
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
    let child_cage = with_tee(|s| s.fork_return);

    child_cage as i32
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

pub fn register_target_handler(target_cage: u64) {
    let tee_cage = getcageid();

    for fs_syscall in FS_CALLS {
        // let secondary_target = with_tee(|s| s.target);

        let handler = get_tee_handler(fs_syscall).unwrap();

        with_tee(|s| {
            s.tee_routes
                .entry((target_cage, fs_syscall))
                .or_insert(TeeRoute {
                    secondary_alt: None,
                });
        });

        if let Some((secondary_grate, secondary_fn)) =
            get_interposition_request(target_cage, fs_syscall)
        {
            let alt_nr = with_tee(|s| s.alloc_alt());
            with_tee(|s| {
                s.tee_routes
                    .entry((target_cage, fs_syscall))
                    .and_modify(|route| route.secondary_alt = Some(alt_nr));
            });

            do_syscall(
                tee_cage,
                SYS_REGISTER_HANDLER,
                &[tee_cage, 0, secondary_fn, 0, 0, 0],
                &[alt_nr, secondary_grate, 0, 0, 0, 0],
            );
        }

        register_handler(target_cage, fs_syscall, tee_cage, handler).unwrap();
    }

    grate_rs::register_default_fd_handlers_except(
        target_cage,
        tee_cage,
        Some(HashSet::from(FS_CALLS)),
    )
    .unwrap();

    let secondary_top = with_tee(|s| s.secondary_top);
    register_handler(secondary_top, SYS_CLONE, tee_cage, fork_lifecycle_handler).unwrap();
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
            TeePhase::Target => {
                // with_tee(|s| s.target = arg1cage);
                fdtables::init_empty_cage(arg1cage as u64);

                for fd in 0..3 {
                    let _ = fdtables::get_specific_virtual_fd(arg1cage, fd, 1, fd, false, 0);
                }

                copy_handler_table_to_cage(tee_cage, arg1cage).unwrap();

                register_target_handler(arg1cage);

                with_tee(|s| s.target_cage = arg1cage);
            }
            _ => {}
        };
    }

    if path == "%{" {
        match with_tee(|s| s.phase) {
            TeePhase::Secondary => with_tee(|s| s.secondary_top = arg1cage),
            _ => {}
        };
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
                let mut buf = vec![0u8; 256];
                copy_data_between_cages(
                    tee_cage,
                    arg2cage,
                    real_path,
                    arg2cage,
                    buf.as_mut_ptr() as u64,
                    tee_cage,
                    256,
                    0,
                )
                .unwrap();
                let len = buf.iter().position(|&b| b == 0).unwrap_or(256);
                let real_path = String::from_utf8_lossy(&buf[..len]);

                println!("[exec_handler] {:#?} path={:#?}", e, real_path);
                return e;
            }
            Err(e) => {
                println!("[exec_handler] -1 {:#?}", e);
                return -1;
            }
        };
    } else {
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
