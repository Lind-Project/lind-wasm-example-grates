use crate::utils::do_syscall;
use crate::tee::*;
use grate_rs::constants::*;
use grate_rs::SyscallHandler;
use grate_rs::ffi::sleep;
use grate_rs::register_handler;
use grate_rs::getcageid;
use grate_rs::copy_data_between_cages;
use grate_rs::ffi::sched_yield;
use crate::handlers::tee::get_tee_handler;

pub fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = with_tee(|s| s.tee_cage_id);

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
        }
    }
}

pub fn register_target_handlers(cage_id: u64) {
    println!("[r-t-h] Actual target={}", cage_id);

    let stack_targets: Vec<u64> = with_tee(|s| {
            [s.primary_target_cage, s.secondary_target_cage]
                .into_iter()
                .flatten()
                .collect()
    });

    let matches: Vec<(u64, u64, u64, u64)> = with_tee(|s| {
        s.interposition_map
            .iter()
            .copied()
            .filter(|(target, _, _, _)| stack_targets.contains(target))
            .collect()
    });

    println!("[r-t-h] matches={:?}", matches);

    let (tee_cage_id, target_cage_id) = with_tee(|s| (s.tee_cage_id, s.target_cage_id));

    for (stack_target, syscall_nr, grate_id, fn_ptr) in matches.iter() {
        let alt_nr = with_tee(|s| s.alloc_alt());
   
        with_tee(|s| {
            let tee_route = s.tee_route.entry((cage_id, *syscall_nr)).or_insert(TeeRoute {
                primary_alt: None,
                secondary_alt: None,
                // tee_handler_registered: false,
            });

            if *stack_target == stack_targets[0] {
                tee_route.primary_alt = Some(alt_nr);
            }

            if *stack_target == stack_targets[1] {
                tee_route.secondary_alt = Some(alt_nr);
            }
        });
        
        println!("[r-t-h] {} {} {} {}", tee_cage_id, alt_nr, *grate_id, *fn_ptr);
        
        do_syscall(
            tee_cage_id, 
            SYS_REGISTER_HANDLER, 
            &[tee_cage_id, 0, *fn_ptr, 0, 0, 0,],
            &[alt_nr, *grate_id, 0, 0, 0, 0,],
        );

        println!("[r-t-h] Alt registration done.");

        // Register to tee-grate instead.
        match get_tee_handler(*syscall_nr) {
            Some(handler) => {
                // println!("[r-t-h] {} {} {}", target_cage_id, *syscall_nr, tee_cage_id);
                register_handler(target_cage_id, *syscall_nr, tee_cage_id, handler).unwrap();
            }, 
            None => {
                println!("[r-t-h] No handler for {}", *syscall_nr);
            }
        };
    }

    // Register exit on this target cage.
    match register_handler(target_cage_id, SYS_EXIT, tee_cage_id, target_exit_handler) {
        Ok(_) => println!("[t-grate] exit registered {} {} {}", target_cage_id, SYS_EXIT, tee_cage_id),
        Err(e) => println!("[t-grate] exit registeration failed: {:#?}", e),
    };
    
    match register_handler(target_cage_id, 231, tee_cage_id, target_exit_handler) {
        Ok(_) => println!("[t-grate] exit_group registered {} {} {}", target_cage_id, 231, tee_cage_id),
        Err(e) => println!("[t-grate] exit_group registeration failed: {:#?}", e),
    };
}

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
    // Push to interposition map.
    // println!("[t-grate] register_handler_handler {} {} {} {}", target_cage, syscall_nr, grate_id, handler_fn_ptr);
    
    if get_tee_handler(syscall_nr).is_some() {
        with_tee(|s| {
            s.interposition_map.push((target_cage, syscall_nr, grate_id, handler_fn_ptr));
        }); 
    }

    return do_syscall(
        grate_id, SYS_REGISTER_HANDLER,
        &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
        &[syscall_nr, grate_id, 0, 0, 0, 0],
    );
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
    let cageid = getcageid();

    let tee_cage = with_tee(|s| s.tee_cage_id);

    let mut buf = vec![0u8; 256];
    if copy_data_between_cages(
        tee_cage, arg1cage,
        arg1, arg1cage,
        buf.as_mut_ptr() as u64, tee_cage,
        256, 0,
    ).is_err() {
        panic!("[tee-grate] Unable to read the execve path");
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(256);
    let path = String::from_utf8_lossy(&buf[..len]);

    // if arg1 == 0x00 {
    if path == "%}" { // == "blk.cwasm" {
        with_tee(|s| {
            // s.stack_targets.push(arg1cage);
            // s.initialized_stacks += 1;

            match s.primary_target_cage {
                Some(_) => s.secondary_target_cage = Some(arg1cage), 
                None => s.primary_target_cage = Some(arg1cage),
            }
        });

        // return do_syscall(
        //    arg1cage, SYS_EXEC, 
        //    &[arg1, arg2, arg3, arg4, arg5, arg6,], 
        //    &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,], 
        // );

        loop {
            unsafe { sleep(10) };

            let exited = with_tee(|s| s.exiting);
            if exited {
                println!("[exec] cageid={} exiting={}", arg1cage, exited);
                return 0;
            }
        }
    } else {
        return do_syscall(
            arg1cage, SYS_EXEC,
            &[arg1, arg2, arg3, arg4, arg5, arg6],
            &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
    }
}

pub extern "C" fn target_exit_handler(
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
    let stack_targets: Vec<u64> = with_tee(|s| {
            [s.primary_target_cage, s.secondary_target_cage]
                .into_iter()
                .flatten()
                .collect()
    });


    println!("[t-grate | target-exit-handler] {} {} {} {} {} {}", arg1, arg2, arg3, arg4, arg5, arg6);

    println!("[t-grate | target-exit-handler] {} {} {} {} {} {}", arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage);
    
    println!("[t-grate | target-exit-handler] target_cage={} primary_stack_target={} secondary_stack_target={}", 
    arg1cage, stack_targets[0], stack_targets[1]);

    let return_value = do_syscall(arg1cage, 231, &[arg1, arg2, arg3, arg4, arg5, arg6,], &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,]);

    // Quit the stack targets.
    do_syscall(stack_targets[0], 231, &[arg1, 1, arg3, arg4, arg5, arg6,], &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,]);
    do_syscall(stack_targets[1], 231, &[arg1, 1, arg3, arg4, arg5, arg6,], &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage,]);


    with_tee(|s| s.exiting = true);
  
    // Quit self cage.
    return_value
}
