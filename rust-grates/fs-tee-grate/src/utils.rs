use grate_rs::{
    constants::{SYS_PWRITE, SYS_PWRITEV, SYS_WRITE, SYS_WRITEV},
    getcageid, make_threei_call,
};

use crate::tee::{with_tee, TeeRoute};

/// Copy all tee routes from a parent cage to its child after fork.
pub fn copy_route_table(source_cage: u64, target_cage: u64) {
    with_tee(|s| {
        let parent_routes: Vec<(u64, TeeRoute)> = s
            .tee_routes
            .iter()
            .filter_map(|((cid, nr), route)| {
                if *cid == source_cage {
                    Some((*nr, route.clone()))
                } else {
                    None
                }
            })
            .collect();

        for (nr, route) in parent_routes {
            s.tee_routes.insert((target_cage, nr), route);
        }
    });
}

/// Look up the `(grate_id, handler_fn_ptr)` recorded for a target cage and syscall.
pub fn get_interposition_request(target_cage: u64, fs_syscall: u64) -> Option<(u64, u64)> {
    with_tee(|s| {
        s.interposition_map
            .iter()
            .find(|(child_cage, syscall_number, _, _)| {
                *child_cage == target_cage && *syscall_number == fs_syscall
            })
            .map(|(_, _, grate_id, handler_fn)| (*grate_id, *handler_fn))
    })
}

/// Perform a syscall with `self_cageid` set to the tee grate's cage.
///
/// This is the normal path for alternate syscalls registered by fs-tee.
pub fn do_syscall(calling_cage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let tee_cage = getcageid();
    match make_threei_call(
        nr as u32,
        0,
        tee_cage,
        calling_cage,
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(grate_rs::GrateError::MakeSyscallError(ret)) => ret,
        Err(_) => -1,
    }
}

/// Perform a syscall with a custom `self_cageid`.
///
/// This is used when the secondary entry cage did not interpose on a syscall, so fs-tee has no
/// alternate syscall number registered for it.
pub fn do_tee_syscall(
    self_cage: u64,
    calling_cage: u64,
    nr: u64,
    args: &[u64; 6],
    arg_cages: &[u64; 6],
) -> i32 {
    match make_threei_call(
        nr as u32,
        0,
        self_cage,
        calling_cage,
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(grate_rs::GrateError::MakeSyscallError(ret)) => ret,
        Err(_) => -1,
    }
}

/// Detect whether a syscall is writing to stdout or stderr for the target cage.
pub fn is_tty(syscall_number: u64, cage_id: u64, arg1: u64) -> bool {
    [SYS_WRITE, SYS_PWRITE, SYS_WRITEV, SYS_PWRITEV].contains(&syscall_number)
        && cage_id == with_tee(|s| s.target_cage)
        && arg1 < 3
}

/// Write a formatted line to fs-tee's secondary log file.
#[macro_export]
macro_rules! secondary_log {
    ($($arg:tt)*) => {
        use std::ffi::c_void;

        let fd = with_tee(|s| s.secondary_log_fd);
        let msg = format!("[fs-tee] {}\n", format_args!($($arg)*));

        unsafe {
            libc::write(
                fd,
                msg.as_ptr() as *const c_void,
                msg.len(),
            )
        };

    };
}
