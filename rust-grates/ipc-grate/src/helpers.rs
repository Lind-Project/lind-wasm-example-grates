//! Shared helpers for the IPC grate.

use grate_rs::{GrateError, getcageid, make_threei_call};

/// Forward a syscall to the next handler via make_threei_call.
///
/// Pass `translate_errno=0` so the lower layer returns its raw negative
/// errno (e.g. -ENOENT) instead of -1.  We then surface that errno
/// directly to the caller — callers like initdb branch on `errno ==
/// ENOENT` and a collapsed -1/-EPERM masks the real condition.
pub fn forward_syscall(
    nr: u64, calling_cage: u64,
    args: &[u64; 6], arg_cages: &[u64; 6],
) -> i32 {
    let grate_cage = getcageid();
    match make_threei_call(
        nr as u32, 0, grate_cage, calling_cage,
        args[0], arg_cages[0], args[1], arg_cages[1], args[2], arg_cages[2],
        args[3], arg_cages[3], args[4], arg_cages[4], args[5], arg_cages[5], 0,
    ) {
        Ok(r) => r,
        Err(GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    }
}
