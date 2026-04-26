use crate::helpers;
use crate::handlers::clamped_lifecycle::register_lifecycle_handlers;
use grate_rs::{SyscallHandler, constants::*, is_thread_clone};

// =====================================================================
//  PATH-BASED SYSCALL HANDLERS
//
//  These handle syscalls where arg1 is a pointer to a path string in the
//  calling cage's memory. The handler reads the path, checks if it starts
//  with the clamped prefix, and either:
//    - Routes to the alt syscall (prefix matches → clamped grate handles it)
//    - Passes through to kernel (no match → kernel handles it)
// =====================================================================
macro_rules! define_path_handler {
    ($name:ident, $sysno:expr) => {
        pub extern "C" fn $name(
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

            let nr = match helpers::get_route(arg1cage, $sysno) {
                Some(alt) => match helpers::read_path_from_cage(arg1, arg1cage) {
                    Some(path) if helpers::path_matches_prefix(&path) => alt,
                    _ => $sysno,
                },
                None => $sysno,
            };

            helpers::do_syscall(arg1cage, nr, &args, &arg_cages)
        }
    };
}

define_path_handler!(ns_stat_handler, SYS_XSTAT);
define_path_handler!(ns_access_handler, SYS_ACCESS);
define_path_handler!(ns_unlink_handler, SYS_UNLINK);
define_path_handler!(ns_mkdir_handler, SYS_MKDIR);
define_path_handler!(ns_rmdir_handler, SYS_RMDIR);
define_path_handler!(ns_rename_handler, SYS_RENAME);
define_path_handler!(ns_truncate_handler, SYS_TRUNCATE);
define_path_handler!(ns_chmod_handler, SYS_CHMOD);
define_path_handler!(ns_chdir_handler, SYS_CHDIR);
define_path_handler!(ns_readlink_handler, SYS_READLINK);
define_path_handler!(ns_unlinkat_handler, SYS_UNLINKAT);
define_path_handler!(ns_readlinkat_handler, SYS_READLINKAT);

// =====================================================================
//  FD-BASED SYSCALL HANDLERS
//
//  These handle syscalls where arg1 is a file descriptor. The handler
//  checks fdtables to see if the fd was opened under the clamped prefix
//  (perfdinfo == 1). If so, it routes to the clamped grate via the alt
//  syscall. Otherwise it passes through to kernel.
//
//  Some handlers (open, close, dup) also update fdtables as a side effect.
// =====================================================================

macro_rules! fd_route_handler {
    ($name:ident, $sysno:expr) => {
        pub extern "C" fn $name(
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

            let nr = match helpers::get_route(arg1cage, $sysno) {
                Some(alt)
                    if fdtables::translate_virtual_fd(arg1cage, arg1)
                        .map(|e| e.perfdinfo != 0)
                        .unwrap_or(false) =>
                {
                    alt
                }
                _ => $sysno,
            };

            helpers::do_syscall(arg1cage, nr, &args, &arg_cages)
        }
    };
}

fd_route_handler!(ns_read_handler, SYS_READ);
fd_route_handler!(ns_write_handler, SYS_WRITE);
fd_route_handler!(ns_pread_handler, SYS_PREAD);
fd_route_handler!(ns_pwrite_handler, SYS_PWRITE);
fd_route_handler!(ns_lseek_handler, SYS_LSEEK);
fd_route_handler!(ns_fstat_handler, SYS_FXSTAT);
fd_route_handler!(ns_fcntl_handler, SYS_FCNTL);
fd_route_handler!(ns_ftruncate_handler, SYS_FTRUNCATE);
fd_route_handler!(ns_fchmod_handler, SYS_FCHMOD);
fd_route_handler!(ns_readv_handler, SYS_READV);
fd_route_handler!(ns_writev_handler, SYS_WRITEV);

/// open (syscall 2): open a file by path.
///
/// This is both path-based (checks prefix) AND updates fdtables:
/// after a successful open, records the new fd with perfdinfo=1 if the
/// path matched the prefix, or perfdinfo=0 if it didn't.
pub extern "C" fn ns_open_handler(
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

    // Check if the path matches the clamped prefix.
    let matches = helpers::read_path_from_cage(arg1, arg1cage)
        .map(|p| helpers::path_matches_prefix(&p))
        .unwrap_or(false);

    // Route to alt if prefix matches, otherwise passthrough.
    let nr = match helpers::get_route(arg1cage, SYS_OPEN) {
        Some(alt) if matches => alt,
        _ => SYS_OPEN,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // On success, record the fd in fdtables with the clamped flag.
    // perfdinfo=1 means "this fd was opened under the clamped prefix."
    if ret >= 0 {
        let clamped = if matches { 1u64 } else { 0 };
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, // virtual fd = the returned fd
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

    // Check if this fd is clamped (perfdinfo != 0).
    let is_clamped = fdtables::translate_virtual_fd(arg1cage, arg1)
        .map(|e| e.perfdinfo != 0)
        .unwrap_or(false);

    let nr = match helpers::get_route(arg1cage, SYS_CLOSE) {
        Some(alt) if is_clamped => alt,
        _ => SYS_CLOSE,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // Always remove the fd from our tracking.
    let _ = fdtables::close_virtualfd(arg1cage, arg1);

    ret
}

/// dup (syscall 32): duplicate a file descriptor.
///
/// Routes based on fdtables, then copies the perfdinfo to the new fd.
pub extern "C" fn ns_dup_handler(
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

    // Look up the old fd's clamped status before dispatching.
    let perfdinfo = fdtables::translate_virtual_fd(arg1cage, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(arg1cage, SYS_DUP) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // On success, record the new fd with the same clamped status as the old one.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, perfdinfo,
        );
    }

    ret
}

/// dup2 (syscall 33): duplicate fd to a specific target fd.
///
/// Routes based on fdtables, then copies perfdinfo to the target fd.
pub extern "C" fn ns_dup2_handler(
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

    let perfdinfo = fdtables::translate_virtual_fd(arg1cage, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(arg1cage, SYS_DUP2) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP2,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // arg2 is the target fd for dup2.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(arg1cage, arg2, 0, arg2, false, perfdinfo);
    }

    ret
}

/// dup3 (syscall 292): duplicate fd to a specific target fd with flags.
///
/// Same as dup2 but with an additional flags argument (arg3).
pub extern "C" fn ns_dup3_handler(
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

    let perfdinfo = fdtables::translate_virtual_fd(arg1cage, arg1)
        .map(|e| e.perfdinfo)
        .unwrap_or(0);

    let nr = match helpers::get_route(arg1cage, SYS_DUP3) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP3,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // arg2 is the target fd for dup3.
    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(arg1cage, arg2, 0, arg2, false, perfdinfo);
    }

    ret
}

// =====================================================================
//  CLONE — route through alt + lifecycle bookkeeping
// =====================================================================

/// clone/fork: route through the clamped grate's handler (alt), then
/// register lifecycle handlers and init fdtables on the child cage.
pub extern "C" fn ns_clone_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let nr = helpers::get_route(arg1cage, SYS_CLONE).unwrap_or(SYS_CLONE);
    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret <= 0 {
        return ret;
    }

    if !is_thread_clone(arg1, arg1cage) {
        let child_cage_id = ret as u64;

        // Route cloning only — fdtables copy is handled by the lifecycle
        // fork_handler to avoid double-init when inner grates also handle fork.
        helpers::clone_cage_routes(arg1cage, child_cage_id);

        register_lifecycle_handlers(child_cage_id);
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
        SYS_OPEN => Some(ns_open_handler),
        SYS_XSTAT => Some(ns_stat_handler),
        SYS_ACCESS => Some(ns_access_handler),
        SYS_UNLINK => Some(ns_unlink_handler),
        SYS_MKDIR => Some(ns_mkdir_handler),
        SYS_RMDIR => Some(ns_rmdir_handler),
        SYS_RENAME => Some(ns_rename_handler),
        SYS_TRUNCATE => Some(ns_truncate_handler),
        SYS_CHMOD => Some(ns_chmod_handler),
        SYS_CHDIR => Some(ns_chdir_handler),
        SYS_READLINK => Some(ns_readlink_handler),
        SYS_UNLINKAT => Some(ns_unlinkat_handler),
        SYS_READLINKAT => Some(ns_readlinkat_handler),

        // FD-based
        SYS_READ => Some(ns_read_handler),
        SYS_WRITE => Some(ns_write_handler),
        SYS_CLOSE => Some(ns_close_handler),
        SYS_PREAD => Some(ns_pread_handler),
        SYS_PWRITE => Some(ns_pwrite_handler),
        SYS_LSEEK => Some(ns_lseek_handler),
        SYS_FXSTAT => Some(ns_fstat_handler),
        SYS_FCNTL => Some(ns_fcntl_handler),
        SYS_FTRUNCATE => Some(ns_ftruncate_handler),
        SYS_FCHMOD => Some(ns_fchmod_handler),
        SYS_READV => Some(ns_readv_handler),
        SYS_WRITEV => Some(ns_writev_handler),

        // FD-based with fd-tracking side effects
        SYS_DUP => Some(ns_dup_handler),
        SYS_DUP2 => Some(ns_dup2_handler),
        SYS_DUP3 => Some(ns_dup3_handler),

        // Lifecycle — interpose so we track child cages
        SYS_CLONE => Some(ns_clone_handler),

        _ => None,
    }
}
