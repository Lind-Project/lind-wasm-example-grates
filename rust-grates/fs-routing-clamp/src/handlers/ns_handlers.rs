use crate::helpers;
use grate_rs::constants::fs::{F_DUPFD, F_DUPFD_CLOEXEC};
use grate_rs::constants::mman::MAP_ANON;
use grate_rs::{SyscallHandler, constants::*, copy_data_between_cages, getcageid, is_thread_clone};

const AT_FDCWD_U64: u64 = (-100i64) as u64;

fn fd_is_clamped(cage_id: u64, fd: u64) -> bool {
    if fd == AT_FDCWD_U64 {
        return false;
    }

    fdtables::translate_virtual_fd(cage_id, fd)
        .map(|e| e.perfdinfo != 0)
        .unwrap_or(false)
}

fn path_arg_matches(current_cage: u64, path_ptr: u64, path_cage: u64) -> bool {
    helpers::resolve_path_from_cage(current_cage, path_ptr, path_cage)
        .map(|path| helpers::path_matches_prefix(&path))
        .unwrap_or(false)
}

fn at_path_arg_matches(
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    current_cage: u64,
) -> bool {
    let Some(path) = helpers::read_path_from_cage(path_ptr, path_cage) else {
        return false;
    };

    if path.starts_with('/') || dirfd == AT_FDCWD_U64 {
        return helpers::path_matches_prefix(&helpers::resolve_path_for_cage(current_cage, &path));
    }

    fd_is_clamped(dirfd_cage, dirfd)
}

fn dispatch_path_routed(
    calling_cage: u64,
    syscall_nr: u64,
    matches: bool,
    args: &[u64; 6],
    arg_cages: &[u64; 6],
) -> i32 {
    if matches {
        return match helpers::get_route(calling_cage, syscall_nr) {
            Some(alt) => helpers::do_syscall(calling_cage, alt, args, arg_cages),
            None => helpers::do_clamp_syscall(calling_cage, syscall_nr, args, arg_cages),
        };
    }

    helpers::do_syscall(calling_cage, syscall_nr, args, arg_cages)
}
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

            let matches = path_arg_matches(arg2cage, arg1, arg1cage);
            dispatch_path_routed(arg1cage, $sysno, matches, &args, &arg_cages)
        }
    };
}

define_path_handler!(ns_stat_handler, SYS_XSTAT);
define_path_handler!(ns_lstat_handler, SYS_LSTAT);
define_path_handler!(ns_access_handler, SYS_ACCESS);
define_path_handler!(ns_unlink_handler, SYS_UNLINK);
define_path_handler!(ns_mkdir_handler, SYS_MKDIR);
define_path_handler!(ns_rmdir_handler, SYS_RMDIR);
define_path_handler!(ns_truncate_handler, SYS_TRUNCATE);
define_path_handler!(ns_chmod_handler, SYS_CHMOD);
define_path_handler!(ns_chown_handler, SYS_CHOWN);
define_path_handler!(ns_lchown_handler, SYS_LCHOWN);
define_path_handler!(ns_mknod_handler, SYS_MKNOD);
define_path_handler!(ns_readlink_handler, SYS_READLINK);
define_path_handler!(ns_statfs_handler, SYS_STATFS);
define_path_handler!(ns_setxattr_handler, SYS_SETXATTR);
define_path_handler!(ns_listxattr_handler, SYS_LISTXATTR);

macro_rules! define_at_path_handler {
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
            let matches = at_path_arg_matches(arg1, arg1cage, arg2, arg2cage, arg1cage);
            dispatch_path_routed(arg1cage, $sysno, matches, &args, &arg_cages)
        }
    };
}

define_at_path_handler!(ns_fstatat_handler, SYS_NEWFSTATAT);
define_at_path_handler!(ns_statx_handler, SYS_STATX);
define_at_path_handler!(ns_unlinkat_handler, SYS_UNLINKAT);
define_at_path_handler!(ns_readlinkat_handler, SYS_READLINKAT);
define_at_path_handler!(ns_fchmodat_handler, SYS_FCHMODAT);
define_at_path_handler!(ns_faccessat_handler, SYS_FACCESSAT);
define_at_path_handler!(ns_fchownat_handler, SYS_FCHOWNAT);
define_at_path_handler!(ns_utimensat_handler, SYS_UTIMENSAT);

pub extern "C" fn ns_link_handler(
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
    let matches =
        path_arg_matches(arg2cage, arg1, arg1cage) || path_arg_matches(arg2cage, arg2, arg2cage);
    dispatch_path_routed(arg1cage, SYS_LINK, matches, &args, &arg_cages)
}

pub extern "C" fn ns_symlink_handler(
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
    let matches = path_arg_matches(arg2cage, arg2, arg2cage);
    dispatch_path_routed(arg1cage, SYS_SYMLINK, matches, &args, &arg_cages)
}

pub extern "C" fn ns_symlinkat_handler(
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
    let matches = at_path_arg_matches(arg2, arg2cage, arg3, arg3cage, arg2cage);
    dispatch_path_routed(arg2cage, SYS_SYMLINKAT, matches, &args, &arg_cages)
}

pub extern "C" fn ns_rename_handler(
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
    let matches =
        path_arg_matches(arg2cage, arg1, arg1cage) || path_arg_matches(arg2cage, arg2, arg2cage);
    dispatch_path_routed(arg1cage, SYS_RENAME, matches, &args, &arg_cages)
}

fn renameat_impl(
    syscall_nr: u64,
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
    let matches = at_path_arg_matches(arg1, arg1cage, arg2, arg2cage, arg1cage)
        || at_path_arg_matches(arg3, arg3cage, arg4, arg4cage, arg3cage);
    dispatch_path_routed(arg1cage, syscall_nr, matches, &args, &arg_cages)
}

pub extern "C" fn ns_renameat_handler(
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
    let _ = cageid;
    renameat_impl(
        SYS_RENAMEAT,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
    )
}

pub extern "C" fn ns_renameat2_handler(
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
    let _ = cageid;
    renameat_impl(
        SYS_RENAMEAT2,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
    )
}

// =====================================================================
//  SPECIAL PATH-BASED HANDLERS
//
//  These still resolve routing off a pathname, but need extra state
//  management beyond the simple define_path_handler! passthrough.
// =====================================================================

pub extern "C" fn ns_chdir_handler(
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

    let ns_cage = getcageid();
    let mut buf = vec![0u8; 4096];

    match copy_data_between_cages(
        ns_cage,
        arg1cage,
        arg1,
        arg1cage,
        buf.as_mut_ptr() as u64,
        ns_cage,
        4096,
        1,
    ) {
        Ok(_) => {}
        Err(_) => {
            return -14;
        }
    };

    let len = buf.iter().position(|&b| b == 0).unwrap_or(4096);
    let pathstr = match String::from_utf8(buf[..len].to_vec()).ok() {
        Some(v) => v,
        None => {
            return -14;
        }
    };

    let resolved_path: String = helpers::resolve_path_for_cage(arg2cage, &pathstr);

    let matches: bool = helpers::path_matches_prefix(&resolved_path);

    let ret = if matches {
        match helpers::get_route(arg1cage, SYS_CHDIR) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_CHDIR, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_CHDIR, &args, &arg_cages)
    };

    if ret == 0 {
        helpers::set_cage_cwd(arg2cage, resolved_path);
    }

    ret
}

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

            if fdtables::translate_virtual_fd(arg1cage, arg1)
                .map(|e| e.perfdinfo != 0)
                .unwrap_or(false)
            {
                // Clamped path.
                match helpers::get_route(arg1cage, $sysno) {
                    // Clamp entry grate has a handler for this call, invoke that.
                    Some(alt) => {
                        return helpers::do_syscall(arg1cage, alt, &args, &arg_cages);
                    }
                    // Clamp entry grate does not have a handler for this syscall, invoke through
                    // selfcage_id=entrycage
                    None => {
                        return helpers::do_clamp_syscall(arg1cage, $sysno, &args, &arg_cages);
                    }
                };
            }

            helpers::do_syscall(arg1cage, $sysno, &args, &arg_cages)
        }
    };
}

fd_route_handler!(ns_getdents_handler, SYS_GETDENTS);
fd_route_handler!(ns_read_handler, SYS_READ);
fd_route_handler!(ns_write_handler, SYS_WRITE);
fd_route_handler!(ns_pread_handler, SYS_PREAD);
fd_route_handler!(ns_pwrite_handler, SYS_PWRITE);
fd_route_handler!(ns_preadv_handler, SYS_PREADV);
fd_route_handler!(ns_readv_handler, SYS_READV);
fd_route_handler!(ns_writev_handler, SYS_WRITEV);
fd_route_handler!(ns_pwritev_handler, SYS_PWRITEV);
fd_route_handler!(ns_lseek_handler, SYS_LSEEK);
fd_route_handler!(ns_fstat_handler, SYS_FXSTAT);
fd_route_handler!(ns_ftruncate_handler, SYS_FTRUNCATE);
fd_route_handler!(ns_fchmod_handler, SYS_FCHMOD);
fd_route_handler!(ns_fchdir_handler, SYS_FCHDIR);
fd_route_handler!(ns_flock_handler, SYS_FLOCK);
fd_route_handler!(ns_ioctl_handler, SYS_IOCTL);
fd_route_handler!(ns_fsync_handler, SYS_FSYNC);
fd_route_handler!(ns_fdatasync_handler, SYS_FDATASYNC);
fd_route_handler!(ns_fstatfs_handler, SYS_FSTATFS);
fd_route_handler!(ns_sync_file_range_handler, SYS_SYNC_FILE_RANGE);

// =====================================================================
//  SPECIAL FD-BASED HANDLERS
//
//  These route using fdtables state but also update fdtables or maintain
//  additional namespace-grate state as a side effect.
// =====================================================================

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
    let matches = helpers::resolve_path_from_cage(arg2cage, arg1, arg1cage)
        .map(|p| helpers::path_matches_prefix(&p))
        .unwrap_or(false);

    let ret = if matches {
        match helpers::get_route(arg1cage, SYS_OPEN) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_OPEN, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_OPEN, &args, &arg_cages)
    };

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

pub extern "C" fn ns_openat_handler(
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

    let matches = at_path_arg_matches(arg1, arg1cage, arg2, arg2cage, arg1cage);
    let ret = if matches {
        match helpers::get_route(arg1cage, SYS_OPENAT) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_OPENAT, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_OPENAT, &args, &arg_cages)
    };

    if ret >= 0 {
        let clamped = if matches { 1u64 } else { 0 };
        let _ =
            fdtables::get_specific_virtual_fd(arg1cage, ret as u64, 0, ret as u64, false, clamped);
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

    let ret = if is_clamped {
        match helpers::get_route(arg1cage, SYS_CLOSE) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_CLOSE, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_CLOSE, &args, &arg_cages)
    };

    // Always remove the fd from our tracking.
    let _ = fdtables::close_virtualfd(arg1cage, arg1);

    ret
}

/// mmap (syscall 9): map file or anonymous memory.
///
/// Routing decision is based on arg5, the file descriptor.
/// For MAP_ANONYMOUS / MAP_ANON, fd is ignored and should not trigger fd-based routing.
pub extern "C" fn ns_mmap_handler(
    _cageid: u64,
    arg1: u64, // addr
    arg1cage: u64,
    arg2: u64, // length
    arg2cage: u64,
    arg3: u64, // prot
    arg3cage: u64,
    arg4: u64, // flags
    arg4cage: u64,
    arg5: u64, // fd
    arg5cage: u64,
    arg6: u64, // offset
    arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    /*
     * MAP_ANONYMOUS means fd is ignored.
     * Do not route based on fd in that case, because fd may be -1.
     */
    let is_anonymous = (arg4 & MAP_ANON as u64) != 0;

    if !is_anonymous {
        let fd = arg5;

        if fdtables::translate_virtual_fd(arg1cage, fd)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false)
        {
            let ret = match helpers::get_route(arg1cage, SYS_MMAP) {
                Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
                None => helpers::do_clamp_syscall(arg1cage, SYS_MMAP, &args, &arg_cages),
            };
            if ret >= 0 {
                helpers::record_clamped_mmap(arg1cage, ret as u64, arg2);
            }
            return ret;
        }
    }

    helpers::do_syscall(arg1cage, SYS_MMAP, &args, &arg_cages)
}

/// munmap (syscall 11): unmap memory.
///
/// munmap has no fd argument, so fd-based routing is impossible here.
/// Instead, route if the addr/len overlaps a range previously returned by a
/// clamped mmap. This lets clamped grates such as imfs decrement mmap_refs.
pub extern "C" fn ns_munmap_handler(
    _cageid: u64,
    arg1: u64, // addr
    arg1cage: u64,
    arg2: u64, // length
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

    let is_clamped_mapping = helpers::is_clamped_mmap(arg1cage, arg1, arg2);

    if is_clamped_mapping {
        let ret = match helpers::get_route(arg1cage, SYS_MUNMAP) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_MUNMAP, &args, &arg_cages),
        };

        if ret == 0 {
            helpers::remove_clamped_mmap(arg1cage, arg1, arg2);
        }

        return ret;
    }

    helpers::do_syscall(arg1cage, SYS_MUNMAP, &args, &arg_cages)
}

pub extern "C" fn ns_fcntl_handler(
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

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_FCNTL) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_FCNTL, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_FCNTL, &args, &arg_cages)
    };

    if ret >= 0 {
        let cmd = arg2;

        if cmd == F_DUPFD as u64 || cmd == F_DUPFD_CLOEXEC as u64 {
            let cloexec = cmd == F_DUPFD_CLOEXEC as u64;

            let _ = fdtables::get_specific_virtual_fd(
                arg1cage, ret as u64, 0, ret as u64, cloexec, perfdinfo,
            );
        }
    }

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

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP, &args, &arg_cages)
    };

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

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP2) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP2, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP2, &args, &arg_cages)
    };

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

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP3) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP3, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP3, &args, &arg_cages)
    };

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

    let nr = helpers::get_route(arg1cage, SYS_CLONE).unwrap_or(SYS_CLONE);
    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret <= 0 {
        return ret;
    }

    if !is_thread_clone(arg1, arg1cage) {
        let child_cage_id = ret as u64;

        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);
        helpers::clone_cage_routes(arg1cage, child_cage_id);
        helpers::clone_cage_cwd(arg1cage, child_cage_id);
    }

    ret
}

pub extern "C" fn ns_getcwd_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    _arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg1 == 0 {
        return -14;
    }

    let ns_cage = getcageid();

    let cwd = helpers::get_cage_cwd(arg2cage);

    let cwd_bytes = cwd.as_bytes();
    let mut buf = cwd_bytes.to_vec();
    buf.push(0);

    if buf.len() > _arg2 as usize {
        return -34;
    }

    match copy_data_between_cages(
        ns_cage,
        arg1cage,
        buf.as_ptr() as u64,
        ns_cage,
        arg1,
        arg1cage,
        buf.len() as u64,
        0,
    ) {
        Ok(_) => return buf.len() as i32,
        Err(_) => return -14,
    }
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
        // Path-based and path-derived
        SYS_OPEN => Some(ns_open_handler),
        SYS_OPENAT => Some(ns_openat_handler),
        SYS_XSTAT => Some(ns_stat_handler),
        SYS_LSTAT => Some(ns_lstat_handler),
        SYS_NEWFSTATAT => Some(ns_fstatat_handler),
        SYS_STATX => Some(ns_statx_handler),
        SYS_GETCWD => Some(ns_getcwd_handler),
        SYS_ACCESS => Some(ns_access_handler),
        SYS_FACCESSAT => Some(ns_faccessat_handler),
        SYS_UNLINK => Some(ns_unlink_handler),
        SYS_UNLINKAT => Some(ns_unlinkat_handler),
        SYS_LINK => Some(ns_link_handler),
        SYS_SYMLINK => Some(ns_symlink_handler),
        SYS_SYMLINKAT => Some(ns_symlinkat_handler),
        SYS_MKDIR => Some(ns_mkdir_handler),
        SYS_RMDIR => Some(ns_rmdir_handler),
        SYS_RENAME => Some(ns_rename_handler),
        SYS_RENAMEAT => Some(ns_renameat_handler),
        SYS_RENAMEAT2 => Some(ns_renameat2_handler),
        SYS_TRUNCATE => Some(ns_truncate_handler),
        SYS_CHMOD => Some(ns_chmod_handler),
        SYS_FCHMODAT => Some(ns_fchmodat_handler),
        SYS_CHOWN => Some(ns_chown_handler),
        SYS_LCHOWN => Some(ns_lchown_handler),
        SYS_FCHOWNAT => Some(ns_fchownat_handler),
        SYS_CHDIR => Some(ns_chdir_handler),
        SYS_MKNOD => Some(ns_mknod_handler),
        SYS_READLINK => Some(ns_readlink_handler),
        SYS_READLINKAT => Some(ns_readlinkat_handler),
        SYS_STATFS => Some(ns_statfs_handler),
        SYS_SETXATTR => Some(ns_setxattr_handler),
        SYS_LISTXATTR => Some(ns_listxattr_handler),
        SYS_UTIMENSAT => Some(ns_utimensat_handler),
        SYS_GETDENTS => Some(ns_getdents_handler),

        // FD-based
        SYS_READ => Some(ns_read_handler),
        SYS_WRITE => Some(ns_write_handler),
        SYS_CLOSE => Some(ns_close_handler),
        SYS_WRITEV => Some(ns_writev_handler),
        SYS_READV => Some(ns_readv_handler),
        SYS_PREAD => Some(ns_pread_handler),
        SYS_PWRITE => Some(ns_pwrite_handler),
        SYS_PREADV => Some(ns_preadv_handler),
        SYS_PWRITEV => Some(ns_pwritev_handler),
        SYS_LSEEK => Some(ns_lseek_handler),
        SYS_FXSTAT => Some(ns_fstat_handler),
        SYS_FCNTL => Some(ns_fcntl_handler),
        SYS_FTRUNCATE => Some(ns_ftruncate_handler),
        SYS_FCHMOD => Some(ns_fchmod_handler),
        SYS_FCHDIR => Some(ns_fchdir_handler),
        SYS_FLOCK => Some(ns_flock_handler),
        SYS_IOCTL => Some(ns_ioctl_handler),
        SYS_FSYNC => Some(ns_fsync_handler),
        SYS_FDATASYNC => Some(ns_fdatasync_handler),
        SYS_FSTATFS => Some(ns_fstatfs_handler),
        SYS_SYNC_FILE_RANGE => Some(ns_sync_file_range_handler),
        SYS_MMAP => Some(ns_mmap_handler),
        SYS_MUNMAP => Some(ns_munmap_handler),

        // FD-based with fd-tracking side effects
        SYS_DUP => Some(ns_dup_handler),
        SYS_DUP2 => Some(ns_dup2_handler),
        SYS_DUP3 => Some(ns_dup3_handler),

        // Lifecycle — interpose so we track child cages
        SYS_CLONE => Some(ns_clone_handler),
        _ => None,
    }
}
