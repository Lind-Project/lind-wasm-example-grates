use crate::helpers;
use grate_rs::{SyscallHandler, constants::*, copy_data_between_cages, getcageid, is_thread_clone};
use grate_rs::constants::fs::{F_DUPFD, F_DUPFD_CLOEXEC, FD_CLOEXEC, O_CLOEXEC, F_SETFD};
use grate_rs::constants::mman::MAP_ANON;
use grate_rs::constants::error::{EAGAIN, EBADF, EMFILE, EINVAL};
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
                Some(alt) => match helpers::resolve_path_from_cage(arg2cage, arg1, arg1cage) {
                    Some(path) if helpers::path_matches_prefix(&path) => alt,
                    _ => $sysno,
                },
                None => $sysno,
            };

            let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);
            let path = helpers::read_path_from_cage(arg1, arg1cage).unwrap_or_default();

            // println!(
            //     "[ns_handlers|{}] cageid={} path={} routed_to={} ret={}",
            //     stringify!($name),
            //     arg1cage,
            //     path,
            //     if nr == $sysno { "kernel" } else { "clamped grate" },
            //     ret,
            // );
            ret
        }
    };
}

define_path_handler!(ns_stat_handler, SYS_XSTAT);
define_path_handler!(ns_access_handler, SYS_ACCESS);
define_path_handler!(ns_unlink_handler, SYS_UNLINK);
define_path_handler!(ns_link_handler, SYS_LINK);
define_path_handler!(ns_mkdir_handler, SYS_MKDIR);
define_path_handler!(ns_rmdir_handler, SYS_RMDIR);
define_path_handler!(ns_rename_handler, SYS_RENAME);
define_path_handler!(ns_truncate_handler, SYS_TRUNCATE);
define_path_handler!(ns_chmod_handler, SYS_CHMOD);
define_path_handler!(ns_mknod_handler, SYS_MKNOD);
define_path_handler!(ns_readlink_handler, SYS_READLINK);
define_path_handler!(ns_unlinkat_handler, SYS_UNLINKAT);
define_path_handler!(ns_readlinkat_handler, SYS_READLINKAT);
define_path_handler!(ns_statfs_handler, SYS_STATFS);

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

    let nr = match helpers::get_route(arg1cage, SYS_CHDIR) {
        Some(alt) if matches => alt,
        _ => SYS_CHDIR,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret == 0 {
        helpers::set_cage_cwd(arg2cage, resolved_path.clone());
    }

    // println!(
    //     "[ns_handlers|chdir] cageid={} path={} resolved_path={} clamped={} routed_to={} ret={}",
    //     arg1cage,
    //     pathstr,
    //     resolved_path,
    //     if matches { "clamped grate" } else { "kernel" },
    //     if nr == SYS_CHDIR { "kernel" } else { "clamped grate" },
    //     ret,
    // );
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

fn do_routed_underfd_syscall(
    cageid: u64,
    sysno: u64,
    args: &[u64; 6],
    arg_cages: &[u64; 6],
    is_clamped: bool,
) -> i32 {
    if is_clamped {
        match helpers::get_route(cageid, sysno) {
            Some(alt) => helpers::do_syscall(cageid, alt, args, arg_cages),
            None => helpers::do_clamp_syscall(cageid, sysno, args, arg_cages),
        }
    } else {
        helpers::do_syscall(cageid, sysno, args, arg_cages)
    }
}

fn close_underfd(cageid: u64, underfd: u64, is_clamped: bool) -> i32 {
    let close_args = [underfd, 0, 0, 0, 0, 0];
    let close_cages = [cageid; 6];
    do_routed_underfd_syscall(cageid, SYS_CLOSE, &close_args, &close_cages, is_clamped)
}

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
            let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
                Ok(entry) => entry,
                Err(_) => {
                    // println!(
                    //     "[ns_handlers|{}] cageid={} fd={} invalid virtual fd, ret=EBADF",
                    //     stringify!($name),
                    //     arg1cage,
                    //     arg1,
                    // );
                    return -(EBADF as i32);
                }
            };

            let perfdinfo = old_fd_entry.perfdinfo != 0;

            args[0] = old_fd_entry.underfd; // replace virtual fd with underfd for the syscall
            
            if perfdinfo {
                
                // Clamped path.
                match helpers::get_route(arg1cage, $sysno) {
                    // Clamp entry grate has a handler for this call, invoke that.
                    Some(alt) => {
                        let ret = helpers::do_syscall(arg1cage, alt, &args, &arg_cages);
                        if ret == -(EAGAIN as i32) {
                            eprintln!(
                                "[fs-routing-clamp|fd-route|EAGAIN] handler={} sys={} cage={} vfd={} underfd={} fdkind={} perfdinfo={} route=clamped-alt alt={}",
                                stringify!($name),
                                $sysno,
                                arg1cage,
                                arg1,
                                old_fd_entry.underfd,
                                old_fd_entry.fdkind,
                                old_fd_entry.perfdinfo,
                                alt,
                            );
                        }
                        // println!(
                        //     "[ns_handlers|{}] cageid={} fd={} underfd={} clamped=clamped grate routed_to=clamped grate ret={}",
                        //     stringify!($name),
                        //     arg1cage,
                        //     arg1,
                        //     old_fd_entry.underfd,
                        //     ret,
                        // );
                        return ret;
                    }
                    // Clamp entry grate does not have a handler for this syscall, invoke through
                    // selfcage_id=entrycage
                    None => {
                        let ret = helpers::do_clamp_syscall(arg1cage, $sysno, &args, &arg_cages);
                        if ret == -(EAGAIN as i32) {
                            eprintln!(
                                "[fs-routing-clamp|fd-route|EAGAIN] handler={} sys={} cage={} vfd={} underfd={} fdkind={} perfdinfo={} route=clamped-raw",
                                stringify!($name),
                                $sysno,
                                arg1cage,
                                arg1,
                                old_fd_entry.underfd,
                                old_fd_entry.fdkind,
                                old_fd_entry.perfdinfo,
                            );
                        }
                        // println!(
                        //     "[ns_handlers|{}] cageid={} fd={} underfd={} clamped=clamped grate routed_to=kernel ret={}",
                        //     stringify!($name),
                        //     arg1cage,
                        //     arg1,
                        //     old_fd_entry.underfd,
                        //     ret,
                        // );
                        return ret;
                    }
                };
            }

            let ret = helpers::do_syscall(arg1cage, $sysno, &args, &arg_cages);
            if ret == -(EAGAIN as i32) {
                eprintln!(
                    "[fs-routing-clamp|fd-route|EAGAIN] handler={} sys={} cage={} vfd={} underfd={} fdkind={} perfdinfo={} route=raw",
                    stringify!($name),
                    $sysno,
                    arg1cage,
                    arg1,
                    old_fd_entry.underfd,
                    old_fd_entry.fdkind,
                    old_fd_entry.perfdinfo,
                );
            }

            // println!(
            //     "[ns_handlers|{}] cageid={} fd={} underfd={} clamped={} routed_to={} ret={}",
            //     stringify!($name),
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo { "clamped grate" } else { "kernel" },
            //     match helpers::get_route(arg1cage, $sysno) {
            //         Some(alt) if perfdinfo => "clamped grate",
            //         _ => "kernel",
            //     },
            //     ret,
            // );
            
            ret
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

    // Check if the path matches the clamped prefix.
    let matches = helpers::resolve_path_from_cage(arg2cage, arg1, arg1cage)
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
        match fdtables::get_unused_virtual_fd(
            arg1cage,
            0,          // fdkind (unused)
            ret as u64, // underfd = same (identity mapping)
            false, // should_cloexec
            clamped, // perfdinfo: 1=clamped, 0=not
        ) {
            Ok(vfd) => {
                // println!("[ns_handlers|open] cageid={} path={} underfd={} clamped={} virtualfd={}",
                //     arg1cage,
                //     helpers::read_path_from_cage(arg1, arg1cage).unwrap_or_default(),
                //     ret,
                //     if clamped != 0 { "clamped grate" } else { "kernel" },
                //     vfd,
                // );
                return vfd as i32;
            }
            Err(_) => {
                let _ = close_underfd(arg1cage, ret as u64, clamped != 0);
                return -(EMFILE as i32);
            }
        };
    }

    ret
}

/// close (syscall 3): close a file descriptor.
///
/// Routes based on fdtables (is this fd clamped?), then removes the fd
/// from fdtables regardless of the result.
pub extern "C" fn ns_close_handler(
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
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let mut arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
        Ok(entry) => entry,
        Err(_) => {
            // println!(
            //     "[ns_handlers|close] fd={} invalid virtual fd, ret=EBADF",
            //     arg1,
            // );
            return -(EBADF as i32);
        }
    };

    let is_clamped = old_fd_entry.perfdinfo != 0;

    args[0] = old_fd_entry.underfd; // replace virtual fd with underfd for the syscall

    let ret = do_routed_underfd_syscall(arg1cage, SYS_CLOSE, &args, &arg_cages, is_clamped);

    if ret >= 0 {
        let _ = fdtables::close_virtualfd(arg1cage, arg1);
    }

    // println!(
    //     "[ns_handlers|close] cageid={} fd={} underfd={} clamped={} ret={}",
    //     arg1cage,
    //     arg1,
    //     old_fd_entry.underfd,
    //     if is_clamped { "clamped grate" } else { "kernel" },
    //     ret,
    // );
    ret
}

/// mmap (syscall 9): map file or anonymous memory.
///
/// Routing decision is based on arg5, the file descriptor.
/// For MAP_ANONYMOUS / MAP_ANON, fd is ignored and should not trigger fd-based routing.
pub extern "C" fn ns_mmap_handler(
    _cageid: u64,
    arg1: u64,      // addr
    arg1cage: u64,
    arg2: u64,      // length
    arg2cage: u64,
    arg3: u64,      // prot
    arg3cage: u64,
    arg4: u64,      // flags
    arg4cage: u64,
    arg5: u64,      // fd
    arg5cage: u64,
    arg6: u64,      // offset
    arg6cage: u64,
) -> i32 {
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    /*
     * MAP_ANONYMOUS means fd is ignored.
     * Do not route based on fd in that case, because fd may be -1.
     */
    let is_anonymous = (arg4 & MAP_ANON as u64) != 0;
    let caller_cage = if is_anonymous { arg2cage } else { arg5cage };

    let mut fd = arg5;
    if !is_anonymous {
        let old_fd_entry = match fdtables::translate_virtual_fd(caller_cage, fd) {
            Ok(entry) => entry,
            Err(_) => {
                return -(EBADF as i32);
            }
        };

        let perfdinfo = old_fd_entry.perfdinfo;

        args[4] = old_fd_entry.underfd; // replace virtual fd with underfd for the syscall
        
        if perfdinfo != 0 {
            let ret = match helpers::get_route(caller_cage, SYS_MMAP) {
                Some(alt) => helpers::do_syscall(caller_cage, alt, &args, &arg_cages),
                None => helpers::do_clamp_syscall(caller_cage, SYS_MMAP, &args, &arg_cages),
            };
            if ret >= 0 || ret <= -256 {
                helpers::record_clamped_mmap(caller_cage, ret as u32 as u64, arg2);
            }
            return ret;
        }
    }

    let ret = helpers::do_syscall(caller_cage, SYS_MMAP, &args, &arg_cages);

    if ret != -1 && !is_anonymous {
        args[4] = fd; // restore original fd in args
    }

    ret
}

/// munmap (syscall 11): unmap memory.
///
/// munmap has no fd argument, so fd-based routing is impossible here.
/// Instead, route if the addr/len overlaps a range previously returned by a
/// clamped mmap. This lets clamped grates such as imfs decrement mmap_refs.
pub extern "C" fn ns_munmap_handler(
    _cageid: u64,
    arg1: u64,      // addr
    arg1cage: u64,
    arg2: u64,      // length
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
    let caller_cage = arg2cage;

    let is_clamped_mapping = helpers::is_clamped_mmap(caller_cage, arg1, arg2);

    if let Some(alt) = helpers::get_route(caller_cage, SYS_MUNMAP) {
        let ret = helpers::do_syscall(caller_cage, alt, &args, &arg_cages);

        if ret == 0 && is_clamped_mapping {
            helpers::remove_clamped_mmap(caller_cage, arg1, arg2);
        }

        return ret;
    }

    if is_clamped_mapping {
        let ret = helpers::do_clamp_syscall(caller_cage, SYS_MUNMAP, &args, &arg_cages);

        if ret == 0 {
            helpers::remove_clamped_mmap(caller_cage, arg1, arg2);
        }

        return ret;
    }

    helpers::do_syscall(caller_cage, SYS_MUNMAP, &args, &arg_cages)
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
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let mut arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
        Ok(entry) => entry,
        Err(_) => {
            // println!(
            //     "[ns_handlers|fcntl] cageid={} fd={} invalid virtual fd, ret=EBADF",
            //     arg1cage,
            //     arg1,
            // );
            return -(EBADF as i32);
        }
    };

    let perfdinfo = old_fd_entry.perfdinfo;

    args[0] = old_fd_entry.underfd; // replace virtual fd with underfd for the syscall
    // arg_cages[0] = cageid;

    let ret = do_routed_underfd_syscall(
        arg1cage,
        SYS_FCNTL,
        &args,
        &arg_cages,
        perfdinfo != 0,
    );

    if ret >= 0 {
        let cmd = arg2;

        if cmd == F_DUPFD as u64 || cmd == F_DUPFD_CLOEXEC as u64 {
            let cloexec = cmd == F_DUPFD_CLOEXEC as u64;

            match fdtables::get_unused_virtual_fd_from_startfd(
                arg1cage,
                0,
                ret as u64,
                cloexec,
                perfdinfo,
                arg3, // startfd
            ) {
                Ok(vfd) => {
                    // println!(
                    //     "[ns_handlers|fcntl] cageid={} cmd={} old_fd={} underfd={} clamped={} new_virtualfd={}",
                    //     arg1cage,
                    //     if cloexec { "F_DUPFD_CLOEXEC" } else { "F_DUPFD" },
                    //     arg1,
                    //     old_fd_entry.underfd,
                    //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
                    //     vfd,
                    // );
                    return vfd as i32;
                }
                Err(_) => {
                    let _ = close_underfd(arg1cage, ret as u64, perfdinfo != 0);
                    return -(EMFILE as i32);
                }
            };
        }
    }

    // println!(
    //     "[ns_handlers|fcntl] cageid={} fd={} underfd={} cmd={} clamped={} routed_to={} ret={}",
    //     arg1cage,
    //     arg1,
    //     old_fd_entry.underfd,
    //     arg2,
    //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
    //     if nr == SYS_FCNTL { "kernel" } else { "clamped grate" },
    //     ret,
    // );

    ret
}

// potential bug: may escape the path isolation. can be handled by checking in the individual namespace grates
pub extern "C" fn ns_fstatat_handler(
    _cageid: u64,
    arg1: u64,      // dirfd
    arg1cage: u64,
    arg2: u64,      // pathname
    arg2cage: u64,
    arg3: u64,      // statbuf
    arg3cage: u64,
    arg4: u64,      // flags
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    const AT_FDCWD_I64: i64 = -100;

    let is_at_fdcwd = (arg1 as i64) == AT_FDCWD_I64;

    let path = helpers::read_path_from_cage(arg2, arg2cage).unwrap_or_default();

    let mut underfd = arg1;
    let mut dirfd_clamped = false;

    /*
     * If dirfd is not AT_FDCWD, translate virtual dirfd -> underlying kernel fd.
     */
    if !is_at_fdcwd {
        let fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
            Ok(entry) => entry,
            Err(_) => {
                // println!(
                //     "[ns_handlers|fstatat] cageid={} dirfd={} invalid virtual fd, ret=EBADF",
                //     arg1cage,
                //     arg1,
                // );
                return -(EBADF as i32);
            }
        };

        underfd = fd_entry.underfd;
        dirfd_clamped = fd_entry.perfdinfo != 0;
        args[0] = underfd;
    }

    /*
     * Routing decision:
     *
     * - empty path: usually AT_EMPTY_PATH; route by dirfd only.
     * - absolute path: dirfd is ignored, route by absolute path prefix.
     * - AT_FDCWD + relative path: resolve relative to caller cage cwd.
     * - real dirfd + relative path: route by dirfd's clamped status.
     */
    let should_clamp = if path.is_empty() {
        dirfd_clamped
    } else if path.starts_with('/') {
        let resolved = helpers::normalize_path(&path);
        helpers::path_matches_prefix(&resolved)
    } else if is_at_fdcwd {
        helpers::resolve_path_from_cage(arg2cage, arg2, arg2cage)
            .map(|resolved| helpers::path_matches_prefix(&resolved))
            .unwrap_or(false)
    } else {
        dirfd_clamped
    };

    let ret = if should_clamp {
        match helpers::get_route(arg1cage, SYS_NEWFSTATAT) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &args, &arg_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_NEWFSTATAT, &args, &arg_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_NEWFSTATAT, &args, &arg_cages)
    };

    ret
}

pub extern "C" fn ns_openat_handler(
    cageid: u64,
    arg1: u64,      // dirfd
    arg1cage: u64,
    arg2: u64,      // pathname
    arg2cage: u64,
    arg3: u64,      // flags
    arg3cage: u64,
    arg4: u64,      // mode
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Linux AT_FDCWD = -100.
    let is_at_fdcwd = (arg1 as i64) == -100;

    let path = helpers::read_path_from_cage(arg2, arg2cage).unwrap_or_default();

    let mut dirfd_clamped = false;
    let mut underfd = arg1;

    /*
     * If dirfd is not AT_FDCWD, translate virtual fd -> kernel fd.
     */
    if !is_at_fdcwd {
        let fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
            Ok(entry) => entry,
            Err(_) => {
                // println!(
                //     "[ns_handlers|fstatat] cageid={} dirfd={} invalid virtual fd, ret=EBADF",
                //     arg1cage,
                //     arg1,
                // );
                return -(EBADF as i32);
            }
        };

        underfd = fd_entry.underfd;
        dirfd_clamped = fd_entry.perfdinfo != 0;
        args[0] = underfd;
    }

    /*
     * Routing decision:
     *
     * 1. If dirfd is clamped, relative openat should route to the clamped grate.
     * 2. If path is absolute or dirfd is AT_FDCWD, resolve by cage cwd and check prefix.
     * 3. Otherwise, if dirfd is not clamped and path is relative, pass through kernel.
     */
    let path_matches = if !path.is_empty() {
        if path.starts_with("/") || is_at_fdcwd {
            helpers::resolve_path_from_cage(arg2cage, arg2, arg1cage)
                .map(|p| helpers::path_matches_prefix(&p))
                .unwrap_or(false)
        } else {
            false
        }
    } else {
        false
    };

    let should_clamp = dirfd_clamped || path_matches;

    let nr = match helpers::get_route(arg1cage, SYS_OPENAT) {
        Some(alt) if should_clamp => alt,
        _ => SYS_OPENAT,
    };

    let ret = if should_clamp && nr == SYS_OPENAT {
        helpers::do_clamp_syscall(arg1cage, SYS_OPENAT, &args, &arg_cages)
    } else {
        helpers::do_syscall(arg1cage, nr, &args, &arg_cages)
    };

    /*
     * On success, record returned kernel fd as a virtual fd.
     * perfdinfo=1 means fd belongs to clamped namespace/grate.
     */
    if ret >= 0 {
        let clamped = if should_clamp { 1u64 } else { 0u64 };

        match fdtables::get_unused_virtual_fd(
            arg1cage,
            0,          // fdkind
            ret as u64, // underfd
            false,      // should_cloexec; openat O_CLOEXEC handling not tracked here
            clamped,    // perfdinfo
        ) {
            Ok(vfd) => {
                // println!(
                //     "[ns_handlers|openat] cageid={} dirfd={} path={} underfd={} clamped={} virtualfd={}",
                //     arg1cage,
                //     arg1,
                //     path,
                //     ret,
                //     if clamped != 0 { "clamped grate" } else { "kernel" },
                //     vfd,
                // );
                return vfd as i32;
            }
            Err(_) => {
                // Avoid leaking the kernel fd if we cannot allocate a virtual fd.
                let _ = close_underfd(arg1cage, ret as u64, clamped != 0);

                return -(EMFILE as i32);
            }
        }
    }
    ret
}

/// dup (syscall 32): duplicate fd to the lowest-numbered unused fd.
///
/// It should allocate a fresh virtual fd for the newly duplicated underfd.
pub extern "C" fn ns_dup_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
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
    let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
        Ok(entry) => entry,
        Err(_) => {
            return -(EBADF as i32);
        }
    };

    let perfdinfo = old_fd_entry.perfdinfo;

    let dup_args = [old_fd_entry.underfd, 0, 0, 0, 0, 0];
    let dup_cages = [arg1cage; 6];

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &dup_args, &dup_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages)
    };

    if ret < 0 {
        return ret;
    }

    let new_underfd = ret as u64;

    // Allocate a fresh unused virtual fd for the new underfd.
    match fdtables::get_unused_virtual_fd(
        arg1cage,
        0,
        new_underfd,
        false,
        perfdinfo,
    ) {
        Ok(new_virtual_fd) => {
            // println!(
            //     "[ns_handlers|dup] cageid={} old_fd={} underfd={} clamped={} new_underfd={} new_virtual_fd={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     new_virtual_fd,
            // );
            new_virtual_fd as i32
        }

        Err(errno) => {
            // If fdtable installation fails, close the duplicated underfd
            // to avoid leaking a real fd.
            let _ = close_underfd(arg1cage, new_underfd, perfdinfo != 0);

            -(errno as i32)
        }
    }
}

/// dup2 (syscall 33): duplicate oldfd to the specific guest-visible newfd.
///
/// oldfd = arg1
/// newfd = arg2
///
/// Important:
/// - arg1/arg2 are guest virtual fds.
/// - underlying syscall must operate on underfds.
/// - we should not pass guest newfd directly to kernel/grate dup2.
pub extern "C" fn ns_dup2_handler(
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
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
    let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
        Ok(entry) => entry,
        Err(_) => {
            return -(EBADF as i32);
        }
    };

    let perfdinfo = old_fd_entry.perfdinfo;

    // dup2 special case:
    // If oldfd == newfd, dup2 returns newfd without closing/replacing it.
    if arg1 == arg2 {
        return arg2 as i32;
    }

    // If the target virtual fd already exists, close its underlying fd
    // and remove the virtual fd mapping first.
    //
    // This implements the guest-visible dup2 behavior:
    // newfd is atomically replaced from the guest's perspective.
    if let Ok(new_fd_entry) = fdtables::translate_virtual_fd(arg1cage, arg2) {
        let _ = close_underfd(arg1cage, new_fd_entry.underfd, new_fd_entry.perfdinfo != 0);
        let _ = fdtables::close_virtualfd(arg1cage, arg2);
    }

    // Duplicate the underlying old fd.
    //
    // We intentionally use SYS_DUP instead of SYS_DUP2 here, because arg2 is
    // a guest virtual fd, not a kernel/grate fd number.
    let dup_args = [old_fd_entry.underfd, 0, 0, 0, 0, 0];
    let dup_cages = [arg1cage; 6];

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &dup_args, &dup_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages)
    };

    if ret < 0 {
        return ret;
    }

    let new_underfd = ret as u64;

    // Install the newly duplicated underfd at the requested guest virtual fd.
    match fdtables::get_specific_virtual_fd(
        arg1cage,
        arg2,
        0,
        new_underfd,
        false,
        perfdinfo,
    ) {
        Ok(_) => {
            // println!(
            //     "[ns_handlers|dup2] cageid={} old_fd={} underfd={} clamped={} new_underfd={} new_virtual_fd={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     arg2,
            // );
            arg2 as i32
        }

        Err(errno) => {
            // If fdtable installation fails, close the duplicated underfd
            // to avoid leaking a real fd.
            let _ = close_underfd(arg1cage, new_underfd, perfdinfo != 0);

            // println!(
            //     "[ns_handlers|dup2] cageid={} old_fd={} underfd={} clamped={} new_underfd={} failed to install new_virtual_fd={}, errno={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     arg2,
            //      errno,
            // );

            -(errno as i32)
        }
    }
}

/// dup3 (syscall 292): duplicate oldfd to the specific guest-visible newfd
/// with flags.
///
/// oldfd = arg1
/// newfd = arg2
/// flags = arg3
///
/// Important:
/// - arg1/arg2 are guest virtual fds.
/// - underlying syscalls must operate on underfds.
/// - do not pass guest newfd directly to kernel/grate dup3.
pub extern "C" fn ns_dup3_handler(
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
    let old_fd_entry = match fdtables::translate_virtual_fd(arg1cage, arg1) {
        Ok(entry) => entry,
        Err(_) => {
            return -(EBADF as i32);
        }
    };

    let perfdinfo = old_fd_entry.perfdinfo;

    // dup3(oldfd, oldfd, flags) returns EINVAL.
    if arg1 == arg2 {
        return -(EINVAL as i32);
    }

    // Linux dup3 only accepts flags == 0 or O_CLOEXEC.
    if arg3 & !(O_CLOEXEC as u64) != 0 {
        return -(EINVAL as i32);
    }

    let cloexec = (arg3 & (O_CLOEXEC as u64)) != 0;

    // If the target virtual fd already exists, close its underlying fd
    // and remove the virtual mapping.
    if let Ok(new_fd_entry) = fdtables::translate_virtual_fd(arg1cage, arg2) {
        let _ = close_underfd(arg1cage, new_fd_entry.underfd, new_fd_entry.perfdinfo != 0);
        let _ = fdtables::close_virtualfd(arg1cage, arg2);
    }

    // Duplicate old underfd to a fresh real fd.
    //
    // We intentionally use SYS_DUP instead of SYS_DUP3 because arg2 is a
    // guest virtual fd, not an underfd target.
    let dup_args = [old_fd_entry.underfd, 0, 0, 0, 0, 0];
    let dup_cages = [arg1cage; 6];

    let ret = if perfdinfo != 0 {
        match helpers::get_route(arg1cage, SYS_DUP) {
            Some(alt) => helpers::do_syscall(arg1cage, alt, &dup_args, &dup_cages),
            None => helpers::do_clamp_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages),
        }
    } else {
        helpers::do_syscall(arg1cage, SYS_DUP, &dup_args, &dup_cages)
    };

    if ret < 0 {
        return ret;
    }

    let new_underfd = ret as u64;

    // If O_CLOEXEC was requested, set FD_CLOEXEC on the newly duplicated underfd
    if cloexec {
        let fcntl_args = [
            new_underfd,
            F_SETFD as u64,
            FD_CLOEXEC as u64,
            0,
            0,
            0,
        ];
        let fcntl_cages = [arg1cage; 6];

        let fcntl_ret = do_routed_underfd_syscall(
            arg1cage,
            SYS_FCNTL,
            &fcntl_args,
            &fcntl_cages,
            perfdinfo != 0,
        );

        if fcntl_ret < 0 {
            let _ = close_underfd(arg1cage, new_underfd, perfdinfo != 0);

            // println!(
            //     "[ns_handlers|dup3] cageid={} old_fd={} underfd={} clamped={} new_underfd={} failed to set CLOEXEC, errno={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     -fcntl_ret,
            // );

            return fcntl_ret;
        }
    }

    // Install the new underfd at the requested guest virtual fd.
    match fdtables::get_specific_virtual_fd(
        arg1cage,
        arg2,
        0,
        new_underfd,
        cloexec,
        perfdinfo,
    ) {
        Ok(_) => {
            // println!(
            //     "[ns_handlers|dup3] cageid={} old_fd={} underfd={} clamped={} new_underfd={} new_virtual_fd={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     arg2,
            // );
            arg2 as i32
        }

        Err(errno) => {
            // If fdtable installation fails, close the duplicated underfd
            // to avoid leaking a real fd.
            let _ = close_underfd(arg1cage, new_underfd, perfdinfo != 0);

            // println!(
            //     "[ns_handlers|dup3] cageid={} old_fd={} underfd={} clamped={} new_underfd={} failed to install new_virtual_fd={}, errno={}",
            //     arg1cage,
            //     arg1,
            //     old_fd_entry.underfd,
            //     if perfdinfo != 0 { "clamped grate" } else { "kernel" },
            //     new_underfd,
            //     arg2,
            //      errno,
            // );

            -(errno as i32)
        }
    }
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
    let is_thread = is_thread_clone(arg1, arg1cage);
    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret <= 0 {
        return ret;
    }

    if !is_thread {
        let child_cage_id = ret as u64;

        // Route cloning only — fdtables copy is handled by the lifecycle
        // fork_handler to avoid double-init when inner grates also handle fork.
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
    let ns_cage = getcageid();

    let cwd = helpers::get_cage_cwd(arg2cage);

    let cwd_bytes = cwd.as_bytes();
    let mut buf = cwd_bytes.to_vec();
    buf.push(0);

    match copy_data_between_cages(
        ns_cage,
        arg1cage,
        buf.as_ptr() as u64,
        ns_cage,
        arg1,
        arg1cage,
        4096,
        1,
    ) {
        Ok(_) => {
            return arg1cage as i32;
        }
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
        SYS_GETCWD => Some(ns_getcwd_handler),
        SYS_ACCESS => Some(ns_access_handler),
        SYS_UNLINK => Some(ns_unlink_handler),
        SYS_LINK => Some(ns_link_handler),
        SYS_MKDIR => Some(ns_mkdir_handler),
        SYS_RMDIR => Some(ns_rmdir_handler),
        SYS_RENAME => Some(ns_rename_handler),
        SYS_TRUNCATE => Some(ns_truncate_handler),
        SYS_CHMOD => Some(ns_chmod_handler),
        SYS_CHDIR => Some(ns_chdir_handler),
        SYS_MKNOD => Some(ns_mknod_handler),
        SYS_READLINK => Some(ns_readlink_handler),
        SYS_UNLINKAT => Some(ns_unlinkat_handler),
        SYS_READLINKAT => Some(ns_readlinkat_handler),
        SYS_STATFS => Some(ns_statfs_handler),
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
        SYS_NEWFSTATAT => Some(ns_fstatat_handler),
        SYS_FCNTL => Some(ns_fcntl_handler),
        SYS_FTRUNCATE => Some(ns_ftruncate_handler),
        SYS_FCHMOD => Some(ns_fchmod_handler),
        SYS_FCHDIR => Some(ns_fchdir_handler),
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
