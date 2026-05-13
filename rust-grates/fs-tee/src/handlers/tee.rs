use crate::secondary_log;
use crate::tee::*;
use crate::utils;
use crate::utils::*;
use fdtables::translate_virtual_fd;
use grate_rs::SyscallHandler;
use grate_rs::constants::*;
use grate_rs::getcageid;
use grate_rs::is_thread_clone;
use std::ffi::c_void;

pub const _PRIMARY_ONLY_SYSCALLS: &[u64] = &[
    SYS_FORK,  // 57
    SYS_CLONE, // 56
    SYS_EXEC,  // 59 (execve)
    SYS_EXIT,  // 60
];
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 1030;

macro_rules! tee_handler {
    ($name:ident, $nr:expr) => {
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
            tee_dispatch(
                stringify!($name),
                $nr,
                arg1cage,
                &mut [arg1, arg2, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
                1,
            )
        }
    };
}

macro_rules! tee_path_handler {
    ($name:ident, $nr:expr) => {
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
            tee_dispatch(
                stringify!($name),
                $nr,
                arg1cage,
                &mut [arg1, arg2, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
                -1,
            )
        }
    };
}

pub fn tee_dispatch(
    syscall_name: &str,
    syscall_number: u64,
    cage_id: u64,
    args: &mut [u64; 6],
    arg_cages: &[u64; 6],
    fd_arg: i32,
) -> i32 {
    let primary_result = do_syscall(cage_id, syscall_number, args, arg_cages);

    let (secondary_path, secondary_entry): (Option<u64>, u64) = with_tee(|s| {
        (
            s.tee_routes
                .get(&(cage_id, syscall_number))
                .unwrap()
                .secondary_alt,
            s.secondary_entry,
        )
    });

    // let pre = args[0];

    if fd_arg != -1 {
        match translate_secondary_fd(cage_id, args[0]) {
            Some(secondary_fd) => {
                args[0] = secondary_fd;
            }
            None => {}
        }
    }

    let secondary_result = if utils::is_tty(syscall_number, cage_id, args[0]) {
        // println!("[WRITING TO SECONDARY TTY]");
        args[2] as i32
        // args[0] = with_tee(|s| s.secondary_log_fd as u64);
        // let tee_cage = getcageid();
        // do_syscall(tee_cage, syscall_number, args, arg_cages)
    } else {
        match secondary_path {
            Some(alt) => do_syscall(cage_id, alt, args, arg_cages),
            None => do_tee_syscall(secondary_entry, cage_id, syscall_number, args, arg_cages),
        }
    };

    /*
        let _secondary_result = match translate_secondary_fd(cage_id, args[0]) {
            Some(secondary_fd) => {
                args[0] = secondary_fd;

                let result = if utils::is_tty(syscall_number, cage_id, args[0]) {
                    // println!("[WRITING TO SECONDARY TTY]");
                    args[2] as i32
                    // args[0] = with_tee(|s| s.secondary_log_fd as u64);
                    // let tee_cage = getcageid();
                    // do_syscall(tee_cage, syscall_number, args, arg_cages)
                } else {
                    match secondary_path {
                        Some(alt) => do_syscall(cage_id, alt, args, arg_cages),
                        None => {
                            do_tee_syscall(secondary_entry, cage_id, syscall_number, args, arg_cages)
                        }
                    }
                };

                args[0] = pre;

                result
            }

            None => -1,
        };
    */

    secondary_log!(
        "{}({}, {}) primary={} secondary={}",
        syscall_name,
        cage_id,
        args[0],
        primary_result,
        secondary_result
    );

    primary_result
}

fn record_fd_pair(cage_id: u64, primary_result: i32, secondary_result: i32) {
    let _ = fdtables::get_specific_virtual_fd(
        cage_id,
        primary_result as u64,   // virtual fd in primary chain
        0,                       // fdkind (unused)
        secondary_result as u64, // underfd in secondary chain
        false,                   // should_cloexec (unused)
        0,                       // perfdinfo (unused)
    );
}

fn translate_secondary_fd(cage_id: u64, fd: u64) -> Option<u64> {
    match fdtables::translate_virtual_fd(cage_id, fd) {
        Ok(entry) => Some(entry.underfd),
        Err(_) => None,
    }
}

const SYS_MKDIRAT: u64 = 258;

// tee_handler!(tee_open, SYS_OPEN);
tee_path_handler!(tee_stat, SYS_XSTAT);
tee_path_handler!(tee_access, SYS_ACCESS);
tee_path_handler!(tee_unlink, SYS_UNLINK);
tee_path_handler!(tee_mkdir, SYS_MKDIR);
tee_handler!(tee_mkdirat, SYS_MKDIRAT);
tee_path_handler!(tee_rmdir, SYS_RMDIR);
tee_path_handler!(tee_rename, SYS_RENAME);
tee_handler!(tee_truncate, SYS_TRUNCATE);
tee_path_handler!(tee_chmod, SYS_CHMOD);
tee_path_handler!(tee_chdir, SYS_CHDIR);
tee_path_handler!(tee_readlink, SYS_READLINK);
tee_handler!(tee_unlinkat, SYS_UNLINKAT);
tee_handler!(tee_read, SYS_READ);
tee_handler!(tee_readlinkat, SYS_READLINKAT);
tee_handler!(tee_write, SYS_WRITE);
tee_handler!(tee_close, SYS_CLOSE);
tee_handler!(tee_pread, SYS_PREAD);
tee_handler!(tee_pwrite, SYS_PWRITE);
tee_handler!(tee_pwritev, SYS_PWRITEV);
tee_handler!(tee_preadv, SYS_PREADV);
tee_handler!(tee_lseek, SYS_LSEEK);
tee_handler!(tee_fstat, SYS_FXSTAT);
tee_handler!(tee_ftruncate, SYS_FTRUNCATE);
tee_handler!(tee_fsync, SYS_FSYNC);
tee_handler!(tee_fchmod, SYS_FCHMOD);
tee_handler!(tee_readv, SYS_READV);
tee_handler!(tee_writev, SYS_WRITEV);
tee_handler!(tee_getdents, SYS_GETDENTS);
tee_path_handler!(tee_mmap, SYS_MMAP);
//tee_handler!(tee_pipe2, SYS_PIPE2);

pub extern "C" fn tee_pipe(
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
    let cage_id = arg_cages[2];

    let (secondary_entry, secondary_alt) = with_tee(|s| {
        (
            s.secondary_entry,
            s.tee_routes
                .get(&(arg_cages[0], SYS_PIPE))
                .unwrap()
                .secondary_alt,
        )
    });

    let primary_result = do_syscall(cage_id, SYS_PIPE, &args, &arg_cages);

    let secondary_result = match secondary_alt {
        Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, cage_id, SYS_OPEN, &args, &arg_cages),
    };

    // record_fd_pair(arg2cage, primary_result, secondary_result);

    secondary_log!(
        "pipe({cage_id}, {arg1}, {arg2}) primary={primary_result} secondary={secondary_result}"
    );

    return primary_result;
}

pub extern "C" fn tee_pipe2(
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
    let cage_id = arg_cages[2];

    let (secondary_entry, secondary_alt) = with_tee(|s| {
        (
            s.secondary_entry,
            s.tee_routes
                .get(&(arg_cages[0], SYS_PIPE2))
                .unwrap()
                .secondary_alt,
        )
    });

    let primary_result = do_syscall(cage_id, SYS_PIPE2, &args, &arg_cages);

    let secondary_result = match secondary_alt {
        Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, cage_id, SYS_OPEN, &args, &arg_cages),
    };

    // record_fd_pair(arg2cage, primary_result, secondary_result);

    secondary_log!(
        "pipe2({cage_id}, {arg1}, {arg2}) primary={primary_result} secondary={secondary_result}"
    );

    return primary_result;
}

pub extern "C" fn tee_open(
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
    let cage_id = arg_cages[2];

    let (secondary_entry, secondary_alt) = with_tee(|s| {
        (
            s.secondary_entry,
            s.tee_routes
                .get(&(arg_cages[0], SYS_OPEN))
                .unwrap()
                .secondary_alt,
        )
    });

    let primary_result = do_syscall(cage_id, SYS_OPEN, &args, &arg_cages);

    let secondary_result = match secondary_alt {
        Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, cage_id, SYS_OPEN, &args, &arg_cages),
    };

    record_fd_pair(arg2cage, primary_result, secondary_result);

    secondary_log!(
        "open({cage_id}, {arg1}, {arg2}) primary={primary_result} secondary={secondary_result}"
    );

    return primary_result;
}

pub extern "C" fn tee_dup(
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

    let (secondary_entry, secondary) = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg1cage, SYS_DUP)).unwrap();
        (s.secondary_entry, route_entry.secondary_alt)
    });

    let syscall_number = SYS_DUP;
    let cage_id = arg2cage;

    let primary_syscall = SYS_DUP;
    let primary_result = do_syscall(arg1cage, primary_syscall, &args, &arg_cages);

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            let result = match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, syscall_number, &args, &arg_cages),
            };

            result
        }

        None => -1,
    };

    record_fd_pair(cage_id, primary_result, secondary_result);

    secondary_log!(
        "dup({cage_id}, {arg1}, {arg2}) primary={primary_result} secondary={secondary_result}"
    );

    primary_result
}

pub extern "C" fn tee_dup2(
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

    let (secondary_entry, secondary) = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg1cage, SYS_DUP2)).unwrap();
        (s.secondary_entry, route_entry.secondary_alt)
    });

    let primary_syscall = SYS_DUP2;
    let primary_result = do_syscall(arg1cage, primary_syscall, &args, &arg_cages);

    let syscall_number = SYS_DUP2;
    let cage_id = arg2cage;

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            let result = match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, syscall_number, &args, &arg_cages),
            };

            result
        }

        None => -1,
    };

    record_fd_pair(cage_id, primary_result, secondary_result);

    secondary_log!(
        "dup2({cage_id}, {}, {}) primary={primary_result} secondary={secondary_result}",
        args[0],
        args[1],
    );

    primary_result
}

pub extern "C" fn tee_dup3(
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

    let (secondary_entry, secondary) = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg1cage, SYS_DUP3)).unwrap();
        (s.secondary_entry, route_entry.secondary_alt)
    });

    let primary_syscall = SYS_DUP3;
    let primary_result = do_syscall(arg1cage, primary_syscall, &args, &arg_cages);

    let syscall_number = SYS_DUP3;
    let cage_id = arg2cage;

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            let result = match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, syscall_number, &args, &arg_cages),
            };

            result
        }

        None => -1,
    };

    record_fd_pair(arg1cage, primary_result, secondary_result);

    secondary_log!(
        "dup3({cage_id}, {}, {}) primary={primary_result} secondary={secondary_result}",
        args[0],
        args[1],
    );

    primary_result
}

pub extern "C" fn tee_fcntl(
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

    let (secondary_entry, secondary) = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg1cage, SYS_FCNTL)).unwrap();
        (s.secondary_entry, route_entry.secondary_alt)
    });

    let primary_syscall = SYS_FCNTL;
    let primary_result = do_syscall(arg1cage, primary_syscall, &args, &arg_cages);

    let syscall_number = SYS_FCNTL;
    let cage_id = arg2cage;

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            let result = match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, syscall_number, &args, &arg_cages),
            };

            result
        }

        None => -1,
    };

    if arg2 == F_DUPFD || arg2 == F_DUPFD_CLOEXEC {
        record_fd_pair(arg1cage, primary_result, secondary_result);
    }

    secondary_log!(
        "fcntl({cage_id}, {}, {}) primary={}, secondary={}",
        arg1,
        arg2,
        primary_result,
        secondary_result
    );

    primary_result
}

pub extern "C" fn tee_fork(
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

        // Copy tee routes for this cage.
        copy_route_table(arg1cage, child_cage_id);
    }

    with_tee(|s| s.fork_return = child_cage_id);

    let secondary_entry = with_tee(|s| s.secondary_entry);

    let secondary = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg1cage, SYS_CLONE)).unwrap();
        route_entry.secondary_alt
    });

    let _secondary_result = match secondary {
        Some(alt) => do_syscall(arg1cage, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, arg1cage, SYS_CLONE, &args, &arg_cages),
    };

    child_cage_id as i32
}

pub fn get_tee_handler(syscall_nr: u64) -> Option<SyscallHandler> {
    match syscall_nr {
        SYS_OPEN => Some(tee_open),
        SYS_XSTAT => Some(tee_stat),
        SYS_ACCESS => Some(tee_access),
        SYS_UNLINK => Some(tee_unlink),
        SYS_MKDIR => Some(tee_mkdir),
        SYS_RMDIR => Some(tee_rmdir),
        SYS_RENAME => Some(tee_rename),
        SYS_TRUNCATE => Some(tee_truncate),
        SYS_CHMOD => Some(tee_chmod),
        SYS_CHDIR => Some(tee_chdir),
        SYS_READLINK => Some(tee_readlink),
        SYS_UNLINKAT => Some(tee_unlinkat),
        SYS_READLINKAT => Some(tee_readlinkat),
        SYS_READ => Some(tee_read),
        SYS_WRITE => Some(tee_write),
        SYS_CLOSE => Some(tee_close),
        SYS_PREAD => Some(tee_pread),
        SYS_PWRITE => Some(tee_pwrite),
        SYS_LSEEK => Some(tee_lseek),
        SYS_FXSTAT => Some(tee_fstat),
        SYS_FCNTL => Some(tee_fcntl),
        SYS_FTRUNCATE => Some(tee_ftruncate),
        SYS_FCHMOD => Some(tee_fchmod),
        SYS_READV => Some(tee_readv),
        SYS_WRITEV => Some(tee_writev),
        SYS_DUP => Some(tee_dup),
        SYS_DUP2 => Some(tee_dup2),
        SYS_DUP3 => Some(tee_dup3),
        SYS_PIPE2 => Some(tee_pipe2),
        SYS_PIPE => Some(tee_pipe),
        SYS_CLONE => Some(tee_fork),
        SYS_PREADV => Some(tee_preadv),
        SYS_GETDENTS => Some(tee_getdents),
        SYS_FSYNC => Some(tee_fsync),
        SYS_MMAP => Some(tee_mmap),
        SYS_PWRITEV => Some(tee_pwritev),
        SYS_MKDIRAT => Some(tee_mkdirat),
        _ => None,
    }
}
