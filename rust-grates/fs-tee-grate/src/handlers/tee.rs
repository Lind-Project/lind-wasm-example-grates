use crate::secondary_log;
use crate::tee::*;
use crate::utils;
use crate::utils::*;
use grate_rs::constants::fs::F_DUPFD;
use grate_rs::constants::fs::F_DUPFD_CLOEXEC;
use grate_rs::constants::*;
use grate_rs::{copy_data_between_cages, getcageid, is_thread_clone};

/// Call a syscall whose first argument is an FD through both stacks.
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
                0,
            )
        }
    };
}

/// Call a syscall that does not require FD translation through both stacks.
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

/// Call a syscall through both the primary and secondary stacks.
///
/// `syscall_name` is used for logging.
/// `syscall_number`, `cage_id`, `args`, and `arg_cages` are forwarded to the syscall layer.
/// `fd_arg` is `-1` when no FD translation is needed. Otherwise it is the argument index whose
/// FD must be translated before forwarding the call to the secondary stack.
pub fn tee_dispatch(
    syscall_name: &str,
    syscall_number: u64,
    cage_id: u64,
    args: &mut [u64; 6],
    arg_cages: &[u64; 6],
    fd_arg: i32,
) -> i32 {
    // Look up the tee route and the entry cage for the secondary stack.
    let (secondary_path, secondary_entry): (Option<u64>, u64) = with_tee(|s| {
        (
            s.tee_routes
                .get(&(cage_id, syscall_number))
                .unwrap()
                .secondary_alt,
            s.secondary_entry,
        )
    });

    let mut secondary_args = *args;

    // Translate the FD argument before forwarding the call to the secondary stack.
    if fd_arg != -1 {
        if let Some(secondary_fd) = translate_secondary_fd(cage_id, args[0]) {
            secondary_args[fd_arg as usize] = secondary_fd;
        }
    }

    // Skip the secondary call when writing to a TTY so stdout/stderr is not duplicated.
    let secondary_result = if utils::is_tty(syscall_number, cage_id, args[0]) {
        args[2] as i32
    } else {
        // Forward through the registered alternate handler when one exists.
        // Otherwise call into the secondary entry cage directly so the stacked layout still
        // behaves like the normal dispatch path.
        //
        // Consider the following two layouts:
        //
        // 1. fs-tee %{ imfs fork-interpose-grate %} target
        //     (1)       (2)   (3)                    (4)
        //
        // 2. fs-tee %{ imfs no-fork-interpose-grate %} target
        //     (1)       (2)   (3)                       (4)
        //
        // In case 1, the intermediate grate interposes on `fork()`, so fs-tee can forward the
        // call by using the registered alternate syscall number.
        //
        // In case 2, there is no alternate registration, but the call still needs to reach cage 2
        // exactly as it would in the normal stacked configuration.
        //
        // The direct call through `secondary_entry` preserves that behavior by mimicking the
        // regular stack flow.
        match secondary_path {
            Some(alt) => do_syscall(cage_id, alt, &secondary_args, arg_cages),
            None => do_tee_syscall(
                secondary_entry,
                cage_id,
                syscall_number,
                &secondary_args,
                arg_cages,
            ),
        }
    };

    let primary_result = do_syscall(cage_id, syscall_number, args, arg_cages);

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        syscall_name,
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(args),
        format_arg_array(arg_cages),
    );

    primary_result
}

/// Record the FD mapping between the primary and secondary stacks.
///
/// This is used for calls such as `open`, `dup*`, and `pipe*`.
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

fn read_pipe_fds(pipefd_ptr: u64, pipefd_cage: u64) -> Option<[i32; 2]> {
    let tee_cage = getcageid();
    let mut bytes = [0u8; 8];

    copy_data_between_cages(
        tee_cage,
        pipefd_cage,
        pipefd_ptr,
        pipefd_cage,
        bytes.as_mut_ptr() as u64,
        tee_cage,
        bytes.len() as u64,
        0,
    )
    .ok()?;

    Some([
        i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
    ])
}

/// Retrieve the secondary stack's FD.
fn translate_secondary_fd(cage_id: u64, fd: u64) -> Option<u64> {
    match fdtables::translate_virtual_fd(cage_id, fd) {
        Ok(entry) => Some(entry.underfd),
        Err(_) => None,
    }
}

// FD-based handlers generated by the shared tee dispatcher.
tee_handler!(tee_read, SYS_READ);
tee_handler!(tee_write, SYS_WRITE);
tee_handler!(tee_close, SYS_CLOSE);
tee_handler!(tee_fstat, SYS_FXSTAT);
tee_handler!(tee_lseek, SYS_LSEEK);
tee_handler!(tee_pread, SYS_PREAD);
tee_handler!(tee_pwrite, SYS_PWRITE);
tee_handler!(tee_readv, SYS_READV);
tee_handler!(tee_writev, SYS_WRITEV);
tee_handler!(tee_fsync, SYS_FSYNC);
tee_handler!(tee_truncate, SYS_TRUNCATE);
tee_handler!(tee_ftruncate, SYS_FTRUNCATE);
tee_handler!(tee_getdents, SYS_GETDENTS);
tee_handler!(tee_fchmod, SYS_FCHMOD);
tee_handler!(tee_mkdirat, SYS_MKDIRAT);
tee_handler!(tee_unlinkat, SYS_UNLINKAT);
tee_handler!(tee_readlinkat, SYS_READLINKAT);
tee_handler!(tee_preadv, SYS_PREADV);
tee_handler!(tee_pwritev, SYS_PWRITEV);

// Path-based handlers that do not need FD translation.
tee_path_handler!(tee_stat, SYS_XSTAT);
tee_path_handler!(tee_mmap, SYS_MMAP);
tee_path_handler!(tee_access, SYS_ACCESS);
tee_path_handler!(tee_chdir, SYS_CHDIR);
tee_path_handler!(tee_rename, SYS_RENAME);
tee_path_handler!(tee_mkdir, SYS_MKDIR);
tee_path_handler!(tee_rmdir, SYS_RMDIR);
tee_path_handler!(tee_unlink, SYS_UNLINK);
tee_path_handler!(tee_readlink, SYS_READLINK);
tee_path_handler!(tee_chmod, SYS_CHMOD);

/// Mirror `fork()` to the secondary stack and copy tee state for real process clones.
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

    // Forward the clone to the primary runtime first.
    let child_cage_id = do_syscall(arg1cage, SYS_CLONE, &args, &arg_cages) as u64;

    if !is_thread_clone(arg1, arg1cage) {
        // Real process forks need a copied FD table and tee route table in the child.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);
        copy_route_table(arg1cage, child_cage_id);
    }

    // Preserve the primary fork return value so the secondary stack can report the same result.
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

/// Open on both stacks, then record the returned FD pair.
///
/// `open()` allocates a fresh FD, so the secondary FD must be tracked for later translation.
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

    // Pair the primary FD and secondary FD for all later calls.
    record_fd_pair(arg2cage, primary_result, secondary_result);

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_open",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// Mirror `pipe()` to both stacks.
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

    let secondary_result = match secondary_alt {
        Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, cage_id, SYS_PIPE, &args, &arg_cages),
    };
    let secondary_fds = (secondary_result == 0)
        .then(|| read_pipe_fds(arg1, arg1cage))
        .flatten();

    let primary_result = do_syscall(cage_id, SYS_PIPE, &args, &arg_cages);
    let primary_fds = (primary_result == 0)
        .then(|| read_pipe_fds(arg1, arg1cage))
        .flatten();

    if let (Some(primary_fds), Some(secondary_fds)) = (primary_fds, secondary_fds) {
        record_fd_pair(arg1cage, primary_fds[0], secondary_fds[0]);
        record_fd_pair(arg1cage, primary_fds[1], secondary_fds[1]);
    }

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_pipe",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// Mirror `dup()` to the secondary stack after translating the source FD.
///
/// On success, the new FD pair is recorded so later FD-based syscalls can be translated.
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

    let cage_id = arg2cage;
    let primary_result = do_syscall(arg1cage, SYS_DUP, &args, &arg_cages);

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, SYS_DUP, &args, &arg_cages),
            }
        }
        None => -1,
    };

    record_fd_pair(cage_id, primary_result, secondary_result);

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_dup",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// Mirror `dup2()` to the secondary stack after translating the source FD.
///
/// The returned FD pair is recorded when the duplication succeeds on both stacks.
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

    let cage_id = arg2cage;
    let primary_result = do_syscall(arg1cage, SYS_DUP2, &args, &arg_cages);

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, SYS_DUP2, &args, &arg_cages),
            }
        }
        None => -1,
    };

    record_fd_pair(cage_id, primary_result, secondary_result);

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_dup2",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// `fcntl()` needs manual handling because only some commands allocate a new FD.
///
/// The source FD is translated before the secondary call. FD mapping is updated only for the
/// duplication commands that return a fresh descriptor.
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

    let cage_id = arg2cage;
    let primary_result = do_syscall(arg1cage, SYS_FCNTL, &args, &arg_cages);

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, SYS_FCNTL, &args, &arg_cages),
            }
        }
        None => -1,
    };

    if arg2 == F_DUPFD as u64 || arg2 == F_DUPFD_CLOEXEC as u64 {
        record_fd_pair(arg1cage, primary_result, secondary_result);
    }

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_fcntl",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// Mirror `dup3()` to the secondary stack after translating the source FD.
///
/// On success, the new FD pair is recorded so later translations stay in sync.
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

    let cage_id = arg2cage;
    let primary_result = do_syscall(arg1cage, SYS_DUP3, &args, &arg_cages);

    let secondary_result = match translate_secondary_fd(cage_id, args[0]) {
        Some(secondary_fd) => {
            args[0] = secondary_fd;

            match secondary {
                Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
                None => do_tee_syscall(secondary_entry, cage_id, SYS_DUP3, &args, &arg_cages),
            }
        }
        None => -1,
    };

    record_fd_pair(arg1cage, primary_result, secondary_result);

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_dup3",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}

/// Mirror `pipe2()` to both stacks.
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

    let secondary_result = match secondary_alt {
        Some(alt) => do_syscall(cage_id, alt, &args, &arg_cages),
        None => do_tee_syscall(secondary_entry, cage_id, SYS_PIPE2, &args, &arg_cages),
    };
    let secondary_fds = (secondary_result == 0)
        .then(|| read_pipe_fds(arg1, arg1cage))
        .flatten();

    let primary_result = do_syscall(cage_id, SYS_PIPE2, &args, &arg_cages);
    let primary_fds = (primary_result == 0)
        .then(|| read_pipe_fds(arg1, arg1cage))
        .flatten();

    if let (Some(primary_fds), Some(secondary_fds)) = (primary_fds, secondary_fds) {
        record_fd_pair(arg1cage, primary_fds[0], secondary_fds[0]);
        record_fd_pair(arg1cage, primary_fds[1], secondary_fds[1]);
    }

    secondary_log!(
        "{}\tCage={}\tPrimary={}\tSecondary={}\tArgs={}, ArgCage={}",
        "tee_pipe2",
        cage_id,
        primary_result,
        secondary_result,
        format_arg_array(&args),
        format_arg_array(&arg_cages),
    );

    primary_result
}
