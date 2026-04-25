use crate::tee::*;
use crate::utils::*;
use grate_rs::SyscallHandler;
use grate_rs::constants::*;

pub const PRIMARY_ONLY_SYSCALLS: &[u64] = &[
    SYS_FORK,  // 57
    SYS_CLONE, // 56
    SYS_EXEC,  // 59 (execve)
    SYS_EXIT,  // 60
];

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
                $nr,
                arg1cage,
                &[arg1, arg2, arg3, arg4, arg5, arg6],
                &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            )
        }
    };
}

pub fn tee_dispatch(
    syscall_number: u64,
    cage_id: u64,
    args: &[u64; 6],
    arg_cages: &[u64; 6],
) -> i32 {
    let (primary, secondary) = with_tee(|s| {
        let route_entry = s.tee_routes.get(&(arg_cages[0], syscall_number)).unwrap();
        (route_entry.primary_alt, route_entry.secondary_alt)
    });

    // Primary
    let primary_syscall = primary.unwrap_or(syscall_number);
    let primary_result = do_syscall(cage_id, primary_syscall, args, arg_cages);

    println!(
        "[t-grate] syscall_number={} primary={}",
        syscall_number, primary_result
    );

    // Secondary
    if PRIMARY_ONLY_SYSCALLS.contains(&syscall_number) {
        return primary_result;
    }

    if let Some(secondary_syscall) = secondary {
        let secondary_result = do_syscall(cage_id, secondary_syscall, args, arg_cages);

        println!(
            "[t-grate] syscall_number={} secondary={}",
            syscall_number, secondary_result
        );
    }

    return primary_result;
}

tee_handler!(tee_open, SYS_OPEN);
tee_handler!(tee_stat, SYS_XSTAT);
tee_handler!(tee_access, SYS_ACCESS);
tee_handler!(tee_unlink, SYS_UNLINK);
tee_handler!(tee_mkdir, SYS_MKDIR);
tee_handler!(tee_rmdir, SYS_RMDIR);
tee_handler!(tee_rename, SYS_RENAME);
tee_handler!(tee_truncate, SYS_TRUNCATE);
tee_handler!(tee_chmod, SYS_CHMOD);
tee_handler!(tee_chdir, SYS_CHDIR);
tee_handler!(tee_readlink, SYS_READLINK);
tee_handler!(tee_unlinkat, SYS_UNLINKAT);
tee_handler!(tee_read, SYS_READ);
tee_handler!(tee_readlinkat, SYS_READLINKAT);
tee_handler!(tee_write, SYS_WRITE);
tee_handler!(tee_close, SYS_CLOSE);
tee_handler!(tee_pread, SYS_PREAD);
tee_handler!(tee_pwrite, SYS_PWRITE);
tee_handler!(tee_lseek, SYS_LSEEK);
tee_handler!(tee_fstat, SYS_FXSTAT);
tee_handler!(tee_fcntl, SYS_FCNTL);
tee_handler!(tee_ftruncate, SYS_FTRUNCATE);
tee_handler!(tee_fchmod, SYS_FCHMOD);
tee_handler!(tee_readv, SYS_READV);
tee_handler!(tee_writev, SYS_WRITEV);
tee_handler!(tee_dup, SYS_DUP);
tee_handler!(tee_dup2, SYS_DUP2);
tee_handler!(tee_dup3, SYS_DUP3);

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
        _ => None,
    }
}
