use crate::tee::*;
use crate::utils::*;
use grate_rs::constants::*;
use grate_rs::SyscallHandler;

pub const PRIMARY_ONLY_SYSCALLS: &[u64] = &[
    SYS_FORK,   // 57
    SYS_CLONE,  // 56
    SYS_EXEC,   // 59 (execve)
    SYS_EXIT,   // 60
];

macro_rules! tee_handler {
    ($name:ident, $nr:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            tee_dispatch(
                $nr, arg1cage,
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
    arg_cages: &[u64; 6]
) -> i32 {
    let (primary, secondary) = with_tee(|s| {
        // println!("[t-grate] tee_route table: {:#?}", s.tee_route);
        let route_entry = s.tee_route.get(&(arg_cages[0], SYS_READ)).unwrap();
        (route_entry.primary_alt, route_entry.secondary_alt)
    });

    // Primary 
    let primary_syscall = primary.unwrap_or(syscall_number);
    let primary_result = do_syscall(cage_id, primary_syscall, args, arg_cages);

    println!("[t-grate] syscall_number={} primary={}", syscall_number, primary_result);
    
    // Secondary 
    if PRIMARY_ONLY_SYSCALLS.contains(&syscall_number) {
        return primary_result;
    }

    if let Some(secondary_syscall) = secondary {
        let secondary_result = do_syscall(cage_id, secondary_syscall, args, arg_cages);

        println!("[t-grate] syscall_number={} secondary={}", syscall_number, secondary_result);
    }


    return primary_result;
}

pub fn get_tee_handler(syscall_nr: u64) -> Option<SyscallHandler> {
    match syscall_nr {
        SYS_READ => Some(read_handler),
        _ => None,
    }
}

tee_handler!(read_handler, SYS_READ);
