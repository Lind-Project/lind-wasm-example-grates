use crate::tee::*;
use grate_rs::make_threei_call;

pub fn do_syscall(calling_cage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let tee_cage = {
        let guard = TEE_STATE.lock().unwrap();
        guard.as_ref().expect("TeeState not initialized").tee_cage_id
    };
    match make_threei_call(
        nr as u32, 0, tee_cage, calling_cage,
        args[0], arg_cages[0],
        args[1], arg_cages[1],
        args[2], arg_cages[2],
        args[3], arg_cages[3],
        args[4], arg_cages[4],
        args[5], arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}
