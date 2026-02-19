//! A simple example highlighting how to use `grate_rs::make_threei_call`
//!
//! Here, the geteuid calls are redirected to the grate for logging purposes.
//!
//! The syscall wrapper here uses make_threei_call to call geteuid() as the cage and logs the return value.
use grate_rs::constants::SYS_GETEUID;
use grate_rs::{GrateBuilder, GrateError};

extern "C" fn geteuid_syscall(
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
    let ret = grate_rs::make_threei_call(
        107,      // Syscall number for geteuid
        0,        // Syscall Name, leave NULL
        cageid,   // This cageid is used to look up grate handlers.
        arg1cage, // This cageid is used to make rawposix calls.
        // Pass down syscall arguments
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4, arg4cage, arg5, arg5cage, arg6,
        arg6cage, 0, // Do not translate the error
    );

    match ret {
        Ok(ret) => {
            println!("GETEUID() = {ret}");
            ret
        }
        Err(e) => {
            println!("GETEUID() = -1 - {:#?}", e);
            -1
        }
    }
}

fn main() {
    let builder = GrateBuilder::new()
        .register(SYS_GETEUID, geteuid_syscall)
        .teardown(|result: Result<i32, GrateError>| {
            println!("Result: {:#?}", result);
        });

    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    builder.run(argv);
}
