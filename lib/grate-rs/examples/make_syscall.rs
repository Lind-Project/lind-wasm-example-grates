//! A simple example highlighting how to use `grate_rs::make_threei_call`
//!
//! Here, the geteuid calls are redirected to the grate for logging purposes.
//!
//! The syscall wrapper here uses make_threei_call to call geteuid() as the cage and logs the return value.
use grate_rs::GrateBuilder;

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
    let builder = GrateBuilder::new().register(107, geteuid_syscall);

    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    match builder.run(argv) {
        Ok(status) => {
            println!("[grate_teardown] Cage exited with: {status}.");
        }
        Err(e) => {
            eprintln!("[grate_error] Failed to run grate: {:?}", e);
            std::process::exit(1);
        }
    }
}
