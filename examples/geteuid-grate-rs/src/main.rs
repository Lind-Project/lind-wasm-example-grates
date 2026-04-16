//! geteuid-grate-rs
//!
//! This is a "hello world" example for building grates in Rust using the `grate-rs` experience.
//!
//! The geteuid-grate interposes on the `SYS_GETEUID` syscall and returns a constant value back to
//! the cage.

use grate_rs::{GrateBuilder, constants::SYS_GETEUID};

// This is the callback handler that is called when a child cage calls `geteuid()`
pub extern "C" fn geteuid_handler(
    _grate_id: u64,
    _arg1: u64,
    _arg1cage: u64,
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
    // Return a stubbed constant value for euid.
    3000
}

fn main() {
    // Populate the handlers and teardown functions using `GrateBuilder`
    let grate = GrateBuilder::new()
        // registers GETEUID with our custom handler.
        .register(SYS_GETEUID, geteuid_handler)
        // This is the teardown function that is called once a child cage exits.
        //
        // The input to this function is a Result<child_exit_status, GrateError>. An error is returned
        // only when we are unable to spawn the child cage.
        .teardown(|result| match result {
            Ok(status) => println!("[geteuid-grate] child exited with status: {status}"),
            Err(e) => {
                println!("[grate-rs] unable to launch child cages: {:#?}", e);
                std::process::exit(-1);
            }
        });

    // The run() function takes an array equivalent to argv[].
    //
    // The child cage is launched using execv(argv[0], &argv[0]) i.e. the first element is the
    // child binary, followed by the command line arguments that is requires.
    let argv = std::env::args().skip(1).collect();
    grate.run(argv);
}
