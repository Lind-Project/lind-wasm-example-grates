// write_filter-grate blocks all write related calls unconditionally
// for files with .log extension by returning EPERM (operation not permitted).

mod handlers;

use grate_rs::{
    GrateBuilder, GrateError,
    constants::{
        SYS_CLONE, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_OPEN, SYS_PWRITE, SYS_WRITE, SYS_WRITEV,
    },
};

fn main() {
    // vector to store args passed along with the grate
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    // register syscalls and run cage
    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_PWRITE, handlers::pwrite_handler)
        .register(SYS_WRITEV, handlers::writev_handler)
        .register(SYS_CLONE, handlers::fork_handler)
        .register(SYS_EXECVE, handlers::exec_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .preexec(|cageid: i32| {
            fdtables::init_empty_cage(cageid as u64);
            for fd in 0..3u64 {
                let _ = fdtables::get_specific_virtual_fd(cageid as u64, fd, 0, fd, false, 0);
            }
        })
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(argv);
}
