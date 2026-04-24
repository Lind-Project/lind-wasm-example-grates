mod handlers;

use grate_rs::{
    GrateBuilder, GrateError,
    constants::{
        SYS_CLONE, SYS_CLOSE, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_OPEN,
        SYS_READ, SYS_WRITE,
    },
};

fn main() {
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_CLOSE, handlers::close_handler)
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
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[devnull-grate] error: {:?}", e);
            }
        })
        .run(argv);
}
