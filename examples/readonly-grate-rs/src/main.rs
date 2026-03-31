// readonly-grate blocks all writes unconditionally
// by returning EPERM (operation not permitted).

use grate_rs::{GrateBuilder, GrateError, constants::SYS_WRITE};

// write() syscall handler
extern "C" fn write_syscall(
    _cageid: u64,
    _fd: u64,
    _fd_cage: u64,
    _buf: u64,
    _buf_cage: u64,
    _count: u64,
    _count_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    println!("[readonly-grate] Operation not permitted.");
    -1 // return EPERM (Opertation no permitted);
}

fn main() {
    // vector to store args passed along with the grate
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    let builder = GrateBuilder::new()
        .register(SYS_WRITE, write_syscall)
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(argv);
}
