// readonly-grate blocks all writes unconditionally
// by returning -EPERM (operation not permitted).

use grate_rs::{
    GrateBuilder, GrateError,
    constants::{SYS_OPEN, SYS_PWRITE, SYS_WRITE, SYS_WRITEV, error::EPERM},
    make_threei_call,
};

// constants

const O_ACCMODE: u64 = 0o00000003;
const O_RDONLY: u64 = 0o00000000;
const O_TRUNC: u64 = 0o00001000;
const O_APPEND: u64 = 0o00002000;

// open() syscall handler
extern "C" fn open_syscall(
    cageid: u64,
    filename: u64,
    filename_cage: u64,
    flags: u64,
    flags_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let access_mode = flags & O_ACCMODE;

    // return -EPERM (Operation not permitted) if
    // access mode is O_WRONLY or O_RDWR
    if access_mode != O_RDONLY {
        return -EPERM;
    }

    // return -EPERM (Operation not permitted) if
    // access mode is O_WRONLY or O_RDWR
    if flags & (O_TRUNC | O_APPEND) != 0 {
        return -EPERM;
    }

    let ret = match make_threei_call(
        SYS_OPEN as u32,
        0,
        cageid,
        filename_cage,
        filename,
        filename_cage,
        flags,
        flags_cage,
        mode,
        mode_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "[readonly-grate]: make_threei_call() failed for SYS_OPEN with: {:?}",
                e
            );
            return -EPERM;
        }
    };

    ret
}

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
    -EPERM // return -EPERM (Operation not permitted);
}

// writev() syscall handler
extern "C" fn writev_syscall(
    _cageid: u64,
    _fd: u64,
    _fd_cage: u64,
    _iovec: u64,
    _iovec_cage: u64,
    _vlen: u64,
    _vlen_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    -EPERM // return -EPERM (Operation not permitted);
}

// pwrite() syscall handler
extern "C" fn pwrite_syscall(
    _cageid: u64,
    _fd: u64,
    _fd_cage: u64,
    _buf: u64,
    _buf_cage: u64,
    _count: u64,
    _count_cage: u64,
    _pos: u64,
    _pos_cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    -EPERM // return -EPERM (Operation not permitted);
}

fn main() {
    // vector to store args passed along with the grate
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    GrateBuilder::new()
        .register(SYS_OPEN, open_syscall)
        .register(SYS_WRITE, write_syscall)
        .register(SYS_PWRITE, pwrite_syscall)
        .register(SYS_WRITEV, writev_syscall)
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(argv);
}
