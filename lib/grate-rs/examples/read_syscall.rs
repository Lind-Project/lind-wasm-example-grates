//! Minimal example showing how to by-pass the read syscall with a custom implemention.
//!
//! Highlights (grate-rs APIs used):
//! - `GrateBuilder`: configure and run a grate-managed cage
//! - `.register(syscall_num, handler)`: map a syscall number to a handler
//! - `getcageid()`: obtain the current cage id from inside a handler.
//! - `copy_data_between_cages(...)`: copy memory between cages.

use grate_rs::{GrateBuilder, GrateError, constants::SYS_READ, copy_data_between_cages, getcageid};
use std::cmp::min;

fn imfs_read(_cageid: u64, _fd: u64, buf: &mut [u8], count: usize) -> i32 {
    let n = min(count, buf.len());

    for i in 0..n {
        buf[i] = b'A';
    }

    n as i32
}

extern "C" fn read_syscall(
    cageid: u64,
    fd: u64,
    _fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    _count_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Equivalent to malloc(count)
    let mut buffer = vec![0u8; count as usize];
    let ptr = buffer.as_mut_ptr();

    // Call a dummy function that just puts "A" * count in the buffer
    let ret = imfs_read(cageid, fd, &mut buffer, count as usize);

    // Copy data to the calling cage.
    match copy_data_between_cages(
        thiscage, buf_cage, ptr as u64, thiscage, buf, buf_cage, count, 0,
    ) {
        Ok(_) => ret,
        Err(e) => {
            eprintln!("copy_data_between_cages failed: {:?}", e);
            -1
        }
    }
}

fn main() {
    println!(
        "[grate_init] Run all required initializations before calling builder.run(), such as imfs_init() or preloads()"
    );

    let builder = GrateBuilder::new()
        .register(SYS_READ, read_syscall)
        .teardown(|result: Result<i32, GrateError>| {
            println!("Result: {:#?}", result);
        });

    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    builder.run(argv);
}
