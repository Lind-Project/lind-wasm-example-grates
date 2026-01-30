use grate_rs::{GrateBuilder, copy_data_between_cages, getcageid};
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
    println!("[grate_init] Run any init stuff here, such as imfs_init() or preloads()");

    let builder = GrateBuilder::new()
        .register(0, read_syscall)
        .cage_init(|| println!("[cage_init] Code to run post-fork but pre-exec"));

    match builder.run() {
        Ok(status) => {
            println!(
                "[grate_teardown] Cage exited with: {status}. Run teardown functions such as dump_file()"
            );
        }
        Err(e) => {
            eprintln!("[grate_error] Failed to run grate: {:?}", e);
            std::process::exit(1);
        }
    }
}
