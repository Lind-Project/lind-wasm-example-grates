// readonly-grate blocks all writes unconditionally
// by returning EPERM (operation not permitted).

use grate_rs::{
    GrateBuilder, GrateError,
    constants::{SYS_OPEN, SYS_WRITE, error::EPERM},
    copy_data_between_cages, getcageid, make_threei_call,
};
use std::{path::Path, sync::Mutex};

const MAX_PATH: usize = 256;

// struct to store file metadata
struct File {
    log_ext: bool,
    fd: u64,
}

static FILE: Mutex<Option<File>> = Mutex::new(None);

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
    let this_cage = getcageid();

    let mut buf = vec![0u8; MAX_PATH];

    // copy filname passed to open()
    let _ = copy_data_between_cages(
        this_cage,
        filename_cage,
        filename,
        filename_cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        MAX_PATH as u64,
        1,
    );

    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH);
    let path_str = match String::from_utf8(buf[..len].to_vec()) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("[write_filter-grate] file path conversion failed: {}", e);
            return -1;
        }
    };

    // extracts file path slice
    let file_path = Path::new(&path_str);

    // extract extension from the file_path
    let file_ext = file_path.extension().and_then(|s| s.to_str());

    // forward open() syscall
    let ret = match make_threei_call(
        SYS_OPEN as u32,
        0,
        this_cage,
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
        Ok(ret) => ret,
        Err(_) => -1,
    };

    // initialize File struct if opened .log file
    if file_ext == Some("log") {
        let mut lock_guard = FILE.lock().unwrap();
        *lock_guard = Some(File {
            log_ext: true,
            fd: ret as u64,
        });
    }

    ret
}

// write() syscall handler
extern "C" fn write_syscall(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    count_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    // forwards write call only if .log file was opened
    let mut lock_guard = FILE.lock().unwrap();
    if let Some(ref file_data) = *lock_guard {
        if file_data.log_ext == true && file_data.fd == fd {
            let ret = match make_threei_call(
                SYS_WRITE as u32,
                0,
                this_cage,
                fd_cage,
                fd,
                fd_cage,
                buf,
                buf_cage,
                count,
                count_cage,
                arg4,
                arg4cage,
                arg5,
                arg5cage,
                arg6,
                arg6cage,
                0,
            ) {
                Ok(ret) => ret,
                Err(_) => -1,
            };
            lock_guard.take();
            return ret;
        }
    }

    // return EPERM (Operation not permitted)
    EPERM
}

fn main() {
    // vector to store args passed along with the grate
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    // register syscalls and run cage
    GrateBuilder::new()
        .register(SYS_OPEN, open_syscall)
        .register(SYS_WRITE, write_syscall)
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(argv);
}
