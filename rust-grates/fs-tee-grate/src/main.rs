use std::ffi::{CString, c_char};

use grate_rs::{
    ffi::{execv, fork, sem_init, sem_post, sem_t, sem_wait, waitpid},
    getcageid,
};

use crate::{
    handlers::register_lifecycle_handlers,
    tee::{TEE_STATE, TeeState},
};

mod handlers;
mod tee;
mod utils;

fn to_exec_argv(args: &[String]) -> (Vec<CString>, Vec<*const c_char>) {
    // println!("[to_exec_argv] {:?}", args);
    let cstrings: Vec<CString> = args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();

    let mut argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();

    argv.push(std::ptr::null());

    println!("[to_exec_argv] {:?} {:?}", cstrings, argv);
    (cstrings, argv)
}

fn create_sem() -> *mut sem_t {
    let sem: &mut sem_t = unsafe { grate_rs::mmap_shared() };

    unsafe { sem_init(sem, 1, 0) };

    return sem;
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    *TEE_STATE.lock().unwrap() = Some(TeeState::new());
    let (_storage, c_argv) = to_exec_argv(&argv);

    let mut exec_sem = create_sem();

    let child_cage = unsafe { fork() };
    if child_cage == 0 {
        unsafe { sem_wait(exec_sem) };

        let exec_ret = unsafe { execv(c_argv[0], c_argv.as_ptr()) };
        println!("[tetrs] exec_ret: {exec_ret}");
        std::process::exit(1);
    }

    register_lifecycle_handlers(child_cage as u64);

    unsafe { sem_post(exec_sem) };

    loop {
        let mut status: i32 = 0;
        let ret = unsafe { waitpid(-1, &mut status as *mut i32, 0) };
        if ret <= 0 {
            break;
        }
        println!("[tetrs] child {} exited with status {}", ret, status);
    }
}
