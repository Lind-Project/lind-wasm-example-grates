//! Internal libc/Lind FFI and ABI shim layer.
//!
//! This module contains:
//! - constants used for low-level memory/process primitives
//! - target-specific ABI type shims (for Lind compatibility)
//! - raw `extern "C"` bindings used by the safe APIs in `lib.rs`
use core::ffi::{c_char, c_int};
use libc::{pid_t, size_t};
use std::ffi::{c_uint, c_void};
use std::io::Write;

#[allow(non_camel_case_types)]
// Do not import off_t from libc since those are defined as i64.
pub type off_t = i32;

#[allow(non_camel_case_types)]
// We use 32-bit pointer width, which requires sem_t to be defined as an array of length 16.
#[repr(C)]
pub struct sem_t {
    __size: [c_char; 16],
}

// Lind-compatible stat struct.
#[repr(C)]
#[derive(Eq, PartialEq, Default, Debug)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: usize,
    pub st_nlink: u32,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: usize,
    pub st_blksize: i32,
    pub st_blocks: u32,
    //currently we don't populate or care about the time bits here
    pub st_atim: [u64; 2],
    pub st_mtim: [u64; 2],
    pub st_ctim: [u64; 2],
}

/// Flush stdio streams and terminate the process.
///
/// This helper is shared by both the public library logic (`lib.rs`) and
/// internal FFI error paths (`call_sys!`).
pub(crate) fn clean_exit(status: i32) -> ! {
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();

    std::process::exit(status);
}

// External function bindings. `link_name` is used where Rust symbol names differ
// from Lind sysroot symbols.
unsafe extern "C" {
    // Lind threei-specific functions.
    #[link_name = "register_handler"]
    pub(crate) fn register_handler_impl(
        cageid: u64,
        syscall_nr: u64,
        grateid: u64,
        fn_ptr_addr: u64,
    ) -> c_int;

    #[link_name = "copy_data_between_cages"]
    pub(crate) fn cp_data_impl(
        thiscage: u64,
        targetcage: u64,
        srcaddr: u64,
        srccage: u64,
        destaddr: u64,
        destcage: u64,
        len: u64,
        copytype: u64,
    ) -> c_int;

    #[link_name = "make_threei_call"]
    pub(crate) fn make_syscall_impl(
        callnumber: c_uint,
        callname: u64,
        self_cageid: u64,
        target_cageid: u64,
        arg1: u64,
        arg1cageid: u64,
        arg2: u64,
        arg2cageid: u64,
        arg3: u64,
        arg3cageid: u64,
        arg4: u64,
        arg4cageid: u64,
        arg5: u64,
        arg5cageid: u64,
        arg6: u64,
        arg6cageid: u64,
        translate_errno: c_int,
    ) -> c_int;

    // Helper to get the current cage ID.
    #[link_name = "getpid"]
    pub(crate) fn getpid_impl() -> pid_t;

    // Multiprocessing.
    pub fn fork() -> pid_t;
    pub fn execv(prog: *const c_char, argv: *const *const c_char) -> c_int;
    pub fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;

    // Memory management.
    pub fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, len: size_t) -> c_int;

    // POSIX semaphores.
    pub fn sem_init(sem: *mut sem_t, pshared: c_int, value: c_uint) -> c_int;
    pub fn sem_destroy(sem: *mut sem_t) -> c_int;
    pub fn sem_post(sem: *mut sem_t) -> c_int;
    pub fn sem_wait(sem: *mut sem_t) -> c_int;

    // Stat
    pub fn stat(path: *const c_char, buf: *mut stat) -> c_int;
}
