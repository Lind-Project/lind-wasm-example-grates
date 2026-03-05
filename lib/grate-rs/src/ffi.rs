use core::ffi::{c_char, c_int};
use libc::{pid_t, size_t};
use std::ffi::{c_uint, c_void};
use std::io::Write;

pub(crate) const PROT_READ: i32 = 0x1; // pages may be read
pub(crate) const PROT_WRITE: i32 = 0x2; // pages may be written

pub(crate) const MAP_SHARED: i32 = 0x01; // share mapping with other processes
pub(crate) const MAP_PRIVATE: i32 = 0x02; // Private Mapping
pub(crate) const MAP_ANON: i32 = 0x20; // mapping is not backed by a file (same as MAP_ANONYMOUS)
pub(crate) const MAP_FAILED: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;

#[allow(non_camel_case_types)]
// Do not import off_t from libc since those are defined as i64.
type off_t = i32;

#[allow(non_camel_case_types)]
#[repr(C)]
pub(crate) struct sem_t {
    __size: [c_char; 16],
}

/// Wrapper macro for calling libc functions/syscalls with error handling.
///
/// ### Usage:
///     let result: Result<i32, GrateError> = call_sys!(function_name(..args..));
///
/// ### Returns:
///     Err(GrateError::CoordinationError) // if the function returns < 0
///     Ok(ret) // otherwise
#[macro_export]
macro_rules! call_sys {
    ($fn:ident ( $($arg:expr),* $(,)?)) => {{
        let ret = unsafe { $fn($($arg),*) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            println!("{:#?}", Err::<(), _>(GrateError::CoordinationError(
                format!(
                    "{} failed: {}",
                    stringify!($fn),
                    err,
                )
            )));
            $crate::ffi::clean_exit(0);
        }
        ret
    }};
}

pub fn clean_exit(status: i32) -> ! {
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();

    std::process::exit(status);
}

// External function bindings. We use `link_name` to map Rust names to their sysroot equivalents.
unsafe extern "C" {
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

    #[link_name = "getpid"]
    pub(crate) fn getpid_impl() -> pid_t;

    pub(crate) fn fork() -> pid_t;
    pub(crate) fn execv(prog: *const c_char, argv: *const *const c_char) -> c_int;
    pub(crate) fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;

    pub(crate) fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    pub(crate) fn munmap(addr: *mut c_void, len: size_t) -> c_int;

    pub(crate) fn sem_init(sem: *mut sem_t, pshared: c_int, value: c_uint) -> c_int;
    pub(crate) fn sem_destroy(sem: *mut sem_t) -> c_int;
    pub(crate) fn sem_post(sem: *mut sem_t) -> c_int;
    pub(crate) fn sem_wait(sem: *mut sem_t) -> c_int;
}
