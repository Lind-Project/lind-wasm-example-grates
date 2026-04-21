//! Public API for `grate-rs`.
//!
//! This module contains the safe, user-facing grate APIs:
//! - syscall registration and 3i wrappers
//! - grate dispatch entrypoint (`pass_fptr_to_wt`)
//! - the `GrateBuilder` lifecycle helpers

// Use and publicly export constants and grate-rs related ffi shims.
pub mod constants;
pub mod ffi;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CString, c_uint};
use std::ptr;

use crate::constants::lind::ELINDAPIABORTED;
use crate::constants::mman::*;
use crate::ffi::{
    clean_exit, cp_data_impl, execv, fork, getpid_impl, make_syscall_impl, mmap, munmap,
    register_handler_impl, sem_destroy, sem_init, sem_post, sem_t, sem_wait, waitpid,
};

/// Error types that can occur during grate execution.
#[derive(Debug)]
pub enum GrateError {
    /// OS errors that occur during setup.
    CoordinationError(String),
    /// Error returned by `register_handler`.
    HandlerRegistrationError(i32),
    /// Error returned by `copy_data_between_cages`.
    CopyDataError(i32),
    /// Make syscall error
    MakeSyscallError(i32),
}

/// The signature of a syscall handler function
pub type SyscallHandler = extern "C" fn(
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32;

/// Wrapper macro for calling libc/sysroot functions with uniform error handling, in the parent
/// grate.
///
/// ### Usage:
/// `let result: i32 = call_sys!(teardown, function_name(..args..));
///
/// ### Returns:
/// - returns the raw syscall result when non-negative
///
/// ### Errors:
/// - If syscall returns `< 0` value, print the error, run teardown function, exit with -1.
macro_rules! call_sys {
    ($teardown:expr, $fn:ident ( $($arg:expr),* $(,)?)) => {{
        let ret = unsafe { $fn($($arg),*) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1);

            println!("{} failed: {}", stringify!($fn), errno);

            GrateBuilder::run_teardown($teardown, Err(GrateError::CoordinationError(format!(
                            "{} failed: {}", stringify!($fn), errno)
                        )));
        }
        ret
    }};
}

/// Wrapper macro for calling libc/sysroot functions for the child cage.
///
/// ### Usage
/// `let result: i32 = call_sys_child!(state, function(..args..));
///
/// ### Returns
/// - Syscall return value if non-negative.
///
/// ### Errors
/// - On error (`< 0`), set the `state` struct's errno and failed, exit with -1.
/// - `state` is a shared LaunchState struct which inform the parent grate that the cage exited
/// without launching the binary through `execv`.
macro_rules! call_sys_child {
    ($state:expr, $fn:ident ( $($arg:expr),* $(,)?)) => {{
        let ret = unsafe { $fn($($arg),*) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(-1);

            // Set launch state to failed with errno.
            $state.errno = errno;
            $state.launch_failed = 1;

            println!("{} failed: {}", stringify!($fn), errno);

            $crate::ffi::clean_exit(-ret);
        }
        ret
    }};
}

/// Struct to coordinate lifecycle state between cage and grate.
#[repr(C)]
struct LaunchState {
    /// If non-0, indicates to the grate that the cage process exited before successfully calling
    /// `execv`
    launch_failed: i32,
    /// In case of a failed launch, sets the OS error that caused it.
    errno: i32,
}

pub unsafe fn mmap_shared<T>() -> &'static mut T {
    unsafe {
        let ptr = mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<T>(),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1,
            0,
        );

        if ptr == MAP_FAILED {
            let err = std::io::Error::last_os_error();
            println!("mmap failed: {}", err);

            clean_exit(0);
        }

        &mut *(ptr as *mut T)
    }
}

// Wrap raw FFI calls in Rust-friendly signatures to keep unsafe usage localized
// and expose idiomatic `Result`-based APIs to crate users.

/// Register Handler for a syscall for a source cage to the the target grate.
pub fn register_handler(
    cageid: u64,
    syscall_nr: u64,
    grateid: u64,
    handler: SyscallHandler,
) -> Result<(), GrateError> {
    let fn_ptr_addr = handler as *const () as usize as u64;

    let ret = unsafe { register_handler_impl(cageid, syscall_nr, grateid as u64, fn_ptr_addr) };

    match ret {
        0 => Ok(()),
        _ => Err(GrateError::HandlerRegistrationError(ret)),
    }
}

/// Copy data between two cages.
pub fn copy_data_between_cages(
    thiscage: u64,
    targetcage: u64,
    srcaddr: u64,
    srccage: u64,
    destaddr: u64,
    destcage: u64,
    len: u64,
    copytype: u64,
) -> Result<(), GrateError> {
    let ret = unsafe {
        cp_data_impl(
            thiscage, targetcage, srcaddr, srccage, destaddr, destcage, len, copytype,
        )
    };

    // 3i::copy_data_between_cages returns ELINDAPIABORTED for every error.
    match ret as u64 {
        ELINDAPIABORTED => Err(GrateError::CopyDataError(ELINDAPIABORTED as i32)),
        _ => Ok(()),
    }
}

/// Use threei to make a syscall.
pub fn make_threei_call(
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
) -> Result<i32, GrateError> {
    let ret = unsafe {
        make_syscall_impl(
            callnumber,
            callname,
            self_cageid,
            target_cageid,
            arg1,
            arg1cageid,
            arg2,
            arg2cageid,
            arg3,
            arg3cageid,
            arg4,
            arg4cageid,
            arg5,
            arg5cageid,
            arg6,
            arg6cageid,
            translate_errno,
        )
    };

    match ret {
        std::i32::MIN..=-1 => Err(GrateError::MakeSyscallError(ret)),
        _ => Ok(ret),
    }
}

/// Get the current cage ID.
pub fn getcageid() -> u64 {
    unsafe { getpid_impl() as u64 }
}

/// Check whether a SYS_CLONE call is a thread creation (not a process fork).
///
/// In Lind, `arg1` of SYS_CLONE is a pointer to `struct clone_args` in the
/// calling cage's memory. The `flags` field is the first u64 in the struct.
/// If `CLONE_VM` (0x100) is set, it's a thread; otherwise it's a process fork.
///
/// Grates should only copy fdtables on process forks, not thread clones
/// (threads share the parent's fd table).
pub fn is_thread_clone(clone_args_ptr: u64, clone_args_cage: u64) -> bool {
    let grate_cage = getcageid();
    let mut flags: u64 = 0;
    let _ = copy_data_between_cages(
        grate_cage, clone_args_cage,
        clone_args_ptr, clone_args_cage,
        &mut flags as *mut u64 as u64, grate_cage,
        8, 0,
    );
    (flags & constants::process::CLONE_VM) != 0
}

/// Dispatch function required by 3i to invoke registered syscall handlers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pass_fptr_to_wt(
    fn_ptr_uint: u64,
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> c_int {
    if fn_ptr_uint == 0 {
        eprintln!("[grate] invalid function pointer");
        return -1;
    }

    unsafe {
        let fn_ptr: extern "C" fn(
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
            u64,
        ) -> i32 = core::mem::transmute(fn_ptr_uint as usize);

        fn_ptr(
            cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4, arg4cage, arg5, arg5cage,
            arg6, arg6cage,
        )
    }
}

pub type GrateTeardownCallback = Box<dyn Fn(Result<i32, GrateError>)>;
pub type PreExecCallback = Box<dyn Fn(i32)>;

/// A builder for creating grates with customizable lifecycle hooks
pub struct GrateBuilder {
    handlers: Vec<(u64, SyscallHandler)>,
    teardown: Option<GrateTeardownCallback>,
    preexec: Option<PreExecCallback>,
}

impl GrateBuilder {
    /// Create an empty grate builder
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            teardown: None,
            preexec: None,
        }
    }

    /// Register a syscall handler
    pub fn register(mut self, syscall_nr: u64, handler: SyscallHandler) -> Self {
        self.handlers.push((syscall_nr, handler));
        self
    }

    /// Register a teardown callback function. Run after cage exits.
    pub fn teardown<F>(mut self, callback: F) -> Self
    where
        F: Fn(Result<i32, GrateError>) + 'static,
    {
        self.teardown = Some(Box::new(callback));
        self
    }

    /// Register a pre-exec callback function. Run after fork, but before exec.
    pub fn preexec<F>(mut self, callback: F) -> Self
    where
        F: Fn(i32) + 'static,
    {
        self.preexec = Some(Box::new(callback));
        self
    }

    /// Run a GrateTeardownCallback with the Result from `run`
    /// - This is a terminal function.
    /// - Must always be called from the parent grate.
    fn run_teardown(callback: Option<GrateTeardownCallback>, result: Result<i32, GrateError>) -> ! {
        let exit_code = match &result {
            Ok(status) => *status,
            Err(_) => 1,
        };
        match callback {
            Some(f) => {
                f(result);
                clean_exit(exit_code);
            }
            None => {
                clean_exit(exit_code);
            }
        }
    }

    /// Build and run the grate.
    ///
    /// This spawns a child cage process and registers handlers in the parent grate process.
    /// Raw process/memory synchronization primitives are provided by the internal `ffi` module.
    /// ### Inputs
    ///     arg_vector: Vec<String>     // char* argv[] that is passed down to exec.
    ///                                 // arg_vector[0] must be the cage binary to run.
    /// ### Behavior
    /// This function is terminal, which run the grate's teardown function upon exit.
    pub fn run(mut self, arg_vector: Vec<String>) -> ! {
        let argv = arg_vector;
        let teardown = self.teardown.take();

        // Return early if no cage binary is provided.
        if argv.len() < 1 {
            GrateBuilder::run_teardown(
                teardown,
                Err(GrateError::CoordinationError(format!(
                    "No cage binary provided."
                ))),
            );
        }

        let grateid = getcageid();

        // Prepare the argv[0], and argv[0..] args for execv.
        let cstrings: Vec<CString> = argv[0..]
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();

        c_argv.push(ptr::null_mut());

        let path = c_argv[0];

        // Set up a shared semaphore to ensure child cage waits until all handler registrations are
        // complete before launching.
        let sem: &mut sem_t = unsafe { mmap_shared::<sem_t>() };
        call_sys!(teardown, sem_init(sem, 1, 0));

        // Set up the shared LaunchState to coordinate errnos in case of a failed cage launch
        let state: &mut LaunchState = unsafe { mmap_shared::<LaunchState>() };

        match call_sys!(teardown, fork()) {
            0 => {
                // Child Cage

                // Wait until parent indicates it's ready.
                call_sys_child!(state, sem_wait(sem));

                // Launch the child binary.
                call_sys_child!(state, execv(path, c_argv.as_ptr()));
                // Only launched when execv returns with a success.
                clean_exit(-1);
            }
            cageid => {
                // Parent cage - grate handler.

                // Register handlers with 3i.
                for (syscall_nr, handler) in &self.handlers {
                    match register_handler(cageid as u64, *syscall_nr, grateid as u64, *handler) {
                        Ok(_) => {}
                        Err(ret) => GrateBuilder::run_teardown(teardown, Err(ret)),
                    };
                }

                // Call the pre-exec hook if specified.
                if let Some(callback) = self.preexec.take() {
                    callback(cageid);
                }

                // Indicate to the child that it can begin execution.
                call_sys!(teardown, sem_post(sem));

                // Wait for the cage process to exit and retrieve its status code.
                let mut status: i32 = 0;
                let _ = call_sys!(
                    teardown,
                    waitpid(cageid, &mut status as *mut i32 as *mut c_int, 0)
                );

                // Clean up semaphores.
                call_sys!(teardown, sem_destroy(sem));
                call_sys!(
                    teardown,
                    munmap(sem as *mut sem_t as *mut c_void, size_of::<sem_t>())
                );

                // Check whether the cage launched successfully.
                let launch_failed = state.launch_failed;

                let result = if launch_failed != 0 {
                    let errno = state.errno;

                    // In case the cage binary was never run, return an Err.
                    Err(GrateError::CoordinationError(format!(
                        "Failed to launch grate with OS Error {}",
                        errno
                    )))
                } else {
                    // If a cage was launched, return an Ok() with it's status code.
                    Ok(status)
                };

                // Clean up LaunchState
                call_sys!(
                    teardown,
                    munmap(
                        state as *mut LaunchState as *mut c_void,
                        size_of::<LaunchState>()
                    )
                );

                // Run the teardown function and exit.
                GrateBuilder::run_teardown(teardown, result);
            }
        }
    }
}
