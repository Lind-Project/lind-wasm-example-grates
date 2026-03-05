pub mod constants;
mod ffi;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CString, c_uint};
use std::ptr;

use crate::ffi::{
    MAP_ANON, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, clean_exit, cp_data_impl, execv, fork,
    getpid_impl, make_syscall_impl, mmap, munmap, register_handler_impl, sem_destroy, sem_init,
    sem_post, sem_t, sem_wait, waitpid,
};

const ELINDAPIABORTED: u64 = 0xE001_0001;

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

// Wrap register_handler, copy_data_between_cages, and getpid to be more Rust-native.
//
// This allows us to use these functions without needing a myriad of unsafe blocks.
//
// Also sticks to the familiar syntax of Result<V, E> return types for these.

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

/// A builder for creating grates with customizable lifecycle hooks
pub struct GrateBuilder {
    handlers: Vec<(u64, SyscallHandler)>,
    teardown: Option<GrateTeardownCallback>,
}

impl GrateBuilder {
    /// Create an empty grate builder
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            teardown: None,
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

    /// Run a GrateTeardownCallback with the Result from `run`
    fn run_teardown(callback: Option<GrateTeardownCallback>, result: Result<i32, GrateError>) -> ! {
        match callback {
            Some(f) => {
                f(result);
                clean_exit(0);
            }
            None => {
                clean_exit(0);
            }
        }
    }

    /// Build and run the grate.
    ///
    /// This spawns a child cage process and registers handlers in the parent grate process.
    /// ### Inputs
    ///     arg_vector: Vec<String>     // char* argv[] that is passed down to exec.
    ///                                 // arg_vector[0] must be the cage binary to run.
    /// ### Returns
    ///     Err(GrateError)             // On failure.
    ///     Ok(ExitStatus)              // Cage exit status.
    pub fn run(mut self, arg_vector: Vec<String>) {
        #[cfg(target_pointer_width = "64")]
        {
            println!("compiled with 64-bit sem_t");
        };

        #[cfg(target_pointer_width = "32")]
        {
            println!("compiled with 32-bit sem_t");
        };

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

        let cstrings: Vec<CString> = argv[0..]
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();

        c_argv.push(ptr::null_mut());

        let path = c_argv[0];
        /*
            sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANON, -1, 0);
            sem_init(sem, 1, 0);
        */

        let sem: &mut sem_t = unsafe {
            let ptr = mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<sem_t>(),
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANON,
                -1,
                0,
            );

            if ptr == MAP_FAILED {
                let err = std::io::Error::last_os_error();
                println!(
                    "{:#?}",
                    Err::<(), _>(GrateError::CoordinationError(format!(
                        "mmap failed: {}",
                        err
                    )))
                );
                clean_exit(0);
            }

            &mut *(ptr as *mut sem_t)
        };

        call_sys!(sem_init(sem, 1, 0));

        match call_sys!(fork()) {
            0 => {
                // sem_wait(sem);
                call_sys!(sem_wait(sem));

                let _ = call_sys!(execv(path, c_argv.as_ptr()));
                GrateBuilder::run_teardown(
                    teardown,
                    Err(GrateError::CoordinationError(format!(
                        "execv failed: child returned post exec"
                    ))),
                );
            }
            cageid => {
                // Parent process - the grate handler.

                // Register handlers with 3i.
                for (syscall_nr, handler) in &self.handlers {
                    match register_handler(cageid as u64, *syscall_nr, grateid as u64, *handler) {
                        Ok(_) => {}
                        Err(ret) => GrateBuilder::run_teardown(teardown, Err(ret)),
                    };
                }

                // sem_post(sem);
                call_sys!(sem_post(sem));

                // Wait for the cage process to exit and retrieve its status code.
                let mut status: i32 = 0;
                let _ = call_sys!(waitpid(cageid, &mut status as *mut i32 as *mut c_int, 0));

                // sem_destroy(sem);
                // munmap(sem, sizeof(*sem));

                call_sys!(sem_destroy(sem));
                call_sys!(munmap(sem as *mut sem_t as *mut c_void, size_of::<sem_t>()));

                GrateBuilder::run_teardown(teardown, Ok(status));
            }
        }
    }
}
