pub mod constants;

use core::ffi::{c_char, c_int};
use libc::{close, pid_t, read, write};
use std::ffi::{CString, c_uint, c_void};
use std::ptr;

use std::io::Write;

const ELINDAPIABORTED: u64 = 0xE001_0001;

/// Wrapper macro for calling libc functions/syscalls with error handling.
///
/// ### Usage:
///     let result: Result<i32, GrateError> = call_sys!(function_name(..args..));
///
/// ### Returns:
///     Err(GrateError::CoordinationError) // if the function returns < 0
///     Ok(ret) // otherwise
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
            clean_exit(0);
        }
        ret
    }};
}

fn clean_exit(status: i32) -> ! {
    std::io::stdout().flush().unwrap();
    std::io::stderr().flush().unwrap();

    std::process::exit(status);
}

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

unsafe extern "C" {
    /// External function bindings. We use `link_name` to map Rust names to their sysroot equivalents.
    #[link_name = "register_handler"]
    fn register_handler_impl(
        cageid: u64,
        syscall_nr: u64,
        handle_flag: u64,
        grateid: u64,
        fn_ptr_addr: u64,
    ) -> c_int;

    #[link_name = "copy_data_between_cages"]
    fn cp_data_impl(
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
    fn make_syscall_impl(
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
    fn getpid_impl() -> pid_t;

    fn fork() -> pid_t;
    fn execv(prog: *const c_char, argv: *const *const c_char) -> c_int;
    fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
    fn pipe(fds: *mut c_int) -> c_int;
}

// Wrap register_handler, copy_data_between_cages, and getpid to be more Rust-native.
//
// This allows us to use these functions without needing a myriad of unsafe blocks.
//
// Also sticks to the familiar syntax of Result<V, E> return types for these.

/// Register Handler for a syscall for a source cage to the the target grate.
pub fn register_handler(
    cageid: u64,
    syscall_nr: u64,
    register_flag: u64,
    grateid: u64,
    handler: SyscallHandler,
) -> Result<(), GrateError> {
    let fn_ptr_addr = handler as *const () as usize as u64;

    let ret = unsafe {
        register_handler_impl(
            cageid,
            syscall_nr,
            register_flag,
            grateid as u64,
            fn_ptr_addr,
        )
    };

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

        // Use pipes to synchronize grate-cage lifecycles.
        let mut fds = [0; 2];
        let _ = call_sys!(pipe(fds.as_mut_ptr()));

        let read_fd = fds[0];
        let write_fd = fds[1];

        let cstrings: Vec<CString> = argv[0..]
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();

        let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();

        c_argv.push(ptr::null_mut());

        let path = c_argv[0];

        match call_sys!(fork()) {
            0 => {
                // Child process - will become the cage.
                let _ = call_sys!(close(write_fd));

                // Wait for a ready signal from the grate before setting up and executing the cage.
                let mut buf: u8 = 0;
                let _ = call_sys!(read(read_fd, &mut buf as *mut u8 as *mut c_void, 1));

                let _ = call_sys!(close(read_fd));
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

                let _ = call_sys!(close(read_fd));

                // Register handlers with 3i.
                for (syscall_nr, handler) in &self.handlers {
                    match register_handler(cageid as u64, *syscall_nr, 1, grateid as u64, *handler)
                    {
                        Ok(_) => {}
                        Err(ret) => GrateBuilder::run_teardown(teardown, Err(ret)),
                    };
                }

                // Signal the cage process that handler registration is complete.
                let signal: u8 = 1;
                let _ = call_sys!(write(write_fd, &signal as *const u8 as *const c_void, 1));

                let _ = call_sys!(close(write_fd));

                // Wait for the cage process to exit and retrieve its status code.
                let mut status: i32 = 0;
                let _ = call_sys!(waitpid(cageid, &mut status as *mut i32 as *mut c_int, 0));

                GrateBuilder::run_teardown(teardown, Ok(status));
            }
        }
    }
}
