// Rust port of the geteuid grate example from examples/geteuid-grate
//
// Key Rust-specific changes from the C version:
// - Uses extern "C" blocks to declare C functions that will be linked at runtime
// - Requires unsafe blocks for FFI calls and pointer operations
// - Uses #[unsafe(no_mangle)] to export the dispatcher function to C
// - Leverages Rust's ownership system for string handling before FFI conversion

use core::ffi::{c_int, c_char};
use libc::{EXIT_FAILURE, perror, pid_t};
use std::ffi::CString;
use std::{env, ptr};

// External C functions that will be linked at runtime by the Lind sysroot
// 
// Since `register_handler` and `copy_data_between_cages` are defined in C, 
// they require an unsafe extern "C" block. 
unsafe extern "C" {
    // Register a syscall handler for a specific cage
    // This function is provided by the Lind runtime for intercepting syscalls
    pub fn register_handler(
        cageid: u64,
        syscall_nr: u64,
        handle_flag: u64,
        grateid: u64,
        fn_ptr_addr: u64,
    ) -> c_int;

    // Standard libc functions available in Lind's sysroot (not in WASI and in turn not in libc::WASI)
    pub fn geteuid() -> i32;
    pub fn getpid() -> pid_t;
    pub fn fork() -> pid_t;
    pub fn execv(prog: *const c_char, argv: *const *mut c_char) -> c_int;
    pub fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
}

// Dispatcher function - must be exported with no_mangle for C interop
//
// This is the entry point called by the Lind runtime when an intercepted
// syscall occurs. The #[unsafe(no_mangle)] attribute prevents Rust from
// mangling the function name, making it callable from C code.

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
        println!("[grate] invalid function pointer");
        return -1;
    }

    unsafe {
        // Cast the u64 function pointer back to a callable function
        // This uses transmute to convert between pointer types, which is unsafe
        let fn_ptr: extern "C" fn(
            u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
        ) -> i32 = core::mem::transmute(fn_ptr_uint as usize);

        // Call the handler function with all arguments passed through
        fn_ptr(
            cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4, arg4cage, arg5, arg5cage,
            arg6, arg6cage,
        )
    }
}

// The actual geteuid syscall handler
//
// This function replaces the real geteuid syscall.
//
// The signature matches what the dispatcher expects to call.
extern "C" fn geteuid_grate(
    _cageid: u64,   
    _arg1: u64,     
    _arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    4321  
}

// Main function - wrapped in unsafe block due to FFI and pointer operations
//
// The entire main function is unsafe because it performs:
// - FFI calls to C functions
// - Raw pointer manipulation for execv arguments
// - Direct process management (fork, exec, wait)

fn main() {
    let argv: Vec<String> = env::args().collect();

    unsafe {
        // Get the grate's process ID (used as grate identifier)
        let grateid: pid_t = getpid();

        // Fork to create a child process that will become the cage
        let pid: pid_t = fork();
        if pid < 0 {
            perror(b"fork failed\0".as_ptr() as *const _);
            libc::_exit(EXIT_FAILURE);
        } else if pid == 0 {
            // Child process - this becomes the cage

            let cageid = getpid() as u64;

            // Register the geteuid handler for this cage
            // syscall_nr = 107 (geteuid), handle_flag = 1 (register)
            let fn_ptr_addr = geteuid_grate as *const () as usize as u64;
            let ret = register_handler(cageid, 107, 1, grateid as u64, fn_ptr_addr);

            if ret != 0 {
                eprintln!(
                    "[grate] failed to register syscall {} (ret={})",
                    107, ret
                );
                libc::_exit(EXIT_FAILURE);
            }

            // Prepare arguments for execv - convert Rust String to C-compatible format
            // This involves creating owned CString objects to ensure null-termination
            // and proper lifetime management before passing raw pointers to C
            let mut cstrings: Vec<CString> = argv[1..]
                .iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();

            let mut c_argv: Vec<*mut i8> =
                cstrings.iter_mut().map(|s| s.as_ptr() as *mut i8).collect();

            c_argv.push(ptr::null_mut());  // Null terminate the argument array

            // Execute the target program (argv[1]) with the remaining arguments
            let path = CString::new(argv[1].as_str()).unwrap();
            execv(path.as_ptr(), c_argv.as_ptr());

            perror(b"execv failed\0".as_ptr() as *const _);
            libc::_exit(EXIT_FAILURE);
        } else {
            // Parent process - wait for the child to complete
            waitpid(pid, ptr::null_mut(), 0);
            libc::_exit(0);
        }
    }
}
