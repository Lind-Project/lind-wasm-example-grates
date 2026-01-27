// Rust port of the geteuid grate example from examples/geteuid-grate
//
// A grate is a process that intercepts and handles system calls for child
// processes called "cages".
//
// This example demonstrates how to create a grate
// that intercepts the geteuid() syscall and returns a hardcoded value instead
// of the real effective user ID.
//
// Key Rust-specific changes from the C version:
// - Uses extern "C" blocks to declare C functions that will be linked at runtime
// - Requires unsafe blocks for FFI calls and pointer operations
// - Uses #[unsafe(no_mangle)] to export the dispatcher function to C
// - Leverages Rust's ownership system for string handling before FFI conversion

use core::ffi::{c_char, c_int, c_void};
use libc::{EXIT_FAILURE, perror, pid_t};
use std::ffi::CString;
use std::{env, ptr};

// External C functions that will be linked at runtime by the Lind sysroot
//
// These functions are provided by the Lind runtime for:
// - register_handler: Intercepting syscalls from cages
// - geteuid/getpid/fork/execv/waitpid: Standard system calls available in Lind's sysroot
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
    pub fn pipe(fds: *mut c_int) -> c_int;
}

// Dispatcher function
//
// Entry point into a grate when a child cage invokes a registered
// syscall. This function is used to invoke the appropriate handler,
// and the value returned is passed down to the calling cage.
//
// Args:
// 	fn_ptr_uint	Address of the registered syscall handler within the
// 			grate's address space.
// 	cageid		Identifier of the calling cage.
// 	arg[1-6]	Syscall arguments. Numeric types are passed by value, pointers
// 			are passed as addresses in the originating cage's address space.
// 	arg[1-6]cage	Cage IDs corresponding to each argument, indicating which cage's address
// 			space the argument belongs to.
//
// This function must be exported with #[unsafe(no_mangle)] for C interop

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

        // Call the handler function with all arguments passed through
        fn_ptr(
            cageid, arg1, arg1cage, arg2, arg2cage, arg3, arg3cage, arg4, arg4cage, arg5, arg5cage,
            arg6, arg6cage,
        )
    }
}

// The actual geteuid syscall handler
//
// This function replaces the real geteuid syscall. When a cage calls geteuid(),
// this handler is invoked instead and returns a hardcoded value (4321).
// In a real implementation, this could perform custom logic like checking
// permissions or returning different values based on cage context.
//
// The signature matches what the dispatcher expects to call.
extern "C" fn geteuid_grate(
    cageid: u64,
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
    println!("[grate] In geteuid_grate handler for cage: {}", cageid);

    // Return a hardcoded geteuid value
    4321
}

// Main function - implements the standard grate process lifecycle
//
// The main function will always be similar in all grates. It performs the
// following steps:
// 1. Validate command line arguments (needs as least the cage program to execute)
// 2. Fork to create the child cage which executes the input binary.
// 3. In the cage: Wait for grate to complete registrations, then exec the cage binary.
// 4. In the grate: Register handlers for the cage, send a ready signal to the cage, wait for cage
//    to exit
//
// Because cages are unaware of grates, the grate instance manages the exec
// logic. It forks and execs exactly once to execute the child binary provided
// as argv[1], passing argv[1..] as that program's command-line arguments.
// Any further process management is handled by the executed program.
//
// The entire main function is unsafe because it performs:
// - FFI calls to C functions
// - Raw pointer manipulation for execv arguments
// - Direct process management (fork, exec, wait)

fn main() {
    let argv: Vec<String> = env::args().collect();

    // Should be at least two inputs (at least one grate file and one cage file)
    if argv.len() < 2 {
        eprintln!("Usage: {} <cage_file>", argv[0]);
        std::process::exit(libc::EXIT_FAILURE);
    }
    unsafe {
        // Get the grate's process ID (used as grate identifier)
        let grateid: pid_t = getpid();

        // In this model, we register handlers in the grate rather than the cage.
        //
        // This requires us to coordinate the grate and cage lifecycles so that the cage is aware
        // of when it's okay to proceed with exec-ing the cage binary.
        //
        // We use pipes to achieve this. The child cage listens for the ready signal from the
        // parent grate that is sent after the handler registration process is complete.
        let mut fds = [0; 2];
        if pipe(fds.as_mut_ptr()) != 0 {
            perror(b"pipe failed\0".as_ptr() as *const _);
        }

        let read_fd = fds[0];
        let write_fd = fds[1];

        // Fork to create a child process that will become the cage
        let cageid: pid_t = fork();
        if cageid < 0 {
            perror(b"fork failed\0".as_ptr() as *const _);
            libc::_exit(EXIT_FAILURE);
        } else if cageid == 0 {
            // Child process - this becomes the cage

            // Before we exec the child cage, we need to wait for the parent grate to
            // finish the required setup process. In this example, the setup process
            // involves registering a handler for the geteuid syscall.
            libc::close(write_fd);

            let mut buf: u8 = 0;
            libc::read(read_fd, &mut buf as *mut u8 as *mut c_void, 1);

            libc::close(read_fd);

            // Prepare arguments for execv - convert Rust String to C-compatible format
            // This involves creating owned CString objects to ensure null-termination
            // and proper lifetime management before passing raw pointers to C
            let mut cstrings: Vec<CString> = argv[1..]
                .iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();

            let mut c_argv: Vec<*mut i8> =
                cstrings.iter_mut().map(|s| s.as_ptr() as *mut i8).collect();

            c_argv.push(ptr::null_mut()); // Null terminate the argument array

            // Execute the target program (argv[1]) with the remaining arguments
            let path = CString::new(argv[1].as_str()).unwrap();
            execv(path.as_ptr(), c_argv.as_ptr());

            perror(b"execv failed\0".as_ptr() as *const _);
            libc::_exit(EXIT_FAILURE);
        }
        // Parent process - Register handlers for the cage, wait for it to exit.

        libc::close(read_fd);

        // Register the geteuid handler for this cage
        // syscall_nr = 107 (geteuid), handle_flag = 1 (register)
        // Syntax of register_handler:
        //   register_handler(
        //     cageid,        - Cage ID to be intercepted
        //     syscall_nr,    - Syscall number to be intercepted (107 = geteuid)
        //     handle_flag,   - 0 for deregister, non-0 for register
        //     grateid,       - Grate ID to redirect call to
        //     fn_ptr_addr    - Handler function pointer
        //   )
        let fn_ptr_addr = geteuid_grate as *const () as usize as u64;
        println!(
            "[grate] Registering geteuid handler for cage {} in grate {} with fn ptr addr: {}",
            cageid, grateid, fn_ptr_addr
        );
        let ret = register_handler(cageid as u64, 107, 1, grateid as u64, fn_ptr_addr);

        if ret != 0 {
            eprintln!("[grate] failed to register syscall {} (ret={})", 107, ret);
            libc::_exit(EXIT_FAILURE);
        }

        // Signal to the child cage that it can proceed with executing the program.
        let signal: u8 = 1;
        libc::write(write_fd, &signal as *const u8 as *const c_void, 1);

        libc::close(write_fd);

        waitpid(cageid, ptr::null_mut(), 0);
        libc::_exit(0);
    }
}
