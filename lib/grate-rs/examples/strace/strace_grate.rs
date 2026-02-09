mod strace;

use strace::{Arg, parse_arg};
use grate_rs::{GrateBuilder, make_threei_call};

// enum to maintain registered syscalls
enum Syscall {
    Read = 0,
    Open = 2,
    Mmap = 9,
}

// invoking macros to register syscall handler
//
// ARGS:
// 1. handler_name      - syscall handler name
// 2. syscall_number    - syscall number passed via "Syscall" enum 
// 3. [arg_type]        - argument types passed sequentially in a tuple

define_syscall_handler!(
    open_syscall,
    Syscall::Open as u32,
    [CString, Int, Int]
);

define_syscall_handler!(
    read_syscall,
    Syscall::Read as u32,
    [Int, CString, Int]
);

define_syscall_handler!(
    mmap_syscall,
    Syscall::Mmap as u32,
    [Int, Int, Int, Int, Int, Int ]
);

fn main() {
    println!("[Grate Init]: Initializing Strace Grate\n");
    
    // register syscall handlers
    let builder = GrateBuilder::new()
        .register((Syscall::Open as u32).into(), open_syscall)
        .register((Syscall::Read as u32).into(), read_syscall)
        .register((Syscall::Mmap as u32).into(), mmap_syscall);
    
    let argv = std::env::args().skip(1).collect::<Vec<_>>();

    match builder.run(argv) {
        Ok(status) => {
            println!("\n[Grate Teardown] Cage exited with : {status}. Safe to run teardown functions such as dump_file");
        }
        Err(e) => {
            eprintln!("[Grate Error] Failed to run grate: {:?}", e);
            std::process::exit(1);
        }
    }
}
