//! FS Routing Clamp
//!
//! A meta-grate that selectively routes syscalls to clamped grates based on a
//! path-prefix condition. This interposes on register_handler, exec, fork, and
//! exit to dynamically build routing tables and conditionally dispatch syscalls.
//!
//! Usage: fs-routing-clamp --prefix /tmp %{ imfs-grate strace-grate %} python

mod handlers;
mod helpers;

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::ptr;

use grate_rs::getcageid;

use grate_rs::constants::mman::*;
use grate_rs::ffi::*;

struct NamespaceConfig {
    /// The path prefix condition (e.g., "/tmp").
    prefix: String,
    /// The full exec chain: [clamped_grates..., "%}", unclamped_argv...].
    exec_chain: Vec<String>,
    /// Whether internal logging is enabled.
    log_enabled: bool,
}

/// Parse argv into a NamespaceConfig.
///
/// Expected syntax: fs-routing-clamp --prefix /tmp %{ imfs-grate strace-grate %} python
///
/// After parsing:
///   prefix = "/tmp"
///   exec_chain = ["imfs-grate", "strace-grate", "%}", "python"]
fn parse_argv(args: Vec<String>) -> Result<NamespaceConfig, String> {
    let mut prefix: Option<String> = None;
    let mut log_enabled = false;
    let mut i = 0;

    // Parse options before %{
    while i < args.len() {
        match args[i].as_str() {
            "--prefix" => {
                i += 1;
                if i >= args.len() {
                    return Err("--prefix requires an argument".into());
                }
                prefix = Some(args[i].clone());
                i += 1;
            }
            "--log" => {
                log_enabled = true;
                i += 1;
            }
            "%{" => {
                i += 1;
                break;
            }
            other => {
                // Check for --prefix=value syntax
                if let Some(val) = other.strip_prefix("--prefix=") {
                    prefix = Some(val.to_string());
                    i += 1;
                } else {
                    return Err(format!("unexpected argument: {}", other));
                }
            }
        }
    }

    let prefix = prefix.ok_or("--prefix is required")?;

    if i >= args.len() {
        return Err("missing %{ ... %} block".into());
    }

    // Everything from here is the exec chain (clamped args, %}, unclamped args).
    // The exec chain is passed as-is to the first clamped grate.
    let exec_chain: Vec<String> = args[i..].to_vec();

    if !exec_chain.contains(&"%}".to_string()) {
        return Err("missing %} in command line".into());
    }

    Ok(NamespaceConfig {
        prefix,
        exec_chain,
        log_enabled,
    })
}

unsafe fn mmap_shared<T>() -> *mut T {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            std::mem::size_of::<T>(),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED {
        log_error!("mmap failed");
        std::process::exit(-1);
    }
    ptr as *mut T
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log_enabled = args.iter().any(|arg| arg == "--log");
    helpers::init_logging(log_enabled);

    if args.is_empty() {
        eprintln!(
            "Usage: fs-routing-clamp [--log] --prefix <path> %{{ <grates...> %}} <program> [args...]"
        );
        std::process::exit(1);
    }

    let config = match parse_argv(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("argument error: {}", e);
            std::process::exit(1);
        }
    };

    let prefix = config.prefix;
    let exec_chain = config.exec_chain;
    let log_enabled = config.log_enabled;

    log!("prefix={}, exec_chain={:?}", prefix, exec_chain);

    // Initialize global state.
    let ns_cage_id = getcageid();
    helpers::init_globals(ns_cage_id, prefix, log_enabled);

    // Prepare the exec chain as C strings.
    let cstrings: Vec<CString> = exec_chain
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    c_argv.push(ptr::null());
    let path = c_argv[0];

    // Allocate shared semaphore for synchronization.
    let sem: *mut sem_t = unsafe { mmap_shared::<sem_t>() };
    if unsafe { sem_init(sem, 1, 0) } < 0 {
        log_error!("sem_init failed");
        std::process::exit(-1);
    }

    // Fork the child cage.
    let child_pid = unsafe { fork() };
    if child_pid < 0 {
        log_error!("fork failed");
        std::process::exit(-1);
    }

    if child_pid == 0 {
        // Wait until parent has registered lifecycle handlers.
        unsafe { sem_wait(sem) };

        // Exec the first clamped grate (or %} if no clamped grates).
        let ret = unsafe { execv(path, c_argv.as_ptr()) };
        if ret < 0 {
            log_error!("execv failed");
        }
        std::process::exit(-1);
    }

    let child_cage_id = child_pid as u64;

    log!(
        "forked child cage {} (ns_cage={})",
        child_cage_id,
        ns_cage_id
    );

    // Mark the child cage as clamped, initialize fdtable entry.
    helpers::register_clamped_cage(child_cage_id);
    fdtables::init_empty_cage(child_cage_id);

    // Register lifecycle handlers on the child cage.
    handlers::register_lifecycle_handlers(child_cage_id);

    // Signal the child to proceed.
    unsafe { sem_post(sem) };

    // Wait for all children.
    loop {
        let mut status: i32 = 0;
        let ret = unsafe { waitpid(-1, &mut status as *mut i32, 0) };
        if ret <= 0 {
            break;
        }
        log!("child {} exited with status {}", ret, status);
    }

    // Cleanup.
    unsafe {
        sem_destroy(sem);
        munmap(sem as *mut c_void, std::mem::size_of::<sem_t>());
    }

    log!("exiting");
    std::process::exit(0);
}
