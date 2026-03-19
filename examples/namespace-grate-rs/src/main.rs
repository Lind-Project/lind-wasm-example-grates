//! Namespace Clamping Grate
//!
//! A meta-grate that selectively routes syscalls to clamped grates based on a
//! path-prefix condition. This interposes on register_handler, exec, fork, and
//! exit to dynamically build routing tables and conditionally dispatch syscalls.
//!
//! Usage: namespace-grate --prefix /tmp %{ imfs-grate strace-grate %} python

mod handlers;
mod helpers;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;
use std::ptr;

use grate_rs::getcageid;

// ── POSIX FFI (re-declared; grate-rs keeps these private) ─────────────────

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_SHARED: i32 = 0x01;
const MAP_ANON: i32 = 0x20;
const MAP_FAILED: *mut c_void = (-1isize) as *mut c_void;

#[allow(non_camel_case_types)]
type off_t = i32;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sem_t {
    __size: [c_char; 16],
}

unsafe extern "C" {
    fn fork() -> i32;
    fn execv(prog: *const c_char, argv: *const *const c_char) -> c_int;
    fn waitpid(pid: i32, status: *mut c_int, options: c_int) -> i32;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn sem_init(sem: *mut sem_t, pshared: c_int, value: u32) -> c_int;
    fn sem_destroy(sem: *mut sem_t) -> c_int;
    fn sem_post(sem: *mut sem_t) -> c_int;
    fn sem_wait(sem: *mut sem_t) -> c_int;
}

// ── Parsed command-line config ────────────────────────────────────────────

struct NamespaceConfig {
    /// The path prefix condition (e.g., "/tmp").
    prefix: String,
    /// The full exec chain: [clamped_grates..., "%}", unclamped_argv...].
    exec_chain: Vec<String>,
}

/// Parse argv into a NamespaceConfig.
///
/// Expected syntax: namespace-grate --prefix /tmp %{ imfs-grate strace-grate %} python
///
/// After parsing:
///   prefix = "/tmp"
///   exec_chain = ["imfs-grate", "strace-grate", "%}", "python"]
fn parse_argv(args: Vec<String>) -> Result<NamespaceConfig, String> {
    let mut prefix: Option<String> = None;
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

    Ok(NamespaceConfig { prefix, exec_chain })
}

// ── Shared memory helpers ─────────────────────────────────────────────────

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
        println!("[ns-grate] mmap failed");
        std::process::exit(-1);
    }
    ptr as *mut T
}

// ── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("Usage: namespace-grate --prefix <path> %{{ <grates...> %}} <program> [args...]");
        std::process::exit(1);
    }

    let config = match parse_argv(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ns-grate] argument error: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "[ns-grate] prefix={}, exec_chain={:?}",
        config.prefix, config.exec_chain
    );

    // Initialize global state.
    let ns_cage_id = getcageid();
    helpers::init_globals(ns_cage_id, config.prefix);

    // Prepare the exec chain as C strings.
    let cstrings: Vec<CString> = config
        .exec_chain
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    c_argv.push(ptr::null());
    let path = c_argv[0];

    // Allocate shared semaphore for synchronization.
    let sem: *mut sem_t = unsafe { mmap_shared::<sem_t>() };
    if unsafe { sem_init(sem, 1, 0) } < 0 {
        eprintln!("[ns-grate] sem_init failed");
        std::process::exit(-1);
    }

    // Fork the child cage.
    let child_pid = unsafe { fork() };
    if child_pid < 0 {
        eprintln!("[ns-grate] fork failed");
        std::process::exit(-1);
    }

    if child_pid == 0 {
        // ── Child ─────────────────────────────────────────────────────
        // Wait until parent has registered lifecycle handlers.
        unsafe { sem_wait(sem) };

        // Exec the first clamped grate (or %} if no clamped grates).
        let ret = unsafe { execv(path, c_argv.as_ptr()) };
        if ret < 0 {
            eprintln!("[ns-grate] execv failed");
        }
        std::process::exit(-1);
    }

    // ── Parent (namespace grate) ──────────────────────────────────────
    let child_cage_id = child_pid as u64;

    println!(
        "[ns-grate] forked child cage {} (ns_cage={})",
        child_cage_id, ns_cage_id
    );

    // Mark the child cage as clamped.
    helpers::register_clamped_cage(child_cage_id);

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
        println!("[ns-grate] child {} exited with status {}", ret, status);
    }

    // Cleanup.
    unsafe {
        sem_destroy(sem);
        munmap(sem as *mut c_void, std::mem::size_of::<sem_t>());
    }

    println!("[ns-grate] exiting");
    std::process::exit(0);
}
