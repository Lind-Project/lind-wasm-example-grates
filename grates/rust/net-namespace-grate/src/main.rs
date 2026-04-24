//! Network Namespace Clamping Grate
//!
//! A meta-grate that selectively routes network syscalls to clamped grates
//! based on a port range condition. Sockets that bind or connect to ports
//! in the range get routed through the clamped grate stack.
//!
//! Usage: net-namespace-grate-rs --ports 8080-8090 %{ mtls-grate %} server

mod handlers;
mod helpers;

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::ptr;

use grate_rs::constants::mman::*;
use grate_rs::ffi::*;

struct NetNamespaceConfig {
    port_low: u16,
    port_high: u16,
    exec_chain: Vec<String>,
}

fn parse_argv(args: Vec<String>) -> Result<NetNamespaceConfig, String> {
    let mut port_range: Option<(u16, u16)> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--ports" => {
                i += 1;
                if i >= args.len() {
                    return Err("--ports requires an argument (e.g. 8080-8090)".into());
                }
                port_range = Some(parse_port_range(&args[i])?);
                i += 1;
            }
            "%{" => {
                i += 1;
                break;
            }
            other => {
                if let Some(val) = other.strip_prefix("--ports=") {
                    port_range = Some(parse_port_range(val)?);
                    i += 1;
                } else {
                    return Err(format!("unexpected argument: {}", other));
                }
            }
        }
    }

    let (port_low, port_high) = port_range.ok_or("--ports is required")?;

    if i >= args.len() {
        return Err("missing %{ ... %} block".into());
    }

    let exec_chain: Vec<String> = args[i..].to_vec();

    if !exec_chain.contains(&"%}".to_string()) {
        return Err("missing %} in command line".into());
    }

    Ok(NetNamespaceConfig {
        port_low,
        port_high,
        exec_chain,
    })
}

fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    if let Some((low_s, high_s)) = s.split_once('-') {
        let low: u16 = low_s.trim().parse()
            .map_err(|_| format!("invalid port: {}", low_s))?;
        let high: u16 = high_s.trim().parse()
            .map_err(|_| format!("invalid port: {}", high_s))?;
        if low > high {
            return Err(format!("port range is inverted: {}-{}", low, high));
        }
        Ok((low, high))
    } else {
        // Single port
        let port: u16 = s.trim().parse()
            .map_err(|_| format!("invalid port: {}", s))?;
        Ok((port, port))
    }
}

unsafe fn mmap_shared<T>() -> *mut T {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            std::mem::size_of::<T>(),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1, 0,
        )
    };
    if ptr == MAP_FAILED {
        std::process::exit(-1);
    }
    ptr as *mut T
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("Usage: net-namespace-grate-rs --ports <low>-<high> %{{ <grates...> %}} <program> [args...]");
        std::process::exit(1);
    }

    let config = match parse_argv(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[net-ns] argument error: {}", e);
            std::process::exit(1);
        }
    };

    helpers::init_globals(config.port_low, config.port_high);

    let cstrings: Vec<CString> = config
        .exec_chain
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    c_argv.push(ptr::null());
    let path = c_argv[0];

    let sem: *mut sem_t = unsafe { mmap_shared::<sem_t>() };
    if unsafe { sem_init(sem, 1, 0) } < 0 {
        std::process::exit(-1);
    }

    let child_pid = unsafe { fork() };
    if child_pid < 0 {
        std::process::exit(-1);
    }

    if child_pid == 0 {
        unsafe { sem_wait(sem) };
        let ret = unsafe { execv(path, c_argv.as_ptr()) };
        if ret < 0 {
            eprintln!("[net-ns] execv failed");
        }
        std::process::exit(-1);
    }

    let child_cage_id = child_pid as u64;

    helpers::register_clamped_cage(child_cage_id);
    fdtables::init_empty_cage(child_cage_id);

    handlers::register_lifecycle_handlers(child_cage_id);

    unsafe { sem_post(sem) };

    loop {
        let mut status: i32 = 0;
        let ret = unsafe { waitpid(-1, &mut status as *mut i32, 0) };
        if ret <= 0 {
            break;
        }
    }

    unsafe {
        sem_destroy(sem);
        munmap(sem as *mut c_void, std::mem::size_of::<sem_t>());
    }

    std::process::exit(0);
}
