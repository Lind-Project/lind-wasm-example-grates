//! Tee grate — duplicates syscalls across two independent handler chains.
//!
//! Usage:
//!   tee-grate --primary <primary-grate> --secondary <secondary-grate> \
//!             [--log <logfile>] [--buffer-limit <bytes>] \
//!             -- <program> [args...]
//!
//! Or inline clamping style:
//!   tee-grate %{ <secondary-grate> %} <program> [args...]
//!
//! The tee grate interposes on register_handler (1001), exec (59), fork (57),
//! and exit (60). When clamped grates register handlers, tee captures both the
//! primary and secondary registrations, allocates alt syscall numbers, and
//! installs its own dispatch handler that calls both at runtime.

mod tee;

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;
use std::ptr;

use grate_rs::constants::*;
use grate_rs::{SyscallHandler, copy_data_between_cages, getcageid, register_handler};

use tee::*;

// =====================================================================
//  POSIX FFI — use grate-rs public ffi module
// =====================================================================

use grate_rs::ffi::{fork, execv, waitpid, mmap, munmap, sem_t, sem_init, sem_destroy, sem_post, sem_wait};
use grate_rs::constants::mman::*;

// =====================================================================
//  CLI parsing
// =====================================================================

struct TeeConfig {
    /// The full exec chain passed to the first child.
    exec_chain: Vec<String>,
    /// Path to log file for secondary errors (optional).
    log_path: Option<String>,
    /// Maximum bytes for secondary buffer.
    buffer_limit: usize,
}

fn parse_argv(args: Vec<String>) -> Result<TeeConfig, String> {
    let mut primary: Option<String> = None;
    let mut secondary: Option<String> = None;
    let mut log_path: Option<String> = None;
    let mut buffer_limit = DEFAULT_SECONDARY_BUFFER_LIMIT;
    let mut app_args: Vec<String> = Vec::new();
    let mut i = 0;

    // Check for %{ %} inline style first.
    if args.iter().any(|a| a == "%{") {
        // Inline style: tee-grate %{ secondary-grate %} app args...
        // Everything inside %{ %} is the secondary exec chain.
        // Everything after %} is the app.
        // Primary is whatever is stacked below tee in the normal grate chain.
        let exec_chain: Vec<String> = args.to_vec();
        if !exec_chain.iter().any(|a| a == "%}") {
            return Err("missing %} in inline tee syntax".into());
        }
        return Ok(TeeConfig {
            exec_chain,
            log_path: None,
            buffer_limit,
        });
    }

    // --primary/--secondary style.
    while i < args.len() {
        match args[i].as_str() {
            "--primary" => {
                i += 1;
                if i >= args.len() { return Err("--primary requires an argument".into()); }
                primary = Some(args[i].clone());
            }
            "--secondary" => {
                i += 1;
                if i >= args.len() { return Err("--secondary requires an argument".into()); }
                secondary = Some(args[i].clone());
            }
            "--log" => {
                i += 1;
                if i >= args.len() { return Err("--log requires an argument".into()); }
                log_path = Some(args[i].clone());
            }
            "--buffer-limit" => {
                i += 1;
                if i >= args.len() { return Err("--buffer-limit requires an argument".into()); }
                buffer_limit = args[i].parse().map_err(|_| "--buffer-limit must be a number")?;
            }
            "--" => {
                // Everything after -- is the app command line.
                app_args = args[i + 1..].to_vec();
                break;
            }
            other => {
                return Err(format!("unexpected argument: {}", other));
            }
        }
        i += 1;
    }

    let primary = primary.ok_or("--primary is required")?;
    let secondary = secondary.ok_or("--secondary is required")?;
    if app_args.is_empty() {
        return Err("missing -- <program> [args...]".into());
    }

    // Build exec chain: primary secondary app args...
    // The primary grate forks and execs the secondary, which forks and execs the app.
    let mut exec_chain = vec![primary, secondary];
    exec_chain.extend(app_args);

    Ok(TeeConfig {
        exec_chain,
        log_path,
        buffer_limit,
    })
}

// =====================================================================
//  Lifecycle handlers
// =====================================================================

/// Handler for syscall 1001 (register_handler).
///
/// When a clamped grate calls register_handler(cage, syscall, grate_id, handler_ptr),
/// tee intercepts it to:
///   1. Determine if the registering grate is primary or secondary (by grate_id)
///   2. Allocate an alt syscall number for the handler
///   3. Register the handler at the alt number on the tee grate's cage
///   4. Store the route: (cage, syscall) → primary_alt / secondary_alt
///   5. Register the tee dispatch handler on the target cage (if not already)
///
/// Register handler args as received by the 3i dispatch:
///   arg1 = target_cage, arg1cage = syscall_nr
///   arg2 (unused),      arg2cage = grate_id
///   arg3 = handler_fn_ptr
pub extern "C" fn register_handler_handler(
    _cageid: u64,
    target_cage: u64,
    syscall_nr: u64,
    _arg2: u64,
    grate_id: u64,
    handler_fn_ptr: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let tee_cage = with_tee(|s| s.tee_cage_id);

    // After interception phase ends, pass through registrations unchanged.
    if !with_tee(|s| s.intercepting) {
        return do_syscall(
            grate_id, SYS_REGISTER_HANDLER,
            &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
            &[syscall_nr, grate_id, 0, 0, 0, 0],
        );
    }

    println!(
        "[tee-grate] intercept register_handler: cage={}, syscall={}, grate={}",
        target_cage, syscall_nr, grate_id
    );

    // Step 1: Allocate alt and record which stack (primary/secondary) this belongs to.
    let alt_nr = with_tee(|s| s.record_registration(target_cage, syscall_nr, grate_id));

    // Step 2: Register the clamped handler at the alt number on tee's cage.
    let ret = do_syscall(
        grate_id, SYS_REGISTER_HANDLER,
        &[tee_cage, 0, handler_fn_ptr, 0, 0, 0],
        &[alt_nr, grate_id, 0, 0, 0, 0],
    );
    if ret != 0 {
        eprintln!("[tee-grate] failed to register alt handler: ret={}", ret);
        return ret;
    }

    // Step 3: If we haven't yet registered the tee dispatch handler on the target
    // cage for this syscall, do so now.
    let already = with_tee(|s| s.is_handler_registered(target_cage, syscall_nr));
    if !already {
        if let Some(tee_handler) = get_tee_handler(syscall_nr) {
            match register_handler(target_cage, syscall_nr, tee_cage, tee_handler) {
                Ok(_) => {
                    with_tee(|s| s.mark_handler_registered(target_cage, syscall_nr));
                }
                Err(e) => {
                    eprintln!("[tee-grate] failed to register tee handler: {:?}", e);
                    return -1;
                }
            }
        } else {
            // No tee handler for this syscall — pass through the registration directly.
            eprintln!(
                "[tee-grate] no tee handler for syscall {} — passing through",
                syscall_nr
            );
            return do_syscall(
                grate_id, SYS_REGISTER_HANDLER,
                &[target_cage, 0, handler_fn_ptr, 0, 0, 0],
                &[syscall_nr, grate_id, 0, 0, 0, 0],
            );
        }
    }

    0
}

/// Handler for syscall 59 (exec).
///
/// Detects %} boundary and stops register_handler interception.
pub extern "C" fn exec_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let tee_cage = with_tee(|s| s.tee_cage_id);

    // Read the exec path from cage memory to check for %}.
    let mut buf = vec![0u8; 256];
    if copy_data_between_cages(
        tee_cage, arg1cage,
        arg1, arg1cage,
        buf.as_mut_ptr() as u64, tee_cage,
        256, 0,
    ).is_err() {
        panic!("[tee-grate] Unable to read the execve path");
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(256);
    let path = String::from_utf8_lossy(&buf[..len]);

    if path == "%}" {
        println!("[tee-grate] detected %}} boundary — stopping register_handler interception");
        with_tee(|s| s.intercepting = false);

        // argv[] pointers are 8-byte wide in the Lind runtime.
        const PTR_SIZE: usize = 8;
        let argv1_addr = arg2 + PTR_SIZE as u64;

        let mut real_ptr = [0u8; PTR_SIZE];
        match copy_data_between_cages(
            tee_cage, arg2cage,
            argv1_addr, arg2cage,
            real_ptr.as_mut_ptr() as u64, tee_cage,
            8, 0,
        ) {
            Ok(_) => {}
            Err(_) => {
                println!("Invalid command line arguments detected.");
                return -2;
            }
        }
        let real_path = u64::from_le_bytes(real_ptr);

        return do_syscall(
            arg2cage, SYS_EXEC,
            &[real_path, argv1_addr, arg3, arg4, arg5, arg6],
            &[arg2cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
    } else {
        return do_syscall(
            arg1cage, SYS_EXEC,
            &[arg1, arg2, arg3, arg4, arg5, arg6],
            &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
        );
    }
}

/// Handler for syscall 57 (fork).
///
/// Forwards fork, clones tee state to child, registers lifecycle handlers.
pub extern "C" fn fork_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let child_cage_id = do_syscall(
        arg1cage, SYS_CLONE,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    ) as u64;

    // Clone tee route state and fd table from parent to child.
    with_tee(|s| {
        if s.is_managed(arg1cage) {
            s.clone_cage_state(arg1cage, child_cage_id);
        }
    });
    let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);

    // Register lifecycle handlers on the child.
    register_lifecycle_handlers(child_cage_id);

    child_cage_id as i32
}

/// Handler for syscall 60 (exit).
///
/// Cleans up tee state for the exiting cage, then forwards.
pub extern "C" fn exit_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    with_tee(|s| { s.remove_cage_state(arg1cage); });
    fdtables::remove_cage_from_fdtable(arg1cage);

    do_syscall(
        arg1cage, SYS_EXIT,
        &[arg1, arg2, arg3, arg4, arg5, arg6],
        &[arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

/// Register the four lifecycle handlers on a cage.
fn register_lifecycle_handlers(cage_id: u64) {
    let tee_cage = with_tee(|s| s.tee_cage_id);

    let handlers: &[(u64, SyscallHandler)] = &[
        (SYS_REGISTER_HANDLER, register_handler_handler),
        (SYS_EXEC, exec_handler),
        (SYS_CLONE, fork_handler),
        (SYS_EXIT, exit_handler),
    ];

    for &(syscall_nr, handler) in handlers {
        if let Err(e) = register_handler(cage_id, syscall_nr, tee_cage, handler) {
            eprintln!(
                "[tee-grate] failed to register lifecycle handler {} on cage {}: {:?}",
                syscall_nr, cage_id, e
            );
        }
    }
}

// =====================================================================
//  Tee dispatch handlers
//
//  Each handler calls tee_dispatch() which forwards to both primary and
//  secondary, returning the primary's result.
// =====================================================================

/// Generate a tee dispatch handler for a given syscall number.
/// The handler extracts args into arrays and calls tee_dispatch().
macro_rules! tee_handler {
    ($name:ident, $nr:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            tee_dispatch(
                $nr, arg1cage,
                [arg1, arg2, arg3, arg4, arg5, arg6],
                [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
            )
        }
    };
}

// Path-based syscalls — pure tee dispatch, no fd tracking needed.
tee_handler!(tee_stat, SYS_XSTAT);
tee_handler!(tee_access, SYS_ACCESS);
tee_handler!(tee_unlink, SYS_UNLINK);
tee_handler!(tee_mkdir, SYS_MKDIR);
tee_handler!(tee_rmdir, SYS_RMDIR);
tee_handler!(tee_rename, SYS_RENAME);
tee_handler!(tee_truncate, SYS_TRUNCATE);
tee_handler!(tee_chmod, SYS_CHMOD);
tee_handler!(tee_chdir, SYS_CHDIR);
tee_handler!(tee_readlink, SYS_READLINK);
tee_handler!(tee_unlinkat, SYS_UNLINKAT);
tee_handler!(tee_readlinkat, SYS_READLINKAT);

// FD-based syscalls — pure tee dispatch, no fd tracking side effects.
tee_handler!(tee_read, SYS_READ);
tee_handler!(tee_write, SYS_WRITE);
tee_handler!(tee_pread, SYS_PREAD);
tee_handler!(tee_pwrite, SYS_PWRITE);
tee_handler!(tee_lseek, SYS_LSEEK);
tee_handler!(tee_fstat, SYS_FXSTAT);
tee_handler!(tee_fcntl, SYS_FCNTL);
tee_handler!(tee_ftruncate, SYS_FTRUNCATE);
tee_handler!(tee_fchmod, SYS_FCHMOD);
tee_handler!(tee_readv, SYS_READV);
tee_handler!(tee_writev, SYS_WRITEV);

// ── FD-tracking handlers ─────────────────────────────────────────────
//
// open, close, dup, dup2, dup3 need to update fdtables after dispatch
// so that fork/exec/exit can propagate fd state correctly.

/// open: tee dispatch, then record the returned fd in fdtables.
pub extern "C" fn tee_open(
    _cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let ret = tee_dispatch(
        SYS_OPEN, arg1cage,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, 0,
        );
    }

    ret
}

/// close: tee dispatch, then remove the fd from fdtables.
pub extern "C" fn tee_close(
    _cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let ret = tee_dispatch(
        SYS_CLOSE, arg1cage,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    let _ = fdtables::close_virtualfd(arg1cage, arg1);

    ret
}

/// dup: tee dispatch, then copy the fd entry in fdtables.
pub extern "C" fn tee_dup(
    _cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let ret = tee_dispatch(
        SYS_DUP, arg1cage,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, 0,
        );
    }

    ret
}

/// dup2: tee dispatch, then record the target fd in fdtables.
pub extern "C" fn tee_dup2(
    _cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let ret = tee_dispatch(
        SYS_DUP2, arg1cage,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, arg2, 0, arg2, false, 0,
        );
    }

    ret
}

/// dup3: tee dispatch, then record the target fd in fdtables.
pub extern "C" fn tee_dup3(
    _cageid: u64, arg1: u64, arg1cage: u64, arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64, arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64, arg6: u64, arg6cage: u64,
) -> i32 {
    let ret = tee_dispatch(
        SYS_DUP3, arg1cage,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, arg2, 0, arg2, false, 0,
        );
    }

    ret
}

/// Map syscall number → tee dispatch handler function pointer.
fn get_tee_handler(syscall_nr: u64) -> Option<SyscallHandler> {
    match syscall_nr {
        SYS_OPEN      => Some(tee_open),
        SYS_XSTAT     => Some(tee_stat),
        SYS_ACCESS    => Some(tee_access),
        SYS_UNLINK    => Some(tee_unlink),
        SYS_MKDIR     => Some(tee_mkdir),
        SYS_RMDIR     => Some(tee_rmdir),
        SYS_RENAME    => Some(tee_rename),
        SYS_TRUNCATE  => Some(tee_truncate),
        SYS_CHMOD     => Some(tee_chmod),
        SYS_CHDIR     => Some(tee_chdir),
        SYS_READLINK  => Some(tee_readlink),
        SYS_UNLINKAT  => Some(tee_unlinkat),
        SYS_READLINKAT => Some(tee_readlinkat),
        SYS_READ      => Some(tee_read),
        SYS_WRITE     => Some(tee_write),
        SYS_CLOSE     => Some(tee_close),
        SYS_PREAD     => Some(tee_pread),
        SYS_PWRITE    => Some(tee_pwrite),
        SYS_LSEEK     => Some(tee_lseek),
        SYS_FXSTAT    => Some(tee_fstat),
        SYS_FCNTL     => Some(tee_fcntl),
        SYS_FTRUNCATE => Some(tee_ftruncate),
        SYS_FCHMOD    => Some(tee_fchmod),
        SYS_READV     => Some(tee_readv),
        SYS_WRITEV    => Some(tee_writev),
        SYS_DUP       => Some(tee_dup),
        SYS_DUP2      => Some(tee_dup2),
        SYS_DUP3      => Some(tee_dup3),
        _ => None,
    }
}

// =====================================================================
//  Main
// =====================================================================

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("Usage: tee-grate --primary <grate> --secondary <grate> [--log <file>] -- <program> [args...]");
        eprintln!("   or: tee-grate %{{ <secondary-grate> %}} <program> [args...]");
        std::process::exit(1);
    }

    let config = match parse_argv(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[tee-grate] argument error: {}", e);
            std::process::exit(1);
        }
    };

    println!(
        "[tee-grate] exec_chain={:?}, buffer_limit={}",
        config.exec_chain, config.buffer_limit
    );

    // Initialize global tee state.
    let tee_cage_id = getcageid();
    *TEE_STATE.lock().unwrap() = Some(TeeState::new(tee_cage_id, config.buffer_limit));

    // Prepare exec chain as C strings.
    let cstrings: Vec<CString> = config.exec_chain
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut c_argv: Vec<*const c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    c_argv.push(ptr::null());
    let path = c_argv[0];

    // Allocate shared semaphore.
    let sem: *mut sem_t = unsafe {
        let ptr = mmap(
            ptr::null_mut(),
            std::mem::size_of::<sem_t>(),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1, 0,
        );
        if ptr == MAP_FAILED {
            eprintln!("[tee-grate] mmap failed");
            std::process::exit(-1);
        }
        ptr as *mut sem_t
    };

    if unsafe { sem_init(sem, 1, 0) } < 0 {
        eprintln!("[tee-grate] sem_init failed");
        std::process::exit(-1);
    }

    // Fork the child cage.
    let child_pid = unsafe { fork() };
    if child_pid < 0 {
        eprintln!("[tee-grate] fork failed");
        std::process::exit(-1);
    }

    if child_pid == 0 {
        // ── Child: wait for parent to register lifecycle handlers, then exec.
        unsafe { sem_wait(sem) };
        let ret = unsafe { execv(path, c_argv.as_ptr()) };
        if ret < 0 {
            eprintln!("[tee-grate] execv failed");
        }
        std::process::exit(-1);
    }

    // ── Parent: tee grate process.
    let child_cage_id = child_pid as u64;

    println!(
        "[tee-grate] forked child cage {} (tee_cage={})",
        child_cage_id, tee_cage_id
    );

    // Mark child as managed and init its fdtables entry.
    with_tee(|s| { s.managed_cages.insert(child_cage_id, ()); });
    if !fdtables::check_cage_exists(child_cage_id) {
        fdtables::init_empty_cage(child_cage_id);
    }

    // Register lifecycle handlers on the child.
    register_lifecycle_handlers(child_cage_id);

    // Signal child to proceed.
    unsafe { sem_post(sem) };

    // Wait for all children.
    loop {
        let mut status: i32 = 0;
        let ret = unsafe { waitpid(-1, &mut status as *mut i32 as *mut c_int, 0) };
        if ret <= 0 { break; }
        println!("[tee-grate] child {} exited with status {}", ret, status);
    }

    // Cleanup.
    unsafe {
        sem_destroy(sem);
        munmap(sem as *mut c_void, std::mem::size_of::<sem_t>());
    }

    println!("[tee-grate] exiting");
    std::process::exit(0);
}
