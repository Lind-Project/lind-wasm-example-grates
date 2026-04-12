//! `chroot-grate-rs`

use grate_rs::constants::fs::S_IFDIR;
use grate_rs::constants::{
    SYS_ACCEPT, SYS_ACCESS, SYS_BIND, SYS_CHDIR, SYS_CHMOD, SYS_CHROOT, SYS_CLONE, SYS_CONNECT,
    SYS_EXECVE, SYS_FCHDIR, SYS_GETCWD, SYS_GETPEERNAME, SYS_GETSOCKNAME, SYS_LINK, SYS_MKDIR,
    SYS_OPEN, SYS_READLINK, SYS_READLINKAT, SYS_RECVFROM, SYS_RENAME, SYS_RMDIR, SYS_SENDTO,
    SYS_STATFS, SYS_TRUNCATE, SYS_UNLINK, SYS_UNLINKAT, SYS_XSTAT,
};
use grate_rs::ffi::stat;
use grate_rs::{GrateBuilder, copy_data_between_cages, getcageid, make_threei_call};
use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::c_char;
use std::sync::Mutex;

mod paths;
mod sockets;

use crate::paths::{
    chroot_path, get_cage_cwd, init_cwd, normalize_path, read_path_from_cage, register_cage,
    set_cage_cwd,
};

use crate::sockets::{translate_sockaddr, untranslate_sockaddr_in_cage};

/// Host-side absolute directory used as the cage's chroot prefix.
pub static CHROOT_DIR: Mutex<String> = Mutex::new(String::new());

/// Per-cage virtual current working directory (cwd) tracking.
pub static CAGE_CWDS: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);

/// Check if a directory exists.
fn check_dir(dir: String) -> bool {
    let cwd_cstring = match CString::new(dir.as_str()) {
        Ok(cstr) => cstr,
        Err(_) => return false,
    };
    let mut st: stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { stat(cwd_cstring.as_ptr() as *const c_char, &mut st) };
    if ret < 0 {
        return false;
    }

    return !(st.st_mode & S_IFDIR == 00);
}

/// Initialize chroot state for this grate process.
pub fn init_state(chroot_dir: String) {
    match check_dir(chroot_dir.clone()) {
        false => panic!("Invalid path for --chroot-dir"),
        true => {
            *CHROOT_DIR.lock().unwrap() = chroot_dir;
            *CAGE_CWDS.lock().unwrap() = Some(HashMap::new());
        }
    };
}

/// Dispatch a syscall via ThreeI, optionally rewriting some argument pointers.
///
/// `rewrites` is a list of `(arg_index, ptr)` pairs, where `ptr` points to a
/// NULL-terminated buffer owned by this grate (in `thiscage` memory).
fn call_with_rewrites(
    syscall_no: u32,
    thiscage: u64,
    calling_cageid: u64,
    mut args: [u64; 6],
    mut arg_cages: [u64; 6],
    rewrites: &[(usize, u64)],
) -> i32 {
    for (idx, cstr) in rewrites {
        if *idx >= 6 {
            return -(libc::EINVAL as i32);
        }
        args[*idx] = *cstr;
        arg_cages[*idx] = thiscage | (1u64 << 63);
    }

    match make_threei_call(
        syscall_no,
        0,
        thiscage,       // self cage (grate)
        calling_cageid, // execute as-if from cageid
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

fn strip_chroot_prefix(path: &str) -> String {
    let chroot_dir = CHROOT_DIR.lock().unwrap().clone();
    if path.starts_with(&chroot_dir) {
        let stripped = &path[chroot_dir.len()..];
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    } else {
        path.to_string()
    }
}

fn write_bytes_to_cage(
    thiscage: u64,
    buf_ptr: u64,
    buf_cage: u64,
    bufsiz: u64,
    bytes: &[u8],
) -> i32 {
    let write_len = std::cmp::min(bytes.len(), bufsiz as usize);
    match copy_data_between_cages(
        thiscage,
        buf_cage,
        bytes.as_ptr() as u64,
        thiscage,
        buf_ptr,
        buf_cage,
        write_len as u64,
        0,
    ) {
        Ok(_) => write_len as i32,
        Err(_) => -(libc::EFAULT as i32),
    }
}

// -----------------------------------------------------------------------------
// Macro-generated handler declarations
// -----------------------------------------------------------------------------

// "Path input" syscalls: read the path argument(s), chroot them, and dispatch
// the real syscall with rewritten pointers.
input_path_handler!(open_handler, SYS_OPEN, 0);
// input_path_handler!(execve_handler, SYS_EXECVE, 0);
input_path_handler!(stat_handler, SYS_XSTAT, 0);
input_path_handler!(access_handler, SYS_ACCESS, 0);
input_path_handler!(statfs_handler, SYS_STATFS, 0);
input_path_handler!(mkdir_handler, SYS_MKDIR, 0);
input_path_handler!(rmdir_handler, SYS_RMDIR, 0);
input_path_handler!(unlink_handler, SYS_UNLINK, 0);
input_path_handler!(unlinkat_handler, SYS_UNLINKAT, 1);
input_path_handler!(chmod_handler, SYS_CHMOD, 0);
input_path_handler!(truncate_handler, SYS_TRUNCATE, 0);

// Two-path syscalls: chroot both path arguments.
input_path_handler!(rename_handler, SYS_RENAME, 0, 1);
input_path_handler!(link_handler, SYS_LINK, 0, 1);

// Socket syscalls that take an AF_UNIX sockaddr: chroot `sun_path` before
// dispatch.
socket_translate_handler!(bind_handler, SYS_BIND, 1, 2);
socket_translate_handler!(connect_handler, SYS_CONNECT, 1, 2);
socket_translate_handler!(sendto_handler, SYS_SENDTO, 4, 5);

// Socket syscalls that return an AF_UNIX sockaddr: strip chroot prefix from
// returned `sun_path` after dispatch.
socket_untranslate_handler!(accept_handler, SYS_ACCEPT, 1, 2);
socket_untranslate_handler!(getsockname_handler, SYS_GETSOCKNAME, 1, 2);
socket_untranslate_handler!(getpeername_handler, SYS_GETPEERNAME, 1, 2);
socket_untranslate_handler!(recvfrom_handler, SYS_RECVFROM, 4, 5);

// -----------------------------------------------------------------------------
// Path-output handlers
// -----------------------------------------------------------------------------

/// `readlink(2)` handler.
///
/// - Rewrites the *input* path through the configured chroot.
/// - Calls the real syscall.
/// - Strips the chroot prefix from the returned target so the cage sees a
///   virtual path.
extern "C" fn readlink_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    buf: u64,
    buf_cage: u64,
    bufsiz: u64,
    _bufsiz_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Read and chroot the input path (symlink location).
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };
    let chrooted_path = chroot_path(&path, cageid);
    let c_path = match CString::new(chrooted_path) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // Call real readlink into a buffer owned by this grate.
    let mut result_buf = vec![0u8; bufsiz as usize];
    let ret = match make_threei_call(
        SYS_READLINK as u32,
        0,
        cageid,
        path_cage,
        c_path.as_ptr() as u64,
        thiscage | (1u64 << 63),
        result_buf.as_mut_ptr() as u64,
        thiscage | (1u64 << 63),
        bufsiz,
        thiscage,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    if ret < 0 {
        return ret;
    }

    let result_len = ret as usize;
    let result = String::from_utf8_lossy(&result_buf[..result_len]).to_string();
    let final_result = strip_chroot_prefix(&result);
    write_bytes_to_cage(thiscage, buf, buf_cage, bufsiz, final_result.as_bytes())
}

/// `readlinkat(2)` handler.
///
/// This mirrors `readlink_handler`, but handles `dirfd`:
/// - If `path` is absolute or `dirfd == AT_FDCWD`, the input path is chrooted.
/// - Otherwise, the relative path is passed through (it is interpreted relative
///   to `dirfd`, which is expected to already refer to a chrooted directory).
///
/// The returned symlink target is always un-chrooted (prefix stripped) so the
/// cage sees a virtual path.
extern "C" fn readlinkat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    buf: u64,
    buf_cage: u64,
    bufsiz: u64,
    _bufsiz_cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    const AT_FDCWD: i64 = -100;

    // Read the input path.
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    // If path is absolute or `dirfd` is AT_FDCWD, we can chroot it; otherwise
    // pass through (relative to `dirfd`).
    let (c_path, use_chrooted) = if path.starts_with('/') || dirfd as i64 == AT_FDCWD {
        let chrooted = chroot_path(&path, cageid);
        (CString::new(chrooted).ok(), true)
    } else {
        (CString::new(path).ok(), false)
    };

    let c_path = match c_path {
        Some(p) => p,
        None => return -1,
    };

    // Call real readlinkat into a buffer owned by this grate.
    let mut result_buf = vec![0u8; bufsiz as usize];
    let ret = match make_threei_call(
        SYS_READLINKAT as u32,
        0,
        cageid,
        path_cage,
        if use_chrooted { AT_FDCWD as u64 } else { dirfd },
        dirfd_cage,
        c_path.as_ptr() as u64,
        thiscage | (1u64 << 63),
        result_buf.as_mut_ptr() as u64,
        thiscage,
        bufsiz,
        thiscage,
        0,
        0,
        0,
        0,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    if ret < 0 {
        return ret;
    }

    let result_len = ret as usize;
    let result = String::from_utf8_lossy(&result_buf[..result_len]).to_string();
    let final_result = strip_chroot_prefix(&result);
    write_bytes_to_cage(thiscage, buf, buf_cage, bufsiz, final_result.as_bytes())
}

// -----------------------------------------------------------------------------
// Process/cwd state tracking handlers
// -----------------------------------------------------------------------------

/// `fork(2)` handler.
///
/// Delegates to the real `fork` and, on success in the parent, registers the
/// child cage in the cwd table with a copy of the parent's virtual cwd.
extern "C" fn fork_handler(
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
) -> i32 {
    // Call the real fork syscall.
    let ret = match make_threei_call(
        SYS_CLONE as u32,
        0,
        cageid,
        arg1cage,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    register_cage(cageid, ret as u64);

    ret
}

/// execve handler.
extern "C" fn execve_handler(
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
) -> i32 {
    // Call the real fork syscall.
    let thiscage = getcageid();

    let path = match read_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -(libc::EFAULT as i32),
    };

    let transformed = chroot_path(&path, cageid);
    let c_path = match CString::new(transformed) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    let rewritten_ptr = c_path.as_ptr() as u64;

    match make_threei_call(
        SYS_EXECVE as u32,
        0,
        thiscage,
        arg1cage,
        rewritten_ptr,
        thiscage | (1u64 << 63),
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) => return r,
        Err(_) => return -1,
    }
}

/// `chdir(2)` handler.
///
/// This does **not** call the host `chdir`. Instead it updates the per-cage
/// virtual cwd table, which is used to resolve relative paths in other handlers.
extern "C" fn chdir_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
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
    // Read the requested path from cage memory.
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    // Normalize relative to the current virtual cwd.
    let cwd = get_cage_cwd(cageid);
    let new_cwd = normalize_path(&path, &cwd);

    match check_dir(new_cwd.clone()) {
        false => return -20, // ENOTDIR
        true => {
            // Update the cwd of cage in our hashmap.
            set_cage_cwd(cageid, new_cwd);
            return 0;
        }
    }
}

/// `fchdir(2)` handler.
///
/// Currently unimplemented: implementing it portably requires fd->path tracking.
extern "C" fn fchdir_handler(
    _cageid: u64,
    _fd: u64,
    _fd_cage: u64,
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
    -38 // ENOSYS
}

/// `getcwd(2)` handler returning the cage's virtual cwd.
///
/// The returned path comes from `CAGE_CWDS` (not the host process cwd).
extern "C" fn getcwd_handler(
    cageid: u64,
    buf_ptr: u64,
    buf_cage: u64,
    size: u64,
    _size_cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Get the cage's virtual cwd from our table.
    let cwd = get_cage_cwd(cageid);
    let cwd_bytes = cwd.as_bytes();

    // Check if buffer is large enough (need space for NUL terminator).
    if cwd_bytes.len() + 1 > size as usize {
        return -34; // ERANGE
    }

    // Create a NUL-terminated buffer.
    let mut buf = cwd_bytes.to_vec();
    buf.push(0);

    // Write to cage's buffer.
    match copy_data_between_cages(
        thiscage,
        buf_cage,
        buf.as_ptr() as u64,
        thiscage,
        buf_ptr,
        buf_cage,
        buf.len() as u64,
        0,
    ) {
        Ok(_) => buf_ptr as i32,
        Err(_) => -14, // EFAULT
    }
}

/// `chroot(2)` handler.
///
/// This grate enforces a fixed jail; nested chroot attempts from inside the cage
/// are denied.
extern "C" fn chroot_handler(
    _cageid: u64,
    _path_ptr: u64,
    _path_cage: u64,
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
    -1 // EPERM - operation not permitted
}

fn parse_args() -> (String, Vec<String>) {
    let args: Vec<String> = std::env::args().collect();

    let mut chroot_dir = String::new();
    let mut remaining_args = Vec::new();
    let mut i = 1;

    while i < args.len() {
        if args[i] == "--chroot-dir" && i + 1 < args.len() {
            chroot_dir = args[i + 1].clone();
            i += 2;
        } else {
            remaining_args.push(args[i].clone());
            i += 1;
        }
    }

    (chroot_dir, remaining_args)
}

fn main() {
    let (chroot_dir, remaining_args) = parse_args();

    if chroot_dir.is_empty() {
        eprintln!("Usage: chroot-grate --chroot-dir <path> <program> [args...]");
        std::process::exit(1);
    }

    println!(
        "[chroot-grate] Initializing with chroot dir: {}",
        chroot_dir
    );

    init_state(chroot_dir);

    // Get initial cwd via syscall and add to table
    let cageid = getcageid();
    let initial_cwd = init_cwd(cageid);

    println!("[chroot-grate] Initial cwd: {}", initial_cwd);

    let builder = GrateBuilder::new()
        // Process management
        .register(SYS_CLONE, fork_handler)
        // Filesystem syscalls
        .register(SYS_OPEN, open_handler)
        .register(SYS_EXECVE, execve_handler)
        .register(SYS_XSTAT, stat_handler)
        .register(SYS_ACCESS, access_handler)
        .register(SYS_STATFS, statfs_handler)
        .register(SYS_MKDIR, mkdir_handler)
        .register(SYS_RMDIR, rmdir_handler)
        .register(SYS_UNLINK, unlink_handler)
        .register(SYS_UNLINKAT, unlinkat_handler)
        .register(SYS_RENAME, rename_handler)
        .register(SYS_LINK, link_handler)
        .register(SYS_CHMOD, chmod_handler)
        .register(SYS_TRUNCATE, truncate_handler)
        .register(SYS_CHDIR, chdir_handler)
        .register(SYS_FCHDIR, fchdir_handler)
        .register(SYS_GETCWD, getcwd_handler)
        .register(SYS_READLINK, readlink_handler)
        .register(SYS_READLINKAT, readlinkat_handler)
        .register(SYS_CHROOT, chroot_handler)
        // Socket syscalls (for AF_UNIX path handling)
        .register(SYS_BIND, bind_handler)
        .register(SYS_CONNECT, connect_handler)
        .register(SYS_SENDTO, sendto_handler)
        .register(SYS_ACCEPT, accept_handler)
        .register(SYS_GETSOCKNAME, getsockname_handler)
        .register(SYS_GETPEERNAME, getpeername_handler)
        .register(SYS_RECVFROM, recvfrom_handler)
        .teardown(|result| {
            println!("[chroot-grate] Result: {:#?}", result);
        });

    builder.run(remaining_args);
}
