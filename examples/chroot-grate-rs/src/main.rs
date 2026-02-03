use grate_rs::{copy_data_between_cages, getcageid, make_threei_call, GrateBuilder};
use std::ffi::CString;
use std::collections::HashMap;
use std::sync::Mutex;

// x86_64 syscall numbers
const SYS_OPEN: u64 = 2;
const SYS_STAT: u64 = 4;
const SYS_ACCESS: u64 = 21;
const SYS_CONNECT: u64 = 42;
const SYS_ACCEPT: u64 = 43;
const SYS_SENDTO: u64 = 44;
const SYS_RECVFROM: u64 = 45;
const SYS_BIND: u64 = 49;
const SYS_GETSOCKNAME: u64 = 51;
const SYS_GETPEERNAME: u64 = 52;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_TRUNCATE: u64 = 76;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_FCHDIR: u64 = 81;
const SYS_RENAME: u64 = 82;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_READLINK: u64 = 89;
const SYS_CHMOD: u64 = 90;
const SYS_STATFS: u64 = 137;
const SYS_CHROOT: u64 = 161;
const SYS_UNLINKAT: u64 = 263;
const SYS_READLINKAT: u64 = 267;

// Global state
static CHROOT_DIR: Mutex<String> = Mutex::new(String::new());
static CAGE_CWDS: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);

/// Initialize global state
fn init_state(chroot_dir: String) {
    *CHROOT_DIR.lock().unwrap() = chroot_dir;
    *CAGE_CWDS.lock().unwrap() = Some(HashMap::new());
}

/// Get the cwd for a cage, defaulting to "/" if not found
fn get_cage_cwd(cageid: u64) -> String {
    CAGE_CWDS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&cageid).cloned())
        .unwrap_or_else(|| "/".to_string())
}

/// Set the cwd for a cage
fn set_cage_cwd(cageid: u64, cwd: String) {
    if let Some(ref mut map) = *CAGE_CWDS.lock().unwrap() {
        map.insert(cageid, cwd);
    }
}

/// Register a new cage (copy parent's cwd)
fn register_cage(parent_cageid: u64, child_cageid: u64) {
    let parent_cwd = get_cage_cwd(parent_cageid);
    set_cage_cwd(child_cageid, parent_cwd);
}

/// Normalize a path: resolve "..", ".", and make absolute
fn normalize_path(path: &str, cwd: &str) -> String {
    let abs_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), path)
    };

    let mut components: Vec<&str> = Vec::new();
    for component in abs_path.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }

    format!("/{}", components.join("/"))
}

/// Apply chroot: prepend chroot_dir and ensure path stays within chroot
fn chroot_path(path: &str, cageid: u64) -> String {
    let chroot_dir = CHROOT_DIR.lock().unwrap().clone();
    let cwd = get_cage_cwd(cageid);

    // Normalize the path relative to cage's cwd
    let normalized = normalize_path(path, &cwd);

    // Prepend chroot directory
    format!("{}{}", chroot_dir.trim_end_matches('/'), normalized)
}

/// Read a null-terminated path from a cage's memory
fn read_path_from_cage(ptr: u64, src_cage: u64) -> Option<String> {
    let thiscage = getcageid();
    let mut buf = vec![0u8; 4096];

    match copy_data_between_cages(
        thiscage,
        src_cage,
        ptr,
        src_cage,
        buf.as_mut_ptr() as u64,
        thiscage,
        buf.len() as u64,
        0,
    ) {
        Ok(_) => {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..len]).to_string())
        }
        Err(_) => None,
    }
}

/// Get the current working directory via syscall and add to cage cwd table
fn init_cwd(cageid: u64) -> String {
    let mut buf = vec![0u8; 4096];
    let buf_ptr = buf.as_mut_ptr() as u64;

    let cwd = match make_threei_call(
        SYS_GETCWD as u32,
        0,
        cageid,
        cageid,
        buf_ptr, cageid,
        buf.len() as u64, cageid,
        0, 0,
        0, 0,
        0, 0,
        0, 0,
        0,
    ) {
        Ok(_) => {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).to_string()
        }
        Err(_) => "/".to_string(),
    };

    set_cage_cwd(cageid, cwd.clone());
    cwd
}


// =============================================================================
// Syscall Handlers
// =============================================================================
//
// Each handler follows a pattern based on what kind of path manipulation is needed:
//
// 1. Path input handlers (open, stat, mkdir, etc.):
//    - Step 1: Read the path string from the cage's memory
//    - Step 2: Apply chroot transformation (normalize + prepend chroot dir)
//    - Step 3: Call the real syscall with the transformed path
//
// 2. Path output handlers (getcwd, readlink):
//    - Step 1: Call the real syscall to get the host path
//    - Step 2: Strip the chroot prefix to get the virtual path
//    - Step 3: Write the virtual path back to the cage's buffer
//
// 3. State-tracking handlers (fork, chdir):
//    - Maintain the per-cage cwd table for proper path resolution

/// fork: Create a new process and register it in our cwd tracking table
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
    // Step 1: Call the real fork syscall
    let ret = match make_threei_call(
        SYS_FORK as u32,
        0,
        cageid,
        arg1cage,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Step 2: On success (ret > 0 means we're parent, ret is child's cageid),
    // register the child cage with a copy of the parent's cwd
    if ret > 0 {
        register_cage(cageid, ret as u64);
    }

    ret
}

/// open: Open a file, translating the path through chroot
extern "C" fn open_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    flags: u64,
    flags_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Step 1: Read the path string from the cage's memory
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    // Step 2: Apply chroot transformation (normalize relative to cwd, prepend chroot dir)
    let transformed = chroot_path(&path, cageid);
    let c_path = match CString::new(transformed) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // Step 3: Call real open with the transformed path (in grate's memory space)
    match make_threei_call(
        SYS_OPEN as u32,
        0,
        cageid,
        path_cage,
        c_path.as_ptr() as u64, thiscage,
        flags, flags_cage,
        mode, mode_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

// -----------------------------------------------------------------------------
// Simple path translation handlers
// These all follow the same pattern: read path, chroot it, call real syscall
// -----------------------------------------------------------------------------

/// execve: Execute a program, translating the executable path through chroot
extern "C" fn execve_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    argv: u64,
    argv_cage: u64,
    envp: u64,
    envp_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_EXECVE as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        argv, argv_cage,
        envp, envp_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// stat: Get file status, translating the path through chroot
extern "C" fn stat_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    statbuf: u64,
    statbuf_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_STAT as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        statbuf, statbuf_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// access: Check file permissions, translating the path through chroot
extern "C" fn access_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_ACCESS as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        mode, mode_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// statfs: Get filesystem statistics, translating the path through chroot
extern "C" fn statfs_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    buf: u64,
    buf_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_STATFS as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        buf, buf_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// mkdir: Create a directory, translating the path through chroot
extern "C" fn mkdir_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_MKDIR as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        mode, mode_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// rmdir: Remove a directory, translating the path through chroot
extern "C" fn rmdir_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
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
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_RMDIR as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// unlink: Delete a file, translating the path through chroot
extern "C" fn unlink_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
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
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_UNLINK as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// unlinkat: Delete a file relative to a directory fd.
/// If path is absolute or dirfd is AT_FDCWD, chroot the path.
/// Otherwise pass through (relative path uses already-chrooted dirfd).
extern "C" fn unlinkat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    const AT_FDCWD: i64 = -100;

    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };

    // If absolute path or AT_FDCWD, chroot it; otherwise pass through
    let (c_path, use_dirfd) = if path.starts_with('/') || dirfd as i64 == AT_FDCWD {
        (CString::new(chroot_path(&path, cageid)).ok(), AT_FDCWD as u64)
    } else {
        (CString::new(path).ok(), dirfd)
    };

    let c_path = match c_path {
        Some(p) => p,
        None => return -1,
    };

    match make_threei_call(
        SYS_UNLINKAT as u32, 0, cageid, path_cage,
        use_dirfd, dirfd_cage,
        c_path.as_ptr() as u64, thiscage,
        flags, flags_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

// -----------------------------------------------------------------------------
// Two-path handlers
// These handle syscalls that take two path arguments
// -----------------------------------------------------------------------------

/// rename: Rename a file, translating both paths through chroot
extern "C" fn rename_handler(
    cageid: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    let oldpath = match read_path_from_cage(oldpath_ptr, oldpath_cage) {
        Some(p) => p,
        None => return -14,
    };
    let newpath = match read_path_from_cage(newpath_ptr, newpath_cage) {
        Some(p) => p,
        None => return -14,
    };

    let c_oldpath = match CString::new(chroot_path(&oldpath, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let c_newpath = match CString::new(chroot_path(&newpath, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match make_threei_call(
        SYS_RENAME as u32, 0, cageid, oldpath_cage,
        c_oldpath.as_ptr() as u64, thiscage,
        c_newpath.as_ptr() as u64, thiscage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// link: Create a hard link, translating both paths through chroot
extern "C" fn link_handler(
    cageid: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    let oldpath = match read_path_from_cage(oldpath_ptr, oldpath_cage) {
        Some(p) => p,
        None => return -14,
    };
    let newpath = match read_path_from_cage(newpath_ptr, newpath_cage) {
        Some(p) => p,
        None => return -14,
    };

    let c_oldpath = match CString::new(chroot_path(&oldpath, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    let c_newpath = match CString::new(chroot_path(&newpath, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match make_threei_call(
        SYS_LINK as u32, 0, cageid, oldpath_cage,
        c_oldpath.as_ptr() as u64, thiscage,
        c_newpath.as_ptr() as u64, thiscage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// chmod: Change file permissions, translating the path through chroot
extern "C" fn chmod_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_CHMOD as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        mode, mode_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// truncate: Truncate a file to a specified length, translating the path through chroot
extern "C" fn truncate_handler(
    cageid: u64,
    path_ptr: u64,
    path_cage: u64,
    length: u64,
    length_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14,
    };
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match make_threei_call(
        SYS_TRUNCATE as u32, 0, cageid, path_cage,
        c_path.as_ptr() as u64, thiscage,
        length, length_cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

// -----------------------------------------------------------------------------
// State-tracking handlers
// These maintain the per-cage cwd table for proper path resolution
// -----------------------------------------------------------------------------

/// chdir: Change current working directory (virtual - updates our cwd table).
/// We don't call the real chdir; we just track the cwd per-cage in our hashmap.
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
    // Step 1: Read path from cage memory
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    // Normalize the path relative to current cwd
    let cwd = get_cage_cwd(cageid);
    let new_cwd = normalize_path(&path, &cwd);

    // Update the cage's cwd in the hashmap
    set_cage_cwd(cageid, new_cwd);

    0
}

/// fchdir: Change cwd to an open directory fd.
/// TODO: Need fd->path tracking to implement this portably.
/// Would require maintaining a table of fd->path mappings for each cage.
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
    -38 // ENOSYS - not implemented
}

/// getcwd: Return the cage's virtual current working directory.
/// Returns the path from our cwd table (not the host's actual cwd).
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

    // Step 1: Get the cage's virtual cwd from our table
    let cwd = get_cage_cwd(cageid);
    let cwd_bytes = cwd.as_bytes();

    // Check if buffer is large enough (need space for null terminator)
    if cwd_bytes.len() + 1 > size as usize {
        return -34; // ERANGE
    }

    // Create null-terminated buffer
    let mut buf = cwd_bytes.to_vec();
    buf.push(0);

    // Write to cage's buffer
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

// -----------------------------------------------------------------------------
// Path-output handlers
// These handle syscalls that return paths and need to strip the chroot prefix
// -----------------------------------------------------------------------------

/// readlink: Read the target of a symbolic link.
/// 1. Chroot the input path (the symlink location)
/// 2. Call the real readlink
/// 3. Strip the chroot prefix from the result (the symlink target)
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
    let chroot_dir = CHROOT_DIR.lock().unwrap().clone();

    // Step 1: Read and chroot the input path
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };
    let chrooted_path = chroot_path(&path, cageid);
    let c_path = match CString::new(chrooted_path) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // Call real readlink into our buffer
    let mut result_buf = vec![0u8; bufsiz as usize];
    let ret = match make_threei_call(
        SYS_READLINK as u32,
        0,
        cageid,
        path_cage,
        c_path.as_ptr() as u64, thiscage,
        result_buf.as_mut_ptr() as u64, thiscage,
        bufsiz, thiscage,
        0, 0,
        0, 0,
        0, 0,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    if ret < 0 {
        return ret;
    }

    // Un-chroot the result if it's absolute and within chroot
    let result_len = ret as usize;
    let result = String::from_utf8_lossy(&result_buf[..result_len]).to_string();

    let final_result = if result.starts_with(&chroot_dir) {
        let stripped = &result[chroot_dir.len()..];
        if stripped.is_empty() { "/".to_string() } else { stripped.to_string() }
    } else {
        result
    };

    // Write result to cage's buffer
    let final_bytes = final_result.as_bytes();
    let write_len = std::cmp::min(final_bytes.len(), bufsiz as usize);

    match copy_data_between_cages(
        thiscage,
        buf_cage,
        final_bytes.as_ptr() as u64,
        thiscage,
        buf,
        buf_cage,
        write_len as u64,
        0,
    ) {
        Ok(_) => write_len as i32,
        Err(_) => -14, // EFAULT
    }
}

/// readlinkat: Read a symlink target relative to a directory fd.
/// Similar to readlink but handles dirfd:
/// - If path is absolute or dirfd is AT_FDCWD, chroot the path
/// - Otherwise pass through (relative path uses already-chrooted dirfd)
/// Always strip chroot prefix from the returned symlink target.
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
    let chroot_dir = CHROOT_DIR.lock().unwrap().clone();
    const AT_FDCWD: i64 = -100;

    // Step 1: Read the input path
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    // If path is absolute or dirfd is AT_FDCWD, we can chroot it
    // Otherwise pass through (relative to dirfd which was already chrooted on open)
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

    // Call real readlinkat
    let mut result_buf = vec![0u8; bufsiz as usize];
    let ret = match make_threei_call(
        SYS_READLINKAT as u32,
        0,
        cageid,
        path_cage,
        if use_chrooted { AT_FDCWD as u64 } else { dirfd }, dirfd_cage,
        c_path.as_ptr() as u64, thiscage,
        result_buf.as_mut_ptr() as u64, thiscage,
        bufsiz, thiscage,
        0, 0,
        0, 0,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    if ret < 0 {
        return ret;
    }

    // Un-chroot the result if it's absolute and within chroot
    let result_len = ret as usize;
    let result = String::from_utf8_lossy(&result_buf[..result_len]).to_string();

    let final_result = if result.starts_with(&chroot_dir) {
        let stripped = &result[chroot_dir.len()..];
        if stripped.is_empty() { "/".to_string() } else { stripped.to_string() }
    } else {
        result
    };

    // Write result to cage's buffer
    let final_bytes = final_result.as_bytes();
    let write_len = std::cmp::min(final_bytes.len(), bufsiz as usize);

    match copy_data_between_cages(
        thiscage,
        buf_cage,
        final_bytes.as_ptr() as u64,
        thiscage,
        buf,
        buf_cage,
        write_len as u64,
        0,
    ) {
        Ok(_) => write_len as i32,
        Err(_) => -14, // EFAULT
    }
}

/// chroot: Deny nested chroot calls.
/// We are the chroot grate - cages cannot change their chroot jail.
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

// =============================================================================
// Socket Syscall Handlers
// =============================================================================
//
// AF_UNIX sockets use filesystem paths in their sockaddr_un structure.
// We need to translate these paths through the chroot:
//
// - Input handlers (bind, connect, sendto): Chroot the path in sockaddr_un
// - Output handlers (accept, getsockname, getpeername, recvfrom):
//   Strip chroot prefix from returned sockaddr_un paths

const AF_UNIX: u16 = 1;

/// Translate sockaddr if AF_UNIX (chroot the path), returns (translated_buf, new_len) or None on error
fn translate_sockaddr(cageid: u64, addr: u64, addr_cage: u64, addrlen: u64) -> Option<(Vec<u8>, u64)> {
    let thiscage = getcageid();

    if addrlen < 2 {
        return None;
    }

    let mut sockaddr_buf = vec![0u8; addrlen as usize];
    if copy_data_between_cages(
        thiscage,
        addr_cage,
        addr,
        addr_cage,
        sockaddr_buf.as_mut_ptr() as u64,
        thiscage,
        addrlen,
        0,
    ).is_err() {
        return None;
    }

    // Check sa_family (first 2 bytes)
    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);

    if sa_family == AF_UNIX && addrlen > 2 {
        // Extract and chroot the path (starts at offset 2)
        let path_bytes = &sockaddr_buf[2..];
        let path_len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        let path = String::from_utf8_lossy(&path_bytes[..path_len]).to_string();

        let chrooted = chroot_path(&path, cageid);

        // Build new sockaddr_un
        let mut new_sockaddr = vec![0u8; 2 + chrooted.len() + 1];
        new_sockaddr[0] = sockaddr_buf[0];
        new_sockaddr[1] = sockaddr_buf[1];
        new_sockaddr[2..2 + chrooted.len()].copy_from_slice(chrooted.as_bytes());

        Some((new_sockaddr.clone(), new_sockaddr.len() as u64))
    } else {
        // Not AF_UNIX, return original
        Some((sockaddr_buf, addrlen))
    }
}

/// Untranslate sockaddr if AF_UNIX (un-chroot the path), modifies buffer in place
/// Untranslate a sockaddr buffer in place (strip chroot prefix from AF_UNIX path)
fn untranslate_sockaddr(sockaddr_buf: &mut [u8]) {
    let chroot_dir = CHROOT_DIR.lock().unwrap().clone();

    // Need at least 2 bytes for sa_family
    if sockaddr_buf.len() < 2 {
        return;
    }

    // Check if this is an AF_UNIX socket
    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);
    if sa_family != AF_UNIX || sockaddr_buf.len() <= 2 {
        return;
    }

    // Extract the path (starts at offset 2, null-terminated)
    let path_bytes = &sockaddr_buf[2..];
    let path_len = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    let path = String::from_utf8_lossy(&path_bytes[..path_len]).to_string();

    // Strip chroot prefix if present to get virtual path
    let virtual_path = if path.starts_with(&chroot_dir) {
        let stripped = &path[chroot_dir.len()..];
        if stripped.is_empty() { "/".to_string() } else { stripped.to_string() }
    } else {
        path
    };

    // Write the virtual path back to the buffer
    let dest = &mut sockaddr_buf[2..];
    let copy_len = std::cmp::min(virtual_path.len(), dest.len() - 1);
    dest[..copy_len].copy_from_slice(&virtual_path.as_bytes()[..copy_len]);
    if copy_len < dest.len() {
        dest[copy_len] = 0; // null-terminate
    }
}

/// Read a returned sockaddr from cage memory, untranslate it, and write it back.
/// Used after syscalls that return a sockaddr (accept, getsockname, getpeername, recvfrom).
fn untranslate_sockaddr_in_cage(addr: u64, addr_cage: u64, addrlen_ptr: u64, addrlen_cage: u64) {
    // Skip if no address buffer provided
    if addr == 0 || addrlen_ptr == 0 {
        return;
    }

    let thiscage = getcageid();

    // Step 1: Read the addrlen value from cage memory to know buffer size
    let mut addrlen_buf = [0u8; 4];
    if copy_data_between_cages(
        thiscage, addrlen_cage,
        addrlen_ptr, addrlen_cage,
        addrlen_buf.as_mut_ptr() as u64, thiscage,
        4, 0,
    ).is_err() {
        return;
    }
    let addrlen = u32::from_ne_bytes(addrlen_buf) as usize;
    if addrlen == 0 {
        return;
    }

    // Step 2: Read the sockaddr from cage memory
    let mut sockaddr_buf = vec![0u8; addrlen];
    if copy_data_between_cages(
        thiscage, addr_cage,
        addr, addr_cage,
        sockaddr_buf.as_mut_ptr() as u64, thiscage,
        addrlen as u64, 0,
    ).is_err() {
        return;
    }

    // Step 3: Untranslate the sockaddr (strip chroot prefix if AF_UNIX)
    untranslate_sockaddr(&mut sockaddr_buf);

    // Step 4: Write the untranslated sockaddr back to cage memory
    let _ = copy_data_between_cages(
        thiscage, addr_cage,
        sockaddr_buf.as_ptr() as u64, thiscage,
        addr, addr_cage,
        addrlen as u64, 0,
    );
}

/// bind: Bind a socket to an address.
/// For AF_UNIX sockets, chroot the path in the sockaddr_un structure.
extern "C" fn bind_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    addr: u64,
    addr_cage: u64,
    addrlen: u64,
    addrlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Step 1: Translate the sockaddr (chroot AF_UNIX paths)
    let (sockaddr_buf, new_len) = match translate_sockaddr(cageid, addr, addr_cage, addrlen) {
        Some(v) => v,
        None => return -14, // EFAULT
    };

    match make_threei_call(
        SYS_BIND as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        sockaddr_buf.as_ptr() as u64, thiscage,
        new_len, addrlen_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// connect: Connect a socket to an address.
/// For AF_UNIX sockets, chroot the path in the sockaddr_un structure.
extern "C" fn connect_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    addr: u64,
    addr_cage: u64,
    addrlen: u64,
    addrlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // Step 1: Translate the sockaddr (chroot AF_UNIX paths)
    let (sockaddr_buf, new_len) = match translate_sockaddr(cageid, addr, addr_cage, addrlen) {
        Some(v) => v,
        None => return -14, // EFAULT
    };

    match make_threei_call(
        SYS_CONNECT as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        sockaddr_buf.as_ptr() as u64, thiscage,
        new_len, addrlen_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// sendto: Send a message to an address.
/// For AF_UNIX sockets, chroot the path in the destination sockaddr_un.
extern "C" fn sendto_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    buf: u64,
    buf_cage: u64,
    len: u64,
    len_cage: u64,
    flags: u64,
    flags_cage: u64,
    dest_addr: u64,
    dest_addr_cage: u64,
    addrlen: u64,
    addrlen_cage: u64,
) -> i32 {
    let thiscage = getcageid();

    // If dest_addr is provided, translate it (chroot AF_UNIX paths)
    if dest_addr != 0 && addrlen > 0 {
        let (sockaddr_buf, new_len) = match translate_sockaddr(cageid, dest_addr, dest_addr_cage, addrlen) {
            Some(v) => v,
            None => return -14,
        };

        match make_threei_call(
            SYS_SENDTO as u32, 0, cageid, sockfd_cage,
            sockfd, sockfd_cage,
            buf, buf_cage,
            len, len_cage,
            flags, flags_cage,
            sockaddr_buf.as_ptr() as u64, thiscage,
            new_len, addrlen_cage,
            0,
        ) {
            Ok(ret) => ret,
            Err(_) => -1,
        }
    } else {
        // No dest_addr, pass through
        match make_threei_call(
            SYS_SENDTO as u32, 0, cageid, sockfd_cage,
            sockfd, sockfd_cage,
            buf, buf_cage,
            len, len_cage,
            flags, flags_cage,
            dest_addr, dest_addr_cage,
            addrlen, addrlen_cage,
            0,
        ) {
            Ok(ret) => ret,
            Err(_) => -1,
        }
    }
}

/// accept: Accept a connection on a socket.
/// Returns the peer's address - for AF_UNIX, strip chroot prefix from the path.
extern "C" fn accept_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    addr: u64,
    addr_cage: u64,
    addrlen_ptr: u64,
    addrlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    // Step 1: Call the real accept syscall
    let ret = match make_threei_call(
        SYS_ACCEPT as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        addr, addr_cage,
        addrlen_ptr, addrlen_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Step 2: On success, untranslate the returned peer sockaddr (strip chroot from AF_UNIX)
    if ret >= 0 {
        untranslate_sockaddr_in_cage(addr, addr_cage, addrlen_ptr, addrlen_cage);
    }

    ret
}

/// getsockname: Get the local address of a socket.
/// For AF_UNIX, strip chroot prefix from the returned path.
extern "C" fn getsockname_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    addr: u64,
    addr_cage: u64,
    addrlen_ptr: u64,
    addrlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    // Step 1: Call the real getsockname syscall
    let ret = match make_threei_call(
        SYS_GETSOCKNAME as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        addr, addr_cage,
        addrlen_ptr, addrlen_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Step 2: On success, untranslate the returned sockaddr (strip chroot from AF_UNIX)
    if ret >= 0 {
        untranslate_sockaddr_in_cage(addr, addr_cage, addrlen_ptr, addrlen_cage);
    }

    ret
}

/// getpeername: Get the remote address of a connected socket.
/// For AF_UNIX, strip chroot prefix from the returned path.
extern "C" fn getpeername_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    addr: u64,
    addr_cage: u64,
    addrlen_ptr: u64,
    addrlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    // Step 1: Call the real getpeername syscall
    let ret = match make_threei_call(
        SYS_GETPEERNAME as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        addr, addr_cage,
        addrlen_ptr, addrlen_cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Step 2: On success, untranslate the returned sockaddr (strip chroot from AF_UNIX)
    if ret >= 0 {
        untranslate_sockaddr_in_cage(addr, addr_cage, addrlen_ptr, addrlen_cage);
    }

    ret
}

/// recvfrom: Receive a message and get the sender's address.
/// For AF_UNIX, strip chroot prefix from the returned source address path.
extern "C" fn recvfrom_handler(
    cageid: u64,
    sockfd: u64,
    sockfd_cage: u64,
    buf: u64,
    buf_cage: u64,
    len: u64,
    len_cage: u64,
    flags: u64,
    flags_cage: u64,
    src_addr: u64,
    src_addr_cage: u64,
    addrlen_ptr: u64,
    addrlen_cage: u64,
) -> i32 {
    // Step 1: Call the real recvfrom syscall
    let ret = match make_threei_call(
        SYS_RECVFROM as u32, 0, cageid, sockfd_cage,
        sockfd, sockfd_cage,
        buf, buf_cage,
        len, len_cage,
        flags, flags_cage,
        src_addr, src_addr_cage,
        addrlen_ptr, addrlen_cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    // Step 2: On success, untranslate the returned source sockaddr (strip chroot from AF_UNIX)
    if ret >= 0 {
        untranslate_sockaddr_in_cage(src_addr, src_addr_cage, addrlen_ptr, addrlen_cage);
    }

    ret
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
    let (chroot_dir, _remaining_args) = parse_args();

    if chroot_dir.is_empty() {
        eprintln!("Usage: chroot-grate --chroot-dir <path> <program> [args...]");
        std::process::exit(1);
    }

    println!("[chroot-grate] Initializing with chroot dir: {}", chroot_dir);

    init_state(chroot_dir);

    // Get initial cwd via syscall and add to table
    let cageid = getcageid();
    let initial_cwd = init_cwd(cageid);

    println!("[chroot-grate] Initial cwd: {}", initial_cwd);

    let builder = GrateBuilder::new()
        // Process management
        .register(SYS_FORK, fork_handler)
        // Filesystem syscalls
        .register(SYS_OPEN, open_handler)
        .register(SYS_EXECVE, execve_handler)
        .register(SYS_STAT, stat_handler)
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
        .register(SYS_RECVFROM, recvfrom_handler);

    match builder.run() {
        Ok(status) => {
            println!("[chroot-grate] Cage exited with status: {}", status);
        }
        Err(e) => {
            eprintln!("[chroot-grate] Failed to run grate: {:?}", e);
            std::process::exit(1);
        }
    }
}
