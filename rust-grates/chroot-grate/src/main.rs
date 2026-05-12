//! `chroot-grate-rs`

use grate_rs::constants::fs::{F_DUPFD, F_DUPFD_CLOEXEC, S_IFDIR};
use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::{
    SYS_ACCEPT, SYS_ACCESS, SYS_BIND, SYS_CHDIR, SYS_CHMOD, SYS_CHOWN, SYS_CHROOT, SYS_CLONE,
    SYS_CLOSE, SYS_CONNECT, SYS_DUP, SYS_DUP2, SYS_DUP3, SYS_EXECVE, SYS_FACCESSAT, SYS_FCHDIR,
    SYS_FCHMODAT, SYS_FCHOWNAT, SYS_FCNTL, SYS_GETCWD, SYS_GETPEERNAME, SYS_GETSOCKNAME,
    SYS_LCHOWN, SYS_LINK, SYS_LISTXATTR, SYS_MKDIR, SYS_NEWFSTATAT, SYS_OPEN, SYS_OPENAT,
    SYS_READLINK, SYS_READLINKAT, SYS_RECVFROM, SYS_RENAME, SYS_RENAMEAT, SYS_RENAMEAT2, SYS_RMDIR,
    SYS_SENDTO, SYS_SETXATTR, SYS_STATFS, SYS_STATX, SYS_SYMLINK, SYS_SYMLINKAT, SYS_TRUNCATE,
    SYS_UNLINK, SYS_UNLINKAT, SYS_UTIMENSAT, SYS_XSTAT,
};
use grate_rs::ffi::stat;
use grate_rs::{
    GrateBuilder, GrateError, copy_data_between_cages, copy_handler_table_to_cage, getcageid,
    is_thread_clone, make_threei_call,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::c_char;
use std::sync::Mutex;

mod logging;
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

/// Per-cage directory fd tracking used to implement virtual `fchdir`.
pub static CAGE_DIR_FDS: Mutex<Option<HashMap<u64, HashMap<u64, String>>>> = Mutex::new(None);

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
            *CAGE_DIR_FDS.lock().unwrap() = Some(HashMap::new());
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
        arg_cages[*idx] = thiscage | GRATE_MEMORY_FLAG;
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
        // Propagate the kernel's actual -errno (e.g. -ENOENT, -EEXIST,
        // -EISDIR) instead of collapsing every failure to -1 / EPERM.
        // glibc's MAKE_LEGACY_SYSCALL with TRANSLATE_ERRNO_ON converts
        // negative values in [-MAX_ERRNO, -1] into errno + return -1.
        Err(GrateError::MakeSyscallError(n)) => n,
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

const AT_FDCWD: i64 = -100;

fn make_syscall_from_grate(
    syscall_no: u32,
    target_cageid: u64,
    args: [u64; 6],
    arg_cages: [u64; 6],
) -> i32 {
    let thiscage = getcageid();
    match make_threei_call(
        syscall_no,
        0,
        thiscage,
        target_cageid,
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
        Ok(r) => r,
        Err(GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    }
}

fn rewrite_at_path(
    cageid: u64,
    dirfd: u64,
    path_ptr: u64,
    path_cage: u64,
) -> Result<(u64, CString), i32> {
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return Err(-(libc::EFAULT as i32)),
    };

    let (rewritten_dirfd, rewritten_path) = if path.starts_with('/') || dirfd as i64 == AT_FDCWD {
        (AT_FDCWD as u64, chroot_path(&path, cageid))
    } else {
        (dirfd, path)
    };

    match CString::new(rewritten_path) {
        Ok(path) => Ok((rewritten_dirfd, path)),
        Err(_) => Err(-(libc::EINVAL as i32)),
    }
}

fn call_with_at_path(
    syscall_no: u32,
    cageid: u64,
    target_cageid: u64,
    mut args: [u64; 6],
    mut arg_cages: [u64; 6],
    dirfd_idx: usize,
    path_idx: usize,
) -> i32 {
    let thiscage = getcageid();
    let (dirfd, c_path) =
        match rewrite_at_path(cageid, args[dirfd_idx], args[path_idx], arg_cages[path_idx]) {
            Ok(v) => v,
            Err(e) => return e,
        };

    args[dirfd_idx] = dirfd;
    args[path_idx] = c_path.as_ptr() as u64;
    arg_cages[path_idx] = thiscage | GRATE_MEMORY_FLAG;

    make_syscall_from_grate(syscall_no, target_cageid, args, arg_cages)
}

fn rewrite_symlink_target(cageid: u64, target_ptr: u64, target_cage: u64) -> Result<CString, i32> {
    let target = match read_path_from_cage(target_ptr, target_cage) {
        Some(p) => p,
        None => return Err(-(libc::EFAULT as i32)),
    };

    let rewritten = if target.starts_with('/') {
        chroot_path(&target, cageid)
    } else {
        target
    };

    CString::new(rewritten).map_err(|_| -(libc::EINVAL as i32))
}

fn fd_dir_path(cageid: u64, fd: u64) -> Option<String> {
    CAGE_DIR_FDS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&cageid))
        .and_then(|fds| fds.get(&fd).cloned())
}

fn set_fd_dir_path(cageid: u64, fd: u64, path: String) {
    if let Some(ref mut cages) = *CAGE_DIR_FDS.lock().unwrap() {
        cages
            .entry(cageid)
            .or_insert_with(HashMap::new)
            .insert(fd, path);
    }
}

fn clear_fd_dir_path(cageid: u64, fd: u64) {
    if let Some(ref mut cages) = *CAGE_DIR_FDS.lock().unwrap() {
        if let Some(fds) = cages.get_mut(&cageid) {
            fds.remove(&fd);
        }
    }
}

fn copy_fd_dir_path(cageid: u64, oldfd: u64, newfd: u64) {
    match fd_dir_path(cageid, oldfd) {
        Some(path) => set_fd_dir_path(cageid, newfd, path),
        None => clear_fd_dir_path(cageid, newfd),
    }
}

fn register_dir_fd_if_directory(cageid: u64, fd: u64, virtual_path: String) {
    let host_path = chroot_path(&virtual_path, cageid);
    if check_dir(host_path) {
        set_fd_dir_path(cageid, fd, virtual_path);
    } else {
        clear_fd_dir_path(cageid, fd);
    }
}

fn register_child_fd_paths(parent_cageid: u64, child_cageid: u64) {
    let parent_fds = CAGE_DIR_FDS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&parent_cageid).cloned());

    if let (Some(parent_fds), Some(ref mut cages)) =
        (parent_fds, CAGE_DIR_FDS.lock().unwrap().as_mut())
    {
        cages.insert(child_cageid, parent_fds);
    }
}

fn resolve_virtual_at_path(cageid: u64, dirfd: u64, path: &str) -> Option<String> {
    if path.starts_with('/') || dirfd as i64 == AT_FDCWD {
        Some(normalize_path(path, &get_cage_cwd(cageid)))
    } else {
        fd_dir_path(cageid, dirfd).map(|dir| normalize_path(path, &dir))
    }
}

// -----------------------------------------------------------------------------
// Macro-generated handler declarations
// -----------------------------------------------------------------------------

// "Path input" syscalls: read the path argument(s), chroot them, and dispatch
// the real syscall with rewritten pointers.
// input_path_handler!(execve_handler, SYS_EXECVE, 0);
input_path_handler!(stat_handler, SYS_XSTAT, 0);
input_path_handler!(access_handler, SYS_ACCESS, 0);
input_path_handler!(statfs_handler, SYS_STATFS, 0);
input_path_handler!(mkdir_handler, SYS_MKDIR, 0);
input_path_handler!(rmdir_handler, SYS_RMDIR, 0);
input_path_handler!(unlink_handler, SYS_UNLINK, 0);
input_path_handler!(chmod_handler, SYS_CHMOD, 0);
input_path_handler!(chown_handler, SYS_CHOWN, 0);
input_path_handler!(lchown_handler, SYS_LCHOWN, 0);
input_path_handler!(truncate_handler, SYS_TRUNCATE, 0);
input_path_handler!(setxattr_handler, SYS_SETXATTR, 0);
input_path_handler!(listxattr_handler, SYS_LISTXATTR, 0);

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
// FD tracking handlers
// -----------------------------------------------------------------------------

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
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -(libc::EFAULT as i32),
    };
    let virtual_path = normalize_path(&path, &get_cage_cwd(cageid));
    let c_path = match CString::new(chroot_path(&path, cageid)) {
        Ok(p) => p,
        Err(_) => return -(libc::EINVAL as i32),
    };

    let ret = make_syscall_from_grate(
        SYS_OPEN as u32,
        path_cage,
        [c_path.as_ptr() as u64, flags, mode, arg4, arg5, arg6],
        [
            thiscage | GRATE_MEMORY_FLAG,
            flags_cage,
            mode_cage,
            arg4cage,
            arg5cage,
            arg6cage,
        ],
    );

    if ret >= 0 {
        register_dir_fd_if_directory(cageid, ret as u64, virtual_path);
    }

    ret
}

extern "C" fn openat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    flags: u64,
    flags_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -(libc::EFAULT as i32),
    };
    let virtual_path = resolve_virtual_at_path(cageid, dirfd, &path);
    let (rewritten_dirfd, c_path) = match rewrite_at_path(cageid, dirfd, path_ptr, path_cage) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let ret = make_syscall_from_grate(
        SYS_OPENAT as u32,
        dirfd_cage,
        [
            rewritten_dirfd,
            c_path.as_ptr() as u64,
            flags,
            mode,
            arg5,
            arg6,
        ],
        [
            dirfd_cage,
            thiscage | GRATE_MEMORY_FLAG,
            flags_cage,
            mode_cage,
            arg5cage,
            arg6cage,
        ],
    );

    if ret >= 0 {
        if let Some(virtual_path) = virtual_path {
            register_dir_fd_if_directory(cageid, ret as u64, virtual_path);
        }
    }

    ret
}

extern "C" fn close_handler(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
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
    let ret = make_syscall_from_grate(
        SYS_CLOSE as u32,
        fd_cage,
        [fd, arg2, arg3, arg4, arg5, arg6],
        [fd_cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        clear_fd_dir_path(cageid, fd);
    }

    ret
}

extern "C" fn dup_handler(
    cageid: u64,
    oldfd: u64,
    oldfd_cage: u64,
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
    let ret = make_syscall_from_grate(
        SYS_DUP as u32,
        oldfd_cage,
        [oldfd, arg2, arg3, arg4, arg5, arg6],
        [oldfd_cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 {
        copy_fd_dir_path(cageid, oldfd, ret as u64);
    }

    ret
}

extern "C" fn dup2_handler(
    cageid: u64,
    oldfd: u64,
    oldfd_cage: u64,
    newfd: u64,
    newfd_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let ret = make_syscall_from_grate(
        SYS_DUP2 as u32,
        oldfd_cage,
        [oldfd, newfd, arg3, arg4, arg5, arg6],
        [
            oldfd_cage, newfd_cage, arg3cage, arg4cage, arg5cage, arg6cage,
        ],
    );

    if ret >= 0 {
        copy_fd_dir_path(cageid, oldfd, newfd);
    }

    ret
}

extern "C" fn dup3_handler(
    cageid: u64,
    oldfd: u64,
    oldfd_cage: u64,
    newfd: u64,
    newfd_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let ret = make_syscall_from_grate(
        SYS_DUP3 as u32,
        oldfd_cage,
        [oldfd, newfd, flags, arg4, arg5, arg6],
        [
            oldfd_cage, newfd_cage, flags_cage, arg4cage, arg5cage, arg6cage,
        ],
    );

    if ret >= 0 {
        copy_fd_dir_path(cageid, oldfd, newfd);
    }

    ret
}

extern "C" fn fcntl_handler(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    cmd: u64,
    cmd_cage: u64,
    arg: u64,
    arg_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let ret = make_syscall_from_grate(
        SYS_FCNTL as u32,
        fd_cage,
        [fd, cmd, arg, arg4, arg5, arg6],
        [fd_cage, cmd_cage, arg_cage, arg4cage, arg5cage, arg6cage],
    );

    if ret >= 0 && (cmd as i32 == F_DUPFD || cmd as i32 == F_DUPFD_CLOEXEC) {
        copy_fd_dir_path(cageid, fd, ret as u64);
    }

    ret
}

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
        thiscage | GRATE_MEMORY_FLAG,
        result_buf.as_mut_ptr() as u64,
        thiscage | GRATE_MEMORY_FLAG,
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
        Err(GrateError::MakeSyscallError(n)) => return n,
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
        thiscage | GRATE_MEMORY_FLAG,
        result_buf.as_mut_ptr() as u64,
        thiscage | GRATE_MEMORY_FLAG,
        bufsiz,
        thiscage,
        0,
        0,
        0,
        0,
        0,
    ) {
        Ok(r) => r,
        Err(GrateError::MakeSyscallError(n)) => return n,
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

/// `unlinkat(2)` handler.
///
/// Mirrors `readlinkat_handler`'s dirfd handling:
/// - If `path` is absolute or `dirfd == AT_FDCWD`, chroot the path and pass
///   `AT_FDCWD` through.
/// - Otherwise, pass the relative path and the original `dirfd` through
///   unchanged (the dirfd already refers to an open directory inside the
///   chrooted tree at the kernel level).
///
/// Without this dirfd-aware logic, a relative path like `"file.txt"` against an
/// `open(2)`-returned dirfd would be normalized against the cage's cwd and
/// chrooted into an absolute path, causing the kernel to ignore `dirfd`.
extern "C" fn unlinkat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    flags: u64,
    flags_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    const AT_FDCWD: i64 = -100;

    let path = match read_path_from_cage(path_ptr, path_cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

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

    match make_threei_call(
        SYS_UNLINKAT as u32,
        0,
        cageid,
        path_cage,
        if use_chrooted { AT_FDCWD as u64 } else { dirfd },
        dirfd_cage,
        c_path.as_ptr() as u64,
        thiscage | GRATE_MEMORY_FLAG,
        flags,
        flags_cage,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ) {
        Ok(r) => r,
        Err(GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    }
}

extern "C" fn symlink_handler(
    cageid: u64,
    target_ptr: u64,
    target_cage: u64,
    linkpath_ptr: u64,
    linkpath_cage: u64,
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

    let target = match rewrite_symlink_target(cageid, target_ptr, target_cage) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let linkpath = match read_path_from_cage(linkpath_ptr, linkpath_cage) {
        Some(p) => p,
        None => return -(libc::EFAULT as i32),
    };
    let linkpath = match CString::new(chroot_path(&linkpath, cageid)) {
        Ok(v) => v,
        Err(_) => return -(libc::EINVAL as i32),
    };

    make_syscall_from_grate(
        SYS_SYMLINK as u32,
        target_cage,
        [
            target.as_ptr() as u64,
            linkpath.as_ptr() as u64,
            arg3,
            arg4,
            arg5,
            arg6,
        ],
        [
            thiscage | GRATE_MEMORY_FLAG,
            thiscage | GRATE_MEMORY_FLAG,
            arg3cage,
            arg4cage,
            arg5cage,
            arg6cage,
        ],
    )
}

extern "C" fn symlinkat_handler(
    cageid: u64,
    target_ptr: u64,
    target_cage: u64,
    dirfd: u64,
    dirfd_cage: u64,
    linkpath_ptr: u64,
    linkpath_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();

    let target = match rewrite_symlink_target(cageid, target_ptr, target_cage) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (rewritten_dirfd, linkpath) =
        match rewrite_at_path(cageid, dirfd, linkpath_ptr, linkpath_cage) {
            Ok(v) => v,
            Err(e) => return e,
        };

    make_syscall_from_grate(
        SYS_SYMLINKAT as u32,
        dirfd_cage,
        [
            target.as_ptr() as u64,
            rewritten_dirfd,
            linkpath.as_ptr() as u64,
            arg4,
            arg5,
            arg6,
        ],
        [
            thiscage | GRATE_MEMORY_FLAG,
            dirfd_cage,
            thiscage | GRATE_MEMORY_FLAG,
            arg4cage,
            arg5cage,
            arg6cage,
        ],
    )
}

extern "C" fn faccessat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    mode: u64,
    mode_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    call_with_at_path(
        SYS_FACCESSAT as u32,
        cageid,
        dirfd_cage,
        [dirfd, path_ptr, mode, flags, arg5, arg6],
        [
            dirfd_cage, path_cage, mode_cage, flags_cage, arg5cage, arg6cage,
        ],
        0,
        1,
    )
}

extern "C" fn fchmodat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    mode: u64,
    mode_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    call_with_at_path(
        SYS_FCHMODAT as u32,
        cageid,
        dirfd_cage,
        [dirfd, path_ptr, mode, flags, arg5, arg6],
        [
            dirfd_cage, path_cage, mode_cage, flags_cage, arg5cage, arg6cage,
        ],
        0,
        1,
    )
}

extern "C" fn fchownat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    owner: u64,
    owner_cage: u64,
    group: u64,
    group_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    call_with_at_path(
        SYS_FCHOWNAT as u32,
        cageid,
        dirfd_cage,
        [dirfd, path_ptr, owner, group, flags, arg6],
        [
            dirfd_cage, path_cage, owner_cage, group_cage, flags_cage, arg6cage,
        ],
        0,
        1,
    )
}

extern "C" fn fstatat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    statbuf: u64,
    statbuf_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    call_with_at_path(
        SYS_NEWFSTATAT as u32,
        cageid,
        dirfd_cage,
        [dirfd, path_ptr, statbuf, flags, arg5, arg6],
        [
            dirfd_cage,
            path_cage,
            statbuf_cage,
            flags_cage,
            arg5cage,
            arg6cage,
        ],
        0,
        1,
    )
}

extern "C" fn statx_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    flags: u64,
    flags_cage: u64,
    mask: u64,
    mask_cage: u64,
    statxbuf: u64,
    statxbuf_cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    call_with_at_path(
        SYS_STATX as u32,
        cageid,
        dirfd_cage,
        [dirfd, path_ptr, flags, mask, statxbuf, arg6],
        [
            dirfd_cage,
            path_cage,
            flags_cage,
            mask_cage,
            statxbuf_cage,
            arg6cage,
        ],
        0,
        1,
    )
}

extern "C" fn utimensat_handler(
    cageid: u64,
    dirfd: u64,
    dirfd_cage: u64,
    path_ptr: u64,
    path_cage: u64,
    times: u64,
    times_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let args = [dirfd, path_ptr, times, flags, arg5, arg6];
    let arg_cages = [
        dirfd_cage, path_cage, times_cage, flags_cage, arg5cage, arg6cage,
    ];

    if path_ptr == 0 {
        return make_syscall_from_grate(SYS_UTIMENSAT as u32, dirfd_cage, args, arg_cages);
    }

    call_with_at_path(
        SYS_UTIMENSAT as u32,
        cageid,
        dirfd_cage,
        args,
        arg_cages,
        0,
        1,
    )
}

extern "C" fn renameat_handler(
    cageid: u64,
    olddirfd: u64,
    olddirfd_cage: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newdirfd: u64,
    newdirfd_cage: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    renameat_common(
        SYS_RENAMEAT as u32,
        cageid,
        olddirfd,
        olddirfd_cage,
        oldpath_ptr,
        oldpath_cage,
        newdirfd,
        newdirfd_cage,
        newpath_ptr,
        newpath_cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
    )
}

extern "C" fn renameat2_handler(
    cageid: u64,
    olddirfd: u64,
    olddirfd_cage: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newdirfd: u64,
    newdirfd_cage: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    flags: u64,
    flags_cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    renameat_common(
        SYS_RENAMEAT2 as u32,
        cageid,
        olddirfd,
        olddirfd_cage,
        oldpath_ptr,
        oldpath_cage,
        newdirfd,
        newdirfd_cage,
        newpath_ptr,
        newpath_cage,
        flags,
        flags_cage,
        arg6,
        arg6cage,
    )
}

fn renameat_common(
    syscall_no: u32,
    cageid: u64,
    olddirfd: u64,
    olddirfd_cage: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newdirfd: u64,
    newdirfd_cage: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let thiscage = getcageid();
    let (rewritten_olddirfd, oldpath) =
        match rewrite_at_path(cageid, olddirfd, oldpath_ptr, oldpath_cage) {
            Ok(v) => v,
            Err(e) => return e,
        };
    let (rewritten_newdirfd, newpath) =
        match rewrite_at_path(cageid, newdirfd, newpath_ptr, newpath_cage) {
            Ok(v) => v,
            Err(e) => return e,
        };

    make_syscall_from_grate(
        syscall_no,
        olddirfd_cage,
        [
            rewritten_olddirfd,
            oldpath.as_ptr() as u64,
            rewritten_newdirfd,
            newpath.as_ptr() as u64,
            arg5,
            arg6,
        ],
        [
            olddirfd_cage,
            thiscage | GRATE_MEMORY_FLAG,
            newdirfd_cage,
            thiscage | GRATE_MEMORY_FLAG,
            arg5cage,
            arg6cage,
        ],
    )
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
        Err(GrateError::MakeSyscallError(n)) => return n,
        Err(_) => return -1,
    };

    if ret > 0 && !is_thread_clone(arg1, arg1cage) {
        let child_cageid = ret as u64;
        register_cage(cageid, child_cageid);
        register_child_fd_paths(cageid, child_cageid);
        let _ = copy_handler_table_to_cage(getcageid(), child_cageid);
    }

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
        thiscage | GRATE_MEMORY_FLAG,
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
        Err(GrateError::MakeSyscallError(n)) => return n,
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

    match check_dir(chroot_path(&new_cwd, cageid)) {
        false => return -20, // ENOTDIR
        true => {
            // Update the cwd of cage in our hashmap.
            set_cage_cwd(cageid, new_cwd);
            return 0;
        }
    }
}

extern "C" fn fchdir_handler(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    _arg2: u64,
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
    if let Some(path) = fd_dir_path(cageid, fd) {
        set_cage_cwd(cageid, path);
        return 0;
    }

    const F_GETFL_CMD: u64 = 3;
    let ret = make_syscall_from_grate(
        SYS_FCNTL as u32,
        fd_cage,
        [fd, F_GETFL_CMD, arg3, arg4, arg5, arg6],
        [fd_cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    );

    if ret < 0 {
        ret
    } else {
        -(libc::ENOTDIR as i32)
    }
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
        Ok(_) => buf.len() as i32,
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

struct Config {
    chroot_dir: String,
    remaining_args: Vec<String>,
    log_enabled: bool,
}

fn parse_args() -> Result<Config, &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut chroot_dir = String::new();
    let mut remaining_args = Vec::new();
    let mut log_enabled = false;
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--log" {
            log_enabled = true;
            i += 1;
        } else if args[i] == "--chroot-dir" {
            if i + 1 >= args.len() {
                return Err("--chroot-dir requires an argument");
            }
            chroot_dir = args[i + 1].clone();
            i += 2;
        } else {
            remaining_args.push(args[i].clone());
            i += 1;
        }
    }

    Ok(Config {
        chroot_dir,
        remaining_args,
        log_enabled,
    })
}

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("argument error: {}", err);
            eprintln!("Usage: chroot-grate [--log] --chroot-dir <path> <program> [args...]");
            std::process::exit(1);
        }
    };
    logging::init(config.log_enabled);

    if config.chroot_dir.is_empty() {
        eprintln!("Usage: chroot-grate [--log] --chroot-dir <path> <program> [args...]");
        std::process::exit(1);
    }

    log!("Initializing with chroot dir: {}", config.chroot_dir);

    init_state(config.chroot_dir);

    // Get initial cwd via syscall and add to table
    let cageid = getcageid();
    let initial_cwd = init_cwd(cageid);

    log!("Initial cwd: {}", initial_cwd);

    let initial_cwd_for_child = initial_cwd.clone();

    let builder = GrateBuilder::new()
        // Process management
        .register(SYS_CLONE, fork_handler)
        // Filesystem syscalls
        .register(SYS_OPEN, open_handler)
        .register(SYS_OPENAT, openat_handler)
        .register(SYS_CLOSE, close_handler)
        .register(SYS_DUP, dup_handler)
        .register(SYS_DUP2, dup2_handler)
        .register(SYS_DUP3, dup3_handler)
        .register(SYS_FCNTL, fcntl_handler)
        .register(SYS_EXECVE, execve_handler)
        .register(SYS_XSTAT, stat_handler)
        .register(SYS_NEWFSTATAT, fstatat_handler)
        .register(SYS_STATX, statx_handler)
        .register(SYS_ACCESS, access_handler)
        .register(SYS_FACCESSAT, faccessat_handler)
        .register(SYS_STATFS, statfs_handler)
        .register(SYS_MKDIR, mkdir_handler)
        .register(SYS_RMDIR, rmdir_handler)
        .register(SYS_UNLINK, unlink_handler)
        .register(SYS_UNLINKAT, unlinkat_handler)
        .register(SYS_RENAME, rename_handler)
        .register(SYS_RENAMEAT, renameat_handler)
        .register(SYS_RENAMEAT2, renameat2_handler)
        .register(SYS_LINK, link_handler)
        .register(SYS_SYMLINK, symlink_handler)
        .register(SYS_SYMLINKAT, symlinkat_handler)
        .register(SYS_CHMOD, chmod_handler)
        .register(SYS_FCHMODAT, fchmodat_handler)
        .register(SYS_CHOWN, chown_handler)
        .register(SYS_LCHOWN, lchown_handler)
        .register(SYS_FCHOWNAT, fchownat_handler)
        .register(SYS_TRUNCATE, truncate_handler)
        .register(SYS_SETXATTR, setxattr_handler)
        .register(SYS_LISTXATTR, listxattr_handler)
        .register(SYS_UTIMENSAT, utimensat_handler)
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
        .preexec(move |child_cage| {
            let child_cage = child_cage as u64;
            set_cage_cwd(child_cage, initial_cwd_for_child.clone());
            if let Some(ref mut cages) = *CAGE_DIR_FDS.lock().unwrap() {
                cages.entry(child_cage).or_insert_with(HashMap::new);
            }
        })
        .teardown(|result| {
            log!("Result: {:#?}", result);
        });

    builder.run(config.remaining_args);
}
