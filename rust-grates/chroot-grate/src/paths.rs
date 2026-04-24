//! Path utilities and path-rewriting syscall handler helpers.
//!
//! This module provides:
//! - Virtual path resolution (`normalize_path`) using the cage's tracked cwd.
//! - Chroot path mapping (`chroot_path`) that prepends the configured chroot directory.
//! - Helpers for reading paths out of a cage address space.
//! - The `input_path_handler!` macro used by `main.rs` to generate syscall
//!   handlers for "path input" syscalls (e.g. `open`, `mkdir`, `unlink`).
//!
//! The chroot directory and per-cage cwd table live in the crate root:
//! `crate::CHROOT_DIR` and `crate::CAGE_CWDS`.

use grate_rs::{copy_data_between_cages, getcageid};
use std::ffi::CStr;

/// Generate a syscall handler that rewrites one or more path arguments.
///
/// The generated handler:
/// 1) reads each path argument from the calling cage's memory,
/// 2) normalizes it relative to the cage's virtual cwd,
/// 3) prepends the configured chroot directory,
/// 4) dispatches the real syscall via `call_with_rewrites`.
///
/// # Parameters
/// - `$name`: function name for the generated handler.
/// - `$syscall_const`: syscall number constant (e.g. `SYS_OPEN`).
/// - `$idx...`: argument indices (0..=5) that are path pointers.
#[macro_export]
macro_rules! input_path_handler {
    ($name:ident, $syscall_const:expr, $( $idx:expr ),+ $(,)?) => {
        extern "C" fn $name(
            cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            let thiscage = getcageid();

            let callingcage = arg1cage;

            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            // Own the rewritten C strings so their buffers stay alive for the
            // duration of `call_with_rewrites`.
            let mut _owned_paths: Vec<::std::ffi::CString> = Vec::new();
            let mut rewrites: Vec<(usize, u64)> = Vec::new();

            $(
                let ptr = args[$idx];
                let cage = cages[$idx];

                // Read the original path from the cage's address space.
                let path = match read_path_from_cage(ptr, cage) {
                    Some(p) => p,
                    None => return -(::libc::EFAULT as i32),
                };

                // Apply chroot transformation (normalize relative to cwd, prepend chroot dir).
                let transformed = chroot_path(&path, cageid);
                let c_path = match ::std::ffi::CString::new(transformed) {
                    Ok(p) => p,
                    Err(_) => return -1,
                };

                let rewritten_ptr = c_path.as_ptr() as u64;
                _owned_paths.push(c_path);
                rewrites.push(($idx as usize, rewritten_ptr));
            )+

            // Dispatch the syscall "as" the cage associated with arg1 (typically
            // the calling cage), with rewritten pointers owned by this grate.
            call_with_rewrites(
                $syscall_const as u32,
                thiscage,
                callingcage,
                args,
                cages,
                &rewrites,
            )
        }
    };
}

/// Normalize a path: resolve `..` and `.` and return an absolute path.
///
/// Relative `path`s are interpreted relative to `cwd`.
pub fn normalize_path(path: &str, cwd: &str) -> String {
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

/// Apply chroot mapping: normalize and prepend the configured chroot directory.
pub fn chroot_path(path: &str, cageid: u64) -> String {
    let chroot_dir = crate::CHROOT_DIR.lock().unwrap().clone();
    let cwd = get_cage_cwd(cageid);

    // Normalize the path relative to cage's cwd
    let normalized = normalize_path(path, &cwd);

    // Prepend chroot directory
    format!("{}{}", chroot_dir.trim_end_matches('/'), normalized)
}

/// Read a NUL-terminated C string from a cage's memory and return it as UTF-8.
///
/// Reads at most 4096 bytes; if no NUL terminator is found within that window,
/// the whole buffer is returned.
pub fn read_path_from_cage(ptr: u64, src_cage: u64) -> Option<String> {
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

/// Seed the per-cage cwd table using the host `getcwd(2)`.
pub fn init_cwd(cageid: u64) -> String {
    let mut buf = vec![0u8; 4096];

    let _ = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut libc::c_char, 4096) };

    let cwd = unsafe {
        CStr::from_ptr(buf.as_ptr() as *mut i8)
            .to_string_lossy()
            .into_owned()
    };

    set_cage_cwd(cageid, cwd.clone());
    cwd
}

/// Return the cage's tracked virtual cwd, defaulting to `/`.
pub fn get_cage_cwd(cageid: u64) -> String {
    crate::CAGE_CWDS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&cageid).cloned())
        .unwrap_or_else(|| "/".to_string())
}

/// Update the cage's tracked virtual cwd.
pub fn set_cage_cwd(cageid: u64, cwd: String) {
    if let Some(ref mut map) = *crate::CAGE_CWDS.lock().unwrap() {
        map.insert(cageid, cwd);
    }
}

/// Register a new cage by copying the parent's cwd.
pub fn register_cage(parent_cageid: u64, child_cageid: u64) {
    let parent_cwd = get_cage_cwd(parent_cageid);
    set_cage_cwd(child_cageid, parent_cwd);
}
