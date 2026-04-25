//! fs-view-grate: per-cage filesystem views.
//!
//! Intercepts path-based syscalls and prefixes every path with /cage-<id>/,
//! giving each cage its own isolated filesystem namespace. When composed
//! with imfs-grate, each cage gets an independent in-memory filesystem.
//!
//! Usage: fs-view-grate <program> [args...]

use grate_rs::constants::*;
use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::{GrateBuilder, GrateError, copy_data_between_cages, getcageid, make_threei_call};

use std::ffi::CString;

const MAX_PATH: usize = 4096;

/// Read a NUL-terminated path from cage memory.
fn read_path(ptr: u64, cage: u64) -> Option<String> {
    let grate = getcageid();
    let mut buf = vec![0u8; MAX_PATH];
    copy_data_between_cages(
        grate, cage, ptr, cage,
        buf.as_mut_ptr() as u64, grate,
        MAX_PATH as u64, 0,
    ).ok()?;
    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH);
    Some(String::from_utf8_lossy(&buf[..len]).to_string())
}

/// Rewrite a path by prefixing with /cage-<id>.
fn cage_path(path: &str, cage_id: u64) -> String {
    format!("/cage-{}{}", cage_id, if path.starts_with('/') { path.to_string() } else { format!("/{}", path) })
}

/// Forward a syscall, rewriting arg at `path_idx` with the cage-prefixed path.
fn forward_with_rewrite(
    nr: u64, cage_id: u64,
    args: &[u64; 6], arg_cages: &[u64; 6],
    path_idx: usize, new_path: &CString,
) -> i32 {
    let grate = getcageid();
    let mut a = *args;
    let mut c = *arg_cages;
    a[path_idx] = new_path.as_ptr() as u64;
    c[path_idx] = grate | GRATE_MEMORY_FLAG;

    match make_threei_call(
        nr as u32, 0, grate, cage_id,
        a[0], c[0], a[1], c[1], a[2], c[2],
        a[3], c[3], a[4], c[4], a[5], c[5], 0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

/// Forward a syscall without rewriting.
fn forward(nr: u64, cage_id: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let grate = getcageid();
    match make_threei_call(
        nr as u32, 0, grate, cage_id,
        args[0], arg_cages[0], args[1], arg_cages[1], args[2], arg_cages[2],
        args[3], arg_cages[3], args[4], arg_cages[4], args[5], arg_cages[5], 0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

/// Ensure the per-cage root directory exists (e.g. /cage-3).
fn ensure_cage_root(cage_id: u64) {
    let root = format!("/cage-{}", cage_id);
    let c_root = CString::new(root).unwrap();
    let grate = getcageid();
    let ptr = c_root.as_ptr() as u64;
    // mkdir with 0755 — ignore errors (already exists is fine)
    let _ = make_threei_call(
        SYS_MKDIR as u32, 0, grate, cage_id,
        ptr, grate | GRATE_MEMORY_FLAG,
        0o755, cage_id,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    );
}

// Generate a handler that rewrites the path at a given arg index.
macro_rules! path_rewrite_handler {
    ($name:ident, $sysno:expr, $path_idx:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
            let cage_id = arg_cages[$path_idx];

            let ptr = args[$path_idx];
            let cage = arg_cages[$path_idx];

            let path = match read_path(ptr, cage) {
                Some(p) => p,
                None => return -14, // EFAULT
            };

            let rewritten = cage_path(&path, cage_id);
            let c_path = match CString::new(rewritten) {
                Ok(p) => p,
                Err(_) => return -1,
            };

            ensure_cage_root(cage_id);
            forward_with_rewrite($sysno, cage_id, &args, &arg_cages, $path_idx, &c_path)
        }
    };
}

// Two-path handler (e.g. rename, link)
macro_rules! two_path_rewrite_handler {
    ($name:ident, $sysno:expr, $idx1:expr, $idx2:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
            let cage_id = arg_cages[$idx1];

            let path1 = match read_path(args[$idx1], arg_cages[$idx1]) {
                Some(p) => p,
                None => return -14,
            };
            let path2 = match read_path(args[$idx2], arg_cages[$idx2]) {
                Some(p) => p,
                None => return -14,
            };

            let grate = getcageid();
            let c1 = match CString::new(cage_path(&path1, cage_id)) {
                Ok(p) => p,
                Err(_) => return -1,
            };
            let c2 = match CString::new(cage_path(&path2, cage_id)) {
                Ok(p) => p,
                Err(_) => return -1,
            };

            let mut a = args;
            let mut c = arg_cages;
            a[$idx1] = c1.as_ptr() as u64;
            c[$idx1] = grate | GRATE_MEMORY_FLAG;
            a[$idx2] = c2.as_ptr() as u64;
            c[$idx2] = grate | GRATE_MEMORY_FLAG;

            ensure_cage_root(cage_id);

            match make_threei_call(
                $sysno as u32, 0, grate, cage_id,
                a[0], c[0], a[1], c[1], a[2], c[2],
                a[3], c[3], a[4], c[4], a[5], c[5], 0,
            ) {
                Ok(r) => r,
                Err(_) => -1,
            }
        }
    };
}

path_rewrite_handler!(open_handler, SYS_OPEN, 0);
path_rewrite_handler!(stat_handler, SYS_XSTAT, 0);
path_rewrite_handler!(access_handler, SYS_ACCESS, 0);
path_rewrite_handler!(mkdir_handler, SYS_MKDIR, 0);
path_rewrite_handler!(rmdir_handler, SYS_RMDIR, 0);
path_rewrite_handler!(unlink_handler, SYS_UNLINK, 0);
path_rewrite_handler!(unlinkat_handler, SYS_UNLINKAT, 1);
path_rewrite_handler!(chmod_handler, SYS_CHMOD, 0);
path_rewrite_handler!(truncate_handler, SYS_TRUNCATE, 0);
path_rewrite_handler!(chdir_handler, SYS_CHDIR, 0);
path_rewrite_handler!(readlink_handler, SYS_READLINK, 0);

two_path_rewrite_handler!(rename_handler, SYS_RENAME, 0, 1);
two_path_rewrite_handler!(link_handler, SYS_LINK, 0, 1);

pub extern "C" fn fork_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    forward(SYS_CLONE, arg1cage, &args, &arg_cages)
}

pub extern "C" fn exec_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
    forward(SYS_EXEC, arg1cage, &args, &arg_cages)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    GrateBuilder::new()
        .register(SYS_OPEN, open_handler)
        .register(SYS_XSTAT, stat_handler)
        .register(SYS_ACCESS, access_handler)
        .register(SYS_MKDIR, mkdir_handler)
        .register(SYS_RMDIR, rmdir_handler)
        .register(SYS_UNLINK, unlink_handler)
        .register(SYS_UNLINKAT, unlinkat_handler)
        .register(SYS_CHMOD, chmod_handler)
        .register(SYS_TRUNCATE, truncate_handler)
        .register(SYS_CHDIR, chdir_handler)
        .register(SYS_READLINK, readlink_handler)
        .register(SYS_RENAME, rename_handler)
        .register(SYS_LINK, link_handler)
        .register(SYS_CLONE, fork_handler)
        .register(SYS_EXEC, exec_handler)
        .teardown(|result: Result<i32, GrateError>| {
            if let Err(e) = result {
                eprintln!("[fs-view] error: {:?}", e);
            }
        })
        .run(argv);
}
