//! A minimal "private /tmp" grate.
//!
//! This grate rewrites any path under `/tmp` to a per-cage directory:
//! `/tmp/<...>` -> `/tmp/cage-<cageid>/<...>`.
//!
//! Notes:
//! - This is a best-effort path rewrite. Relative paths are resolved against the
//!   grate process's current working directory, which may diverge from the cage
//!   if the cage calls `chdir`.

use grate_rs::constants;
use grate_rs::{
    GrateBuilder, GrateError, copy_data_between_cages, getcageid, lind_get_base, make_threei_call,
};

use std::ffi::CString;
use std::path::{Component, Path, PathBuf};

fn get_cwd() -> PathBuf {
    let mut buf = vec![0u8; 4096];
    let ptr = unsafe { libc::getcwd(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
    assert!(!ptr.is_null(), "getcwd failed");

    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    PathBuf::from(std::str::from_utf8(&buf[..len]).expect("cwd is not utf8"))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if matches!(components.last(), Some(Component::Normal(_))) {
                    components.pop();
                }
            }
            Component::CurDir => {}
            c => components.push(c),
        }
    }
    components.iter().collect()
}

fn transform_path(open_path: &str, cageid: u64) -> PathBuf {
    let raw = if Path::new(open_path).is_absolute() {
        PathBuf::from(open_path)
    } else {
        get_cwd().join(open_path)
    };

    let resolved = normalize_path(&raw);

    if let Ok(suffix) = resolved.strip_prefix("/tmp") {
        PathBuf::from(format!("/tmp/cage-{}", cageid)).join(suffix)
    } else {
        resolved
    }
}

fn ensure_private_tmp_dir(cageid: u64) {
    let base = format!("/tmp/cage-{}", cageid);
    let c_base = CString::new(base).expect("CString failed");

    let ret = unsafe { libc::mkdir(c_base.as_ptr(), 0o755) };
    if ret == 0 {
        return;
    }

    let errno = unsafe { *libc::__errno_location() };
    if errno == 17 {
        return;
    }
    //    eprintln!("[private-tmp] mkdir failed: errno={}", errno);
}

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
        1, // bounded string copy
    ) {
        Ok(_) => {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..len]).to_string())
        }
        Err(_) => None,
    }
}

fn call_with_rewrites(
    syscall_no: u32,
    cageid: u64,
    thiscage: u64,
    mut args: [u64; 6],
    mut arg_cages: [u64; 6],
    rewrites: &[(usize, CString)],
) -> i32 {
    for (idx, cstr) in rewrites {
        if *idx >= 6 {
            return -(libc::EINVAL as i32);
        }
        args[*idx] = cstr.as_ptr() as u64 + lind_get_base();
        arg_cages[*idx] = thiscage;
    }

    match make_threei_call(
        syscall_no,
        0,
        thiscage, // self cage (grate)
        cageid,   // execute as-if from cageid
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

macro_rules! one_path_handler {
    ($name:ident, $syscall_const:expr, $path_idx:expr) => {
        extern "C" fn $name(
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
            let thiscage = getcageid();
            ensure_private_tmp_dir(cageid);

            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            let path_ptr = args[$path_idx];
            let path_cage = cages[$path_idx];

            let path = match read_path_from_cage(path_ptr, path_cage) {
                Some(p) => p,
                None => return -(libc::EFAULT as i32),
            };

            let transformed = transform_path(&path, cageid);
            let c_path = match CString::new(transformed.to_string_lossy().as_bytes()) {
                Ok(p) => p,
                Err(_) => return -(libc::EINVAL as i32),
            };

            // println!("{:#?} => {:#?}", path, c_path);

            call_with_rewrites(
                $syscall_const as u32,
                arg1cage,
                thiscage,
                args,
                cages,
                &[(($path_idx as usize), c_path)],
            )
        }
    };
}

macro_rules! two_path_handler {
    ($name:ident, $syscall_const:expr, $path1_idx:expr, $path2_idx:expr) => {
        extern "C" fn $name(
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
            let thiscage = getcageid();
            ensure_private_tmp_dir(cageid);

            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            let path1_ptr = args[$path1_idx];
            let path1_cage = cages[$path1_idx];
            let path2_ptr = args[$path2_idx];
            let path2_cage = cages[$path2_idx];

            let path1 = match read_path_from_cage(path1_ptr, path1_cage) {
                Some(p) => p,
                None => return -(libc::EFAULT as i32),
            };
            let path2 = match read_path_from_cage(path2_ptr, path2_cage) {
                Some(p) => p,
                None => return -(libc::EFAULT as i32),
            };

            let t1 = transform_path(&path1, cageid);
            let t2 = transform_path(&path2, cageid);

            let c1 = match CString::new(t1.to_string_lossy().as_bytes()) {
                Ok(p) => p,
                Err(_) => return -(libc::EINVAL as i32),
            };
            let c2 = match CString::new(t2.to_string_lossy().as_bytes()) {
                Ok(p) => p,
                Err(_) => return -(libc::EINVAL as i32),
            };

            call_with_rewrites(
                $syscall_const as u32,
                cageid,
                thiscage,
                args,
                cages,
                &[(($path1_idx as usize), c1), (($path2_idx as usize), c2)],
            )
        }
    };
}

macro_rules! passthrough_handler {
    ($name:ident, $syscall_const:expr) => {
        extern "C" fn $name(
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
            let thiscage = getcageid();
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];
            call_with_rewrites($syscall_const as u32, cageid, thiscage, args, cages, &[])
        }
    };
}

one_path_handler!(open_handler, constants::SYS_OPEN, 0);
one_path_handler!(access_handler, constants::SYS_ACCESS, 0);
one_path_handler!(chmod_handler, constants::SYS_CHMOD, 0);
one_path_handler!(unlink_handler, constants::SYS_UNLINK, 0);
one_path_handler!(rmdir_handler, constants::SYS_RMDIR, 0);
one_path_handler!(mkdir_handler, constants::SYS_MKDIR, 0);
one_path_handler!(readlink_handler, constants::SYS_READLINK, 0);
one_path_handler!(truncate_handler, constants::SYS_TRUNCATE, 0);

// Linux __xstat-style calls are typically `(ver, path, buf)`; rewrite arg2 (index 1).
one_path_handler!(xstat_handler, constants::SYS_XSTAT, 1);

two_path_handler!(rename_handler, constants::SYS_RENAME, 0, 1);
two_path_handler!(link_handler, constants::SYS_LINK, 0, 1);

passthrough_handler!(getcwd_handler, constants::SYS_GETCWD);
passthrough_handler!(ftruncate_handler, constants::SYS_FTRUNCATE);

fn main() {
    let builder = GrateBuilder::new()
        // File creation / open / read metadata
        .register(constants::SYS_OPEN, open_handler)
        .register(constants::SYS_XSTAT, xstat_handler)
        .register(constants::SYS_ACCESS, access_handler)
        .register(constants::SYS_CHMOD, chmod_handler)
        // File removal / renaming
        .register(constants::SYS_UNLINK, unlink_handler)
        .register(constants::SYS_RENAME, rename_handler)
        .register(constants::SYS_RMDIR, rmdir_handler)
        // Directory operations
        .register(constants::SYS_MKDIR, mkdir_handler)
        .register(constants::SYS_LINK, link_handler)
        .register(constants::SYS_READLINK, readlink_handler)
        .register(constants::SYS_GETCWD, getcwd_handler)
        // Timestamps / truncation
        .register(constants::SYS_TRUNCATE, truncate_handler)
        .register(constants::SYS_FTRUNCATE, ftruncate_handler)
        .teardown(|result: Result<i32, GrateError>| {
            println!("Result: {:#?}", result);
        });

    let argv = std::env::args().skip(1).collect::<Vec<_>>();
    builder.run(argv);
}

