//! IMFS Grate — In-Memory Filesystem for Lind.
//!
//! This grate intercepts filesystem syscalls (open, close, read, write, lseek,
//! fcntl, unlink, pread, pwrite) and handles them with an in-memory filesystem.
//!
//! Usage: imfs-grate <cage_binary> [args...]
//!
//! Environment variables:
//!   PRELOADS — colon-separated list of host files to load into IMFS at startup.

mod handlers;
mod imfs;
mod logging;

use grate_rs::constants::fs::O_RDWR;
use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::ffi::stat;
use grate_rs::{GrateBuilder, GrateError, getcageid, make_threei_call};
use std::ffi::CString;

const SYS_LINKAT: u64 = 265;
const PRELOAD_READ_CHUNK_SIZE: usize = 4096;
const DUMP_WRITE_CHUNK_SIZE: usize = 1024;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

struct Config {
    argv: Vec<String>,
    log_enabled: bool,
}

fn parse_argv(args: Vec<String>) -> Config {
    let mut log_enabled = false;
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--log" {
            log_enabled = true;
            i += 1;
        } else {
            break;
        }
    }

    Config {
        argv: args[i..].to_vec(),
        log_enabled,
    }
}

fn main() {
    let config = parse_argv(std::env::args().skip(1).collect());
    logging::init(config.log_enabled);
    let dump_files = std::env::var("DUMPS").ok();

    // Initialize the in-memory filesystem.
    imfs::init();

    // Load files from the host filesystem into IMFS before cage execution.
    if let Ok(preloads) = std::env::var("PRELOADS") {
        load_preloads(&preloads);
    }

    imfs::with_imfs(|s| s.mkdir(0, "/tmp", 0755));

    // Build and run the grate. Registers handlers for all filesystem syscalls,
    // forks a child cage, and waits for it to exit.
    GrateBuilder::new()
        .register(SYS_OPEN, handlers::open_handler)
        .register(SYS_OPENAT, handlers::openat_handler)
        .register(SYS_GETCWD, handlers::getcwd_handler)
        .register(SYS_ACCESS, handlers::access_handler)
        .register(SYS_FACCESSAT, handlers::faccessat_handler)
        .register(SYS_CLOSE, handlers::close_handler)
        .register(SYS_DUP, handlers::dup_handler)
        .register(SYS_DUP2, handlers::dup2_handler)
        .register(SYS_DUP3, handlers::dup3_handler)
        .register(SYS_PIPE, handlers::enosys_handler)
        .register(SYS_PIPE2, handlers::enosys_handler)
        .register(SYS_READ, handlers::read_handler)
        .register(SYS_WRITE, handlers::write_handler)
        .register(SYS_LSEEK, handlers::lseek_handler)
        .register(SYS_FCNTL, handlers::fcntl_handler)
        .register(SYS_GETDENTS, handlers::getdents_handler)
        .register(SYS_UNLINK, handlers::unlink_handler)
        .register(SYS_UNLINKAT, handlers::unlinkat_handler)
        .register(SYS_LINK, handlers::link_handler)
        .register(SYS_LINKAT, handlers::linkat_handler)
        .register(SYS_RENAME, handlers::rename_handler)
        .register(SYS_RENAMEAT, handlers::renameat_handler)
        .register(SYS_RENAMEAT2, handlers::renameat2_handler)
        .register(SYS_MKNOD, handlers::mknod_handler)
        .register(SYS_SYMLINK, handlers::symlink_handler)
        .register(SYS_SYMLINKAT, handlers::symlinkat_handler)
        .register(SYS_READLINK, handlers::readlink_handler)
        .register(SYS_READLINKAT, handlers::readlinkat_handler)
        .register(SYS_PREAD, handlers::pread_handler)
        .register(SYS_PWRITE, handlers::pwrite_handler)
        .register(SYS_PREADV, handlers::preadv_handler)
        .register(SYS_PWRITEV, handlers::pwritev_handler)
        .register(SYS_MKDIR, handlers::mkdir_handler)
        .register(SYS_CLONE, handlers::fork_handler)
        .register(SYS_EXEC, handlers::exec_handler)
        .register(SYS_CHDIR, handlers::chdir_handler)
        .register(SYS_FXSTAT, handlers::fstat_handler)
        .register(SYS_XSTAT, handlers::stat_handler)
        .register(SYS_LSTAT, handlers::lstat_handler)
        .register(SYS_NEWFSTATAT, handlers::fstatat_handler)
        .register(SYS_STATX, handlers::enosys_handler)
        .register(SYS_RMDIR, handlers::rmdir_handler)
        .register(SYS_CHMOD, handlers::chmod_handler)
        .register(SYS_FCHMODAT, handlers::fchmodat_handler)
        .register(SYS_CHOWN, handlers::chown_handler)
        .register(SYS_LCHOWN, handlers::lchown_handler)
        .register(SYS_FCHOWNAT, handlers::fchownat_handler)
        .register(SYS_TRUNCATE, handlers::truncate_handler)
        .register(SYS_FTRUNCATE, handlers::ftruncate_handler)
        .register(SYS_FCHDIR, handlers::fchdir_handler)
        .register(SYS_FCHMOD, handlers::fchmod_handler)
        .register(SYS_READV, handlers::readv_handler)
        .register(SYS_WRITEV, handlers::writev_handler)
        .register(SYS_FSYNC, handlers::fsync_handler)
        .register(SYS_FDATASYNC, handlers::fsync_handler)
        .register(SYS_STATFS, handlers::statfs_handler)
        .register(SYS_FSTATFS, handlers::fstatfs_handler)
        .register(SYS_SYNC_FILE_RANGE, handlers::sync_file_range_handler)
        .register(SYS_UTIMENSAT, handlers::utimensat_handler)
        .preexec(|cageid: i32| {
            imfs::with_imfs(|s| {
                s.cwd_info.insert(cageid as u64, "/".to_string());
            });

            fdtables::init_empty_cage(cageid as u64);
            log!("init-ing {}", cageid);

            for fd in 0..3 {
                let _ = fdtables::get_specific_virtual_fd(
                    cageid as u64,
                    fd,
                    imfs::IMFS_FDKIND,
                    0,
                    false,
                    0,
                );

                imfs::with_imfs(|s| s.insert_perfdinfo(cageid as u64, fd, O_RDWR as u64));
            }
        })
        .teardown(move |result: Result<i32, GrateError>| {
            if let Some(dumps) = dump_files.as_deref() {
                dump_outputs(dumps);
            }
            log!("exited: {:?}", result);
        })
        .run(config.argv);
}

/// Load files from the host filesystem into IMFS.
///
/// The PRELOADS env var is a colon-separated list of paths.
/// Each file is read from the host and written into IMFS at the same path,
/// creating parent directories as needed.
fn load_preloads(preloads: &str) {
    // Preload/dump utilities use IMFS cage 0 because they run before any
    // application cage exists. Initialize its fd table once for all utility I/O.
    init_utility_cage();

    for path in preloads.split(':') {
        if path.is_empty() {
            continue;
        }

        log!("preloading: {}", path);

        if !preload_is_regular_file(path) {
            continue;
        }

        // Read the file from the host filesystem through 3i, bypassing IMFS.
        let data = match read_preload_file(path) {
            Ok(d) => d,
            Err(e) => {
                log!("failed to read {}: {}", path, e);
                continue;
            }
        };

        imfs::with_imfs(|state| {
            // Create parent directories.
            let mut dir_path = String::new();
            for component in path.split('/').filter(|s| !s.is_empty()) {
                dir_path.push('/');
                dir_path.push_str(component);

                // Try to create as directory — will fail silently if it exists or
                // if this is the final component (a file).
                if dir_path != path {
                    let _ = state.mkdir(0, &dir_path, 0o755);
                }
            }

            // Create and write the file.
            let fd = state.open(0, path, fs::O_CREAT | fs::O_WRONLY, 0o777);
            if fd >= 0 {
                state.write(0, fd as u64, &data);
                state.close(0, fd as u64);
            }
        });
    }
}

fn preload_is_regular_file(path: &str) -> bool {
    let c_path = match CString::new(path) {
        Ok(path) => path,
        Err(_) => return false,
    };

    // Match the C implementation: only regular files are staged into IMFS.
    // The pathname and stat buffer live in this grate's memory, so mark their
    // cage IDs with GRATE_MEMORY_FLAG before passing them through ThreeI.
    let this_cage = getcageid();
    let mut st = stat::default();
    let ret = raw_threei_syscall(
        SYS_STAT,
        [
            c_path.as_ptr() as u64,
            &mut st as *mut stat as u64,
            0,
            0,
            0,
            0,
        ],
        [
            this_cage | GRATE_MEMORY_FLAG,
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
        ],
    );

    ret >= 0 && (st.st_mode & S_IFMT) == S_IFREG
}

fn read_preload_file(path: &str) -> Result<Vec<u8>, String> {
    let c_path = CString::new(path).map_err(|_| "path contains interior NUL".to_string())?;
    let this_cage = getcageid();

    // Do not use std::fs here. In lind-wasm, Rust std metadata can report a
    // bogus huge file size and make std::fs::read try to allocate too much.
    // Use the underlying host syscalls via 3i, like the C grate does.
    let fd = raw_threei_syscall(
        SYS_OPEN,
        [c_path.as_ptr() as u64, fs::O_RDONLY as u64, 0, 0, 0, 0],
        [
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
        ],
    );
    if fd < 0 {
        return Err(format!("open failed: {}", fd));
    }

    let mut data = Vec::new();
    let mut buf = [0u8; PRELOAD_READ_CHUNK_SIZE];

    // Read in bounded chunks from the host, then write the complete contents
    // into the IMFS node after the host fd has been closed.
    loop {
        let nread = raw_threei_syscall(
            SYS_READ,
            [
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                0,
                0,
                0,
            ],
            [
                this_cage,
                this_cage | GRATE_MEMORY_FLAG,
                this_cage,
                this_cage,
                this_cage,
                this_cage,
            ],
        );

        if nread < 0 {
            let _ = raw_threei_syscall(
                SYS_CLOSE,
                [fd as u64, 0, 0, 0, 0, 0],
                [
                    this_cage, this_cage, this_cage, this_cage, this_cage, this_cage,
                ],
            );
            return Err(format!("read failed: {}", nread));
        }

        if nread == 0 {
            break;
        }

        data.extend_from_slice(&buf[..nread as usize]);
    }

    let close_ret = raw_threei_syscall(
        SYS_CLOSE,
        [fd as u64, 0, 0, 0, 0, 0],
        [
            this_cage, this_cage, this_cage, this_cage, this_cage, this_cage,
        ],
    );
    if close_ret < 0 {
        return Err(format!("close failed: {}", close_ret));
    }

    Ok(data)
}

fn dump_outputs(dumps: &str) {
    if dumps.is_empty() {
        return;
    }

    // DUMPS follows the C grate format:
    //   imfs_path=host_path;other_imfs_path=other_host_path
    // If '=' is omitted, the same path is used on both sides.
    init_utility_cage();

    for entry in dumps.split(';') {
        let entry = entry.trim_start_matches([' ', '\t']);
        if entry.is_empty() {
            continue;
        }

        let (imfs_path, actual_path) = match entry.split_once('=') {
            Some((imfs_path, actual_path)) => (imfs_path, actual_path),
            None => (entry, entry),
        };

        if imfs_path.is_empty() || actual_path.is_empty() {
            continue;
        }

        log!("dumping {} -> {}", imfs_path, actual_path);
        if let Err(e) = dump_file(imfs_path, actual_path) {
            log!("failed to dump {} -> {}: {}", imfs_path, actual_path, e);
        }
    }
}

fn init_utility_cage() {
    // fdtables panics if a cage is initialized twice, so preload and dump share
    // this guard instead of calling init_empty_cage(0) directly.
    if !fdtables::check_cage_exists(0) {
        fdtables::init_empty_cage(0);
    }
}

fn dump_file(imfs_path: &str, actual_path: &str) -> Result<(), String> {
    create_host_parent_dirs(actual_path)?;

    let c_actual_path =
        CString::new(actual_path).map_err(|_| "dump target contains interior NUL".to_string())?;
    let this_cage = getcageid();
    let host_fd = raw_threei_syscall(
        SYS_OPEN,
        [
            c_actual_path.as_ptr() as u64,
            (fs::O_CREAT | fs::O_WRONLY | fs::O_TRUNC) as u64,
            0o777,
            0,
            0,
            0,
        ],
        [
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
        ],
    );
    if host_fd < 0 {
        return Err(format!("host open failed: {}", host_fd));
    }

    // Read from IMFS with cage 0's fd table, and write each chunk back to the
    // host through ThreeI so teardown does not depend on Rust std filesystem I/O.
    let dump_result = imfs::with_imfs(|state| {
        let imfs_fd = state.open(0, imfs_path, fs::O_RDONLY, 0);
        if imfs_fd < 0 {
            return Err(format!("imfs open failed: {}", imfs_fd));
        }

        let mut buf = [0u8; DUMP_WRITE_CHUNK_SIZE];
        loop {
            let nread = state.read(0, imfs_fd as u64, &mut buf);
            if nread < 0 {
                let _ = state.close(0, imfs_fd as u64);
                return Err(format!("imfs read failed: {}", nread));
            }
            if nread == 0 {
                break;
            }

            write_host_all(host_fd, &buf[..nread as usize])?;
        }

        let close_ret = state.close(0, imfs_fd as u64);
        if close_ret < 0 {
            return Err(format!("imfs close failed: {}", close_ret));
        }

        Ok(())
    });

    let close_ret = raw_threei_syscall(
        SYS_CLOSE,
        [host_fd as u64, 0, 0, 0, 0, 0],
        [
            this_cage, this_cage, this_cage, this_cage, this_cage, this_cage,
        ],
    );
    if close_ret < 0 {
        return Err(format!("host close failed: {}", close_ret));
    }

    dump_result
}

fn create_host_parent_dirs(path: &str) -> Result<(), String> {
    // Mirror the C dump_file helper: mkdir each parent component before opening
    // the output file. Relative dump targets stay relative; absolute targets
    // are built from '/'.
    let mut components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if components.len() <= 1 {
        return Ok(());
    }

    components.pop();

    let mut dir_path = if path.starts_with('/') {
        "/".to_string()
    } else {
        String::new()
    };

    for component in components {
        if !dir_path.is_empty() && !dir_path.ends_with('/') {
            dir_path.push('/');
        }
        dir_path.push_str(component);
        mkdir_host(&dir_path)?;
    }

    Ok(())
}

fn mkdir_host(path: &str) -> Result<(), String> {
    let c_path = CString::new(path).map_err(|_| "mkdir path contains interior NUL".to_string())?;
    let this_cage = getcageid();
    // Ignore mkdir's return value like the C implementation. Existing parent
    // directories are expected and should not prevent the dump from continuing.
    let _ = raw_threei_syscall(
        SYS_MKDIR,
        [c_path.as_ptr() as u64, 0o755, 0, 0, 0, 0],
        [
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
            this_cage,
        ],
    );
    Ok(())
}

fn write_host_all(fd: i32, mut data: &[u8]) -> Result<(), String> {
    let this_cage = getcageid();
    while !data.is_empty() {
        // Host writes may legally be partial; keep advancing until the whole
        // IMFS chunk has been persisted or an error is reported.
        let nwritten = raw_threei_syscall(
            SYS_WRITE,
            [fd as u64, data.as_ptr() as u64, data.len() as u64, 0, 0, 0],
            [
                this_cage,
                this_cage | GRATE_MEMORY_FLAG,
                this_cage,
                this_cage,
                this_cage,
                this_cage,
            ],
        );

        if nwritten < 0 {
            return Err(format!("host write failed: {}", nwritten));
        }
        if nwritten == 0 {
            return Err("host write made no progress".to_string());
        }

        data = &data[nwritten as usize..];
    }

    Ok(())
}

fn raw_threei_syscall(syscall: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let this_cage = getcageid();
    // Utility syscalls target the current grate cage rather than an application
    // cage. Pointer arguments that refer to grate-owned buffers must already
    // carry GRATE_MEMORY_FLAG in arg_cages.
    match make_threei_call(
        syscall as u32,
        0,
        this_cage,
        this_cage,
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
        Err(GrateError::MakeSyscallError(ret)) => ret,
        Err(_) => -1,
    }
}
