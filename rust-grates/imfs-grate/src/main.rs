//! IMFS Grate — In-Memory Filesystem for Lind.
//!
//! This grate intercepts filesystem syscalls (open, close, read, write, lseek,
//! fcntl, unlink, pread, pwrite) and handles them with an in-memory filesystem.
//!
//! Usage: imfs-grate [--log] [--preload-file <path> [--preload-digest <hex>]] <cage_binary> [args...]
//!
//! Preloading always goes through a *preload archive*: one contiguous block
//! of memory holding every file to stage (see the `preload-archive` crate).
//! IMFS is handed that block as a `(pointer, size)` pair and builds its nodes
//! from the bytes (see `imfs::preload`). The archive can come from:
//!
//!   --preload-file <path> — an archive built ahead of time by the native
//!     `tools/mkpreload` program, placed where the runtime can see it
//!     (typically a tmpfs path under lindfs such as /dev/shm/...). It is read
//!     into this cage's memory in one go, verified, and then staged. The blob
//!     was built outside this cage, so it is treated as untrusted input: it is
//!     size-capped and its digest is checked, and with --preload-digest it
//!     must be exactly the blob whose SHA-256 (as printed by mkpreload) is
//!     given.
//!   PRELOADS — colon-separated list of host files. Each entry is a path, or
//!     `imfs_path=host_path` to load into a different IMFS path. This grate
//!     reads them into an archive itself, then stages it the same way.
//!
//! Environment variables:
//!   PRELOADS — see above.
//!   DUMPS — semicolon-separated list of IMFS files to write back to the host
//!     at teardown.

mod handlers;
mod imfs;
mod logging;

use grate_rs::constants::fs::O_RDWR;
use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::{GrateBuilder, GrateError, getcageid};
use preload_archive::host::raw_threei_syscall;
use preload_archive::{ArchiveDigest, parse_digest_hex};
use std::ffi::CString;

const SYS_LINKAT: u64 = 265;
/// Permission bits given to every file preloaded from PRELOADS.
const PRELOAD_FILE_MODE: u32 = 0o777;
/// Largest --preload-file archive accepted. The archive and the IMFS chunks
/// built from it coexist in this cage's linear memory during staging.
const PRELOAD_MAX_ARCHIVE_BYTES: usize = 48 << 20;
const DUMP_WRITE_CHUNK_SIZE: usize = 1024;

struct Config {
    argv: Vec<String>,
    log_enabled: bool,
    /// Prebuilt archive to stage, from `--preload-file`.
    preload_file: Option<String>,
    /// SHA-256 the prebuilt archive must have, from `--preload-digest`.
    preload_digest: Option<ArchiveDigest>,
}

/// Split the grate's own options from the cage command line. Options are
/// accepted in any order; the first argument that is not one of them starts
/// the cage binary and its args.
fn parse_argv(args: Vec<String>) -> Result<Config, String> {
    let mut log_enabled = false;
    let mut preload_file = None;
    let mut preload_digest = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--log" => {
                log_enabled = true;
                i += 1;
            }
            "--preload-file" => {
                let value = args.get(i + 1).ok_or("--preload-file needs a path")?;
                if value.is_empty() {
                    return Err("--preload-file needs a path".to_string());
                }
                preload_file = Some(value.clone());
                i += 2;
            }
            "--preload-digest" => {
                let value = args
                    .get(i + 1)
                    .ok_or("--preload-digest needs a 64-character hex SHA-256")?;
                preload_digest = Some(
                    parse_digest_hex(value)
                        .ok_or_else(|| format!("invalid --preload-digest value: {}", value))?,
                );
                i += 2;
            }
            _ => break,
        }
    }

    if preload_digest.is_some() && preload_file.is_none() {
        return Err("--preload-digest needs --preload-file".to_string());
    }

    Ok(Config {
        argv: args[i..].to_vec(),
        log_enabled,
        preload_file,
        preload_digest,
    })
}

fn main() {
    let config = match parse_argv(std::env::args().skip(1).collect()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("imfs-grate: {}", e);
            std::process::exit(1);
        }
    };
    logging::init(config.log_enabled);
    let dump_files = std::env::var("DUMPS").ok();

    // Initialize the in-memory filesystem.
    imfs::init();

    // Stage files into IMFS before cage execution: first a prebuilt archive,
    // then anything listed in PRELOADS on top.
    if let Some(path) = config.preload_file.as_deref() {
        preload_from_file(path, config.preload_digest.as_ref());
    }
    if let Ok(preloads) = std::env::var("PRELOADS") {
        preload_from_list(&preloads);
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

/// Stage an archive that was built ahead of time (by `tools/mkpreload`) and
/// placed at `path`. The whole archive is read into this cage's memory with
/// one open/read/close sequence and verified there, then IMFS stages the
/// files out of that buffer; no other host access happens.
fn preload_from_file(path: &str, expected: Option<&ArchiveDigest>) {
    log!("preload: reading archive {}", path);

    if !preload_archive::host::is_regular_file(path) {
        log!("preload: {} is not a regular file", path);
        return;
    }

    let archive = match preload_archive::host::read_file(path) {
        Ok(archive) => archive,
        Err(e) => {
            log!("preload: cannot read {}: {}", path, e);
            return;
        }
    };

    // The blob was produced outside this cage: cap it, check its digest, and
    // insist on the expected digest if one was given, before staging.
    let result = imfs::with_imfs(|state| {
        state.preload_archive_verified(&archive, PRELOAD_MAX_ARCHIVE_BYTES, expected)
    });
    report_preload(archive.len(), result);
}

/// Stage the PRELOADS list: read each host file through 3i into one archive
/// buffer, then stage that buffer exactly like one received from another cage.
fn preload_from_list(preloads: &str) {
    let report = preload_archive::host::build_archive(preloads, PRELOAD_FILE_MODE);
    for line in &report.staged {
        log!("preloading: {}", line);
    }
    for line in &report.skipped {
        log!("preload: skipping {}", line);
    }

    if let Some(archive) = report.archive {
        stage_archive(&archive);
    }
}

/// Hand an archive this cage built itself to IMFS as a `(pointer, size)` pair.
fn stage_archive(archive: &[u8]) {
    // SAFETY: `archive` is a live slice for the whole call, so the pointer is
    // valid for `archive.len()` bytes.
    let result = unsafe { imfs::preload_from_ptr(archive.as_ptr(), archive.len()) };
    report_preload(archive.len(), result);
}

fn report_preload(
    archive_len: usize,
    result: Result<imfs::preload::PreloadStats, preload_archive::ArchiveError>,
) {
    match result {
        Ok(stats) => log!(
            "preloaded {} files ({} bytes) from a {} byte archive, skipped {}",
            stats.staged,
            stats.bytes,
            archive_len,
            stats.skipped
        ),
        Err(e) => log!("preload failed: {}", e),
    }
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

#[cfg(test)]
mod tests {
    use super::parse_argv;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_are_split_from_the_cage_command_line() {
        let config = parse_argv(args(&["--log", "prog.cwasm", "--log"])).unwrap();
        assert!(config.log_enabled);
        assert_eq!(config.preload_file, None);
        assert_eq!(config.argv, args(&["prog.cwasm", "--log"]));
    }

    #[test]
    fn preload_file_is_parsed_in_any_order_with_log() {
        let config =
            parse_argv(args(&["--preload-file", "/dev/shm/p.mem", "--log", "prog"])).unwrap();
        assert_eq!(config.preload_file.as_deref(), Some("/dev/shm/p.mem"));
        assert!(config.log_enabled);
        assert_eq!(config.argv, args(&["prog"]));

        let config =
            parse_argv(args(&["--log", "--preload-file", "/dev/shm/p.mem", "prog"])).unwrap();
        assert_eq!(config.preload_file.as_deref(), Some("/dev/shm/p.mem"));
        assert_eq!(config.argv, args(&["prog"]));
    }

    #[test]
    fn missing_preload_file_value_is_an_error() {
        assert!(parse_argv(args(&["--preload-file"])).is_err());
        assert!(parse_argv(args(&["--preload-file", "", "prog"])).is_err());
    }

    #[test]
    fn preload_digest_is_parsed_and_needs_preload_file() {
        let hex = "0123456789abcdef".repeat(4);
        let config = parse_argv(args(&[
            "--preload-digest",
            &hex,
            "--preload-file",
            "p.mem",
            "prog",
        ]))
        .unwrap();
        let digest = config.preload_digest.unwrap();
        assert_eq!(digest[0], 0x01);
        assert_eq!(digest[31], 0xef);
        assert_eq!(config.argv, args(&["prog"]));

        assert!(parse_argv(args(&["--preload-digest", &hex, "prog"])).is_err());
        assert!(
            parse_argv(args(&[
                "--preload-file",
                "p",
                "--preload-digest",
                "zz",
                "prog"
            ]))
            .is_err()
        );
        assert!(parse_argv(args(&["--preload-file", "p", "--preload-digest"])).is_err());
    }
}
