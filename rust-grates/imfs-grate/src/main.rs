//! IMFS Grate — In-Memory Filesystem for Lind.
//!
//! This grate intercepts filesystem syscalls (open, close, read, write, lseek,
//! fcntl, unlink, pread, pwrite) and handles them with an in-memory filesystem.
//!
//! Usage: imfs-grate [--log] [--preload-file <path> [--preload-digest <hex>]]
//!                   [--preload-shm [--attest [--attest-steps <a,b,...>]]] [--dump-shm]
//!                   <cage_binary> [args...]
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
//!   --preload-shm — a *bundle* of archives (archives back to back, built by
//!     `mkpreload ... --section ...`) that the runtime mapped before any cage
//!     started (lind-boot `--preload-shm`, or a TriSeal keep's `[shm]`
//!     config). The whole bundle is copied into this cage's memory in one
//!     call (the runtime does the copy, so inside an enclave it never leaves
//!     it), and its archives are verified and staged from that copy one at a
//!     time. With `--attest`, IMFS stops after each archive and asks the
//!     in-toto grate running it to sign a statement over the archive's files
//!     (see `preload_archive::attest`); the DSSE envelopes and the signer's
//!     public key are kept in /attest. The archives are named after
//!     `--attest-steps` (default `pipeline,sources`: the compiler pipeline,
//!     then the source files).
//!   PRELOADS — colon-separated list of host files. Each entry is a path, or
//!     `imfs_path=host_path` to load into a different IMFS path. This grate
//!     reads them into an archive itself, then stages it the same way.
//!
//! Environment variables:
//!   PRELOADS — see above.
//!   DUMPS — semicolon-separated list of IMFS files to write back to the host
//!     at teardown. With `--dump-shm` they (and the /attest files) are packed
//!     into one archive and handed to the runtime's dump region in a single
//!     call instead; `mkpreload unpack` writes them out on the host.

mod cageid;
mod handlers;
mod imfs;
mod logging;

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use cageid::getcageid;
use grate_rs::{GrateBuilder, GrateError};
use preload_archive::attest::{MAX_STEP_NAME, OP_ATTEST, OP_PUBLIC_KEY, SYS_INTOTO_ATTEST};
use preload_archive::host::raw_threei_syscall;
use preload_archive::{ArchiveBuilder, ArchiveDigest, bundle_archives, parse_digest_hex};
use std::ffi::CString;

const SYS_LINKAT: u64 = 265;
/// Permission bits given to every file preloaded from PRELOADS.
const PRELOAD_FILE_MODE: u32 = 0o777;
/// Largest --preload-file archive accepted. The archive and the IMFS chunks
/// built from it coexist in this cage's linear memory during staging.
const PRELOAD_MAX_ARCHIVE_BYTES: usize = 48 << 20;
const DUMP_WRITE_CHUNK_SIZE: usize = 1024;
/// IMFS directory holding the attestations made during --preload-shm.
const ATTEST_DIR: &str = "/attest";
/// Room for one DSSE envelope (or the public key) from the in-toto grate.
const ATTEST_OUT_CAPACITY: usize = 4 << 20;
const DEFAULT_ATTEST_STEPS: &[&str] = &["pipeline", "sources"];

struct Config {
    argv: Vec<String>,
    log_enabled: bool,
    /// Prebuilt archive to stage, from `--preload-file`.
    preload_file: Option<String>,
    /// SHA-256 the prebuilt archive must have, from `--preload-digest`.
    preload_digest: Option<ArchiveDigest>,
    /// Stage the bundle in the runtime's preload region, from `--preload-shm`.
    preload_shm: bool,
    /// Have each archive of the bundle attested, from `--attest`.
    attest: bool,
    /// Names of the archives of the bundle, from `--attest-steps`.
    attest_steps: Vec<String>,
    /// Hand DUMPS to the runtime's dump region, from `--dump-shm`.
    dump_shm: bool,
}

/// Split the grate's own options from the cage command line. Options are
/// accepted in any order; the first argument that is not one of them starts
/// the cage binary and its args.
fn parse_argv(args: Vec<String>) -> Result<Config, String> {
    let mut log_enabled = false;
    let mut preload_file = None;
    let mut preload_digest = None;
    let mut preload_shm = false;
    let mut attest = false;
    let mut attest_steps: Vec<String> =
        DEFAULT_ATTEST_STEPS.iter().map(|s| s.to_string()).collect();
    let mut dump_shm = false;
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
            "--preload-shm" => {
                preload_shm = true;
                i += 1;
            }
            "--attest" => {
                attest = true;
                i += 1;
            }
            "--attest-steps" => {
                let value = args
                    .get(i + 1)
                    .ok_or("--attest-steps needs a comma-separated list of names")?;
                attest_steps = value.split(',').map(str::to_string).collect();
                if attest_steps.iter().any(|s| !valid_step_name(s)) {
                    return Err(format!("invalid --attest-steps value: {}", value));
                }
                i += 2;
            }
            "--dump-shm" => {
                dump_shm = true;
                i += 1;
            }
            _ => break,
        }
    }

    if preload_digest.is_some() && preload_file.is_none() {
        return Err("--preload-digest needs --preload-file".to_string());
    }
    if attest && !preload_shm {
        return Err("--attest needs --preload-shm".to_string());
    }

    Ok(Config {
        argv: args[i..].to_vec(),
        log_enabled,
        preload_file,
        preload_digest,
        preload_shm,
        attest,
        attest_steps,
        dump_shm,
    })
}

/// Step names end up in IMFS file names and the signed statement.
fn valid_step_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < MAX_STEP_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
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
    let mut attested = Vec::new();
    if config.preload_shm {
        attested = preload_from_shm(&config);
    }
    if let Ok(preloads) = std::env::var("PRELOADS") {
        preload_from_list(&preloads);
    }

    imfs::with_imfs(|s| s.mkdir(0, "/tmp", 0o755));

    // Staging is over and the program starts: mark it for the runtime,
    // which can count what the run asks of the host from here.
    if let Err(e) = preload_archive::shm::phase(preload_archive::shm::PHASE_RUN) {
        log!("phase mark not supported by the runtime ({})", e);
    }

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

            // fds 0..3 are the cage's inherited host streams. Reads and writes on them
            // (or on any fd dup'd from them) are forwarded to the host by the handlers.
            for fd in 0..3 {
                imfs::with_imfs(|s| s.register_host_std(cageid as u64, fd));
            }
        })
        .teardown(move |result: Result<i32, GrateError>| {
            if config.dump_shm {
                dump_to_shm(dump_files.as_deref().unwrap_or(""), &attested);
            } else if let Some(dumps) = dump_files.as_deref() {
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

fn fatal(msg: &str) -> ! {
    eprintln!("imfs-grate: {}", msg);
    std::process::exit(1);
}

/// Stage the bundle in the runtime's preload region. The whole region is
/// copied into this cage's memory with one call before anything looks at it;
/// from then on the host has no part in staging, and cannot change what is
/// checked. The copy is split into its archives, and each is verified and
/// staged in turn; with `--attest`, IMFS stops after each archive and the
/// in-toto grate signs a statement over its files (read from the same copy)
/// before the next one is staged. A region, archive or attestation that fails
/// stops the grate: nothing runs on a partly staged or unattested tree.
/// Returns the IMFS paths of the attestation files written.
fn preload_from_shm(config: &Config) -> Vec<String> {
    let info = preload_archive::shm::info()
        .unwrap_or_else(|e| fatal(&format!("--preload-shm: no shared-memory region ({})", e)));
    if info.preload_len == 0 {
        fatal("--preload-shm: the runtime has no preload region");
    }
    let total = usize::try_from(info.preload_len).unwrap_or_else(|_| {
        fatal(&format!(
            "--preload-shm: the {} byte bundle does not fit in memory",
            info.preload_len
        ))
    });

    // Load: the one copy out of shared memory.
    log!(
        "preload: copying the {} byte bundle out of shared memory",
        total
    );
    let mut bundle = vec![0u8; total];
    preload_archive::shm::read(0, &mut bundle)
        .unwrap_or_else(|e| fatal(&format!("preload: cannot copy the bundle ({})", e)));
    let archives =
        bundle_archives(&bundle).unwrap_or_else(|e| fatal(&format!("preload: bad bundle: {}", e)));
    // The files take about as much room as the bundle: make it at once.
    imfs::with_imfs(|state| state.reserve_chunks(total));

    let mut attested = Vec::new();
    if config.attest {
        let key = request_attestation(OP_PUBLIC_KEY, &[], "")
            .unwrap_or_else(|e| fatal(&format!("cannot get the signer's public key: {}", e)));
        attested.push(stage_attest_file("signer.pub.json", &key));
    }

    for (i, archive) in archives.into_iter().enumerate() {
        let index = i + 1;
        let step = config
            .attest_steps
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("archive-{}", index));

        let result =
            imfs::with_imfs(|state| state.preload_archive_verified(archive, archive.len(), None));
        if let Err(e) = &result {
            fatal(&format!("preload: archive {} ({}): {}", index, step, e));
        }
        report_preload(archive.len(), result);

        // Stop: have what was just staged attested before going on.
        if config.attest {
            log!(
                "preload: stop after archive {} ({}), requesting attestation",
                index,
                step
            );
            let envelope = request_attestation(OP_ATTEST, archive, &step)
                .unwrap_or_else(|e| fatal(&format!("attestation of {} failed: {}", step, e)));
            attested.push(stage_attest_file(
                &format!("{}-{}.intoto.json", index, step),
                &envelope,
            ));
        }
    }
    attested
}

/// Ask the in-toto grate running this grate for an attestation of `archive`
/// (or for its public key). The request goes out as a syscall on this cage,
/// which 3i routes to the in-toto grate's handler.
fn request_attestation(op: u64, archive: &[u8], step: &str) -> Result<Vec<u8>, String> {
    let name = CString::new(step).map_err(|_| "step name contains NUL".to_string())?;
    let mut out = vec![0u8; ATTEST_OUT_CAPACITY];
    let this_cage = getcageid();
    let ret = raw_threei_syscall(
        SYS_INTOTO_ATTEST,
        [
            op,
            archive.as_ptr() as u64,
            archive.len() as u64,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            name.as_ptr() as u64,
        ],
        [
            this_cage,
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage | GRATE_MEMORY_FLAG,
            this_cage,
            this_cage | GRATE_MEMORY_FLAG,
        ],
    );
    if ret < 0 {
        return Err(format!(
            "error {} (is imfs-grate running under the in-toto grate?)",
            ret
        ));
    }
    out.truncate(ret as usize);
    Ok(out)
}

/// Keep an attestation file in IMFS under /attest. Returns its IMFS path.
fn stage_attest_file(name: &str, bytes: &[u8]) -> String {
    let path = format!("{}/{}", ATTEST_DIR, name);
    let mut builder = ArchiveBuilder::new();
    builder.push(&path, 0o444, bytes);
    stage_archive(&builder.finish());
    log!("attest: wrote {} ({} bytes)", path, bytes.len());
    path
}

/// Pack the DUMPS files and the attestation files into one archive and hand
/// it to the runtime's dump region in a single call. Each DUMPS file is
/// stored under its host path with mode 777 (what the per-file dump creates
/// it with); the attestation files under `attest/`, read-only.
fn dump_to_shm(dumps: &str, attested: &[String]) {
    init_utility_cage();
    let mut builder = ArchiveBuilder::new();
    let mut files = 0;
    let entries = dumps
        .split(';')
        .map(|e| e.trim_start_matches([' ', '\t']))
        .filter(|e| !e.is_empty())
        .filter_map(|e| match e.split_once('=') {
            Some((imfs_path, host_path)) => Some((imfs_path, host_path)),
            None => Some((e, e)),
        })
        .filter(|(imfs_path, host_path)| !imfs_path.is_empty() && !host_path.is_empty());
    let entries = entries.map(|(imfs_path, host_path)| (imfs_path, host_path, 0o777));
    let attest_entries = attested
        .iter()
        .map(|p| (p.as_str(), p.trim_start_matches('/'), 0o444));

    for (imfs_path, host_path, mode) in entries.chain(attest_entries) {
        match read_imfs_file(imfs_path) {
            Ok(data) => {
                builder.push(host_path, mode, &data);
                files += 1;
            }
            Err(e) => log!("failed to dump {}: {}", imfs_path, e),
        }
    }

    let archive = builder.finish();
    match preload_archive::shm::dump(&archive) {
        Ok(()) => log!(
            "dumped {} files ({} bytes) to shared memory",
            files,
            archive.len()
        ),
        Err(e) => eprintln!("imfs-grate: dump to shared memory failed: {}", e),
    }
}

/// Read a whole IMFS file with cage 0's fd table.
fn read_imfs_file(path: &str) -> Result<Vec<u8>, String> {
    imfs::with_imfs(|state| {
        let mut st = grate_rs::ffi::stat::default();
        if state.stat(0, path, &mut st) < 0 {
            return Err("not found".to_string());
        }
        let fd = state.open(0, path, fs::O_RDONLY, 0);
        if fd < 0 {
            return Err(format!("imfs open failed: {}", fd));
        }
        let mut data = Vec::with_capacity(st.st_size as usize);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = state.read(0, fd as u64, &mut buf);
            if n < 0 {
                let _ = state.close(0, fd as u64);
                return Err(format!("imfs read failed: {}", n));
            }
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n as usize]);
        }
        let _ = state.close(0, fd as u64);
        Ok(data)
    })
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
    fn shm_and_attest_flags_are_parsed() {
        let config =
            parse_argv(args(&["--preload-shm", "--attest", "--dump-shm", "make"])).unwrap();
        assert!(config.preload_shm && config.attest && config.dump_shm);
        assert_eq!(config.attest_steps, args(&["pipeline", "sources"]));
        assert_eq!(config.argv, args(&["make"]));

        let config = parse_argv(args(&[
            "--attest-steps",
            "tools,src,extra",
            "--preload-shm",
            "--attest",
            "make",
        ]))
        .unwrap();
        assert_eq!(config.attest_steps, args(&["tools", "src", "extra"]));

        assert!(parse_argv(args(&["--attest", "make"])).is_err());
        assert!(parse_argv(args(&["--preload-shm", "--attest-steps", "a/b", "make"])).is_err());
        assert!(parse_argv(args(&["--preload-shm", "--attest-steps", "a,,b", "make"])).is_err());
        assert!(parse_argv(args(&["--preload-shm", "--attest-steps"])).is_err());
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
