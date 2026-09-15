//! Cage-side helpers: read host files through 3i, either one at a time into
//! an archive or a prebuilt archive as a whole.
//!
//! Everything here goes through `make_threei_call` rather than Rust `std::fs`.
//! In lind-wasm, `std::fs::metadata()` can report a bogus huge file size and
//! make `std::fs::read()` try to allocate too much, so the raw syscalls are
//! used like the C grates do.

use std::ffi::CString;

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::ffi::stat;
use grate_rs::{GrateError, getcageid, make_threei_call};

use crate::{ArchiveBuilder, parse_preload_entry};

const READ_CHUNK_SIZE: usize = 64 * 1024;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

/// Issue a syscall against the current grate cage. Pointer arguments that
/// refer to grate-owned buffers must already carry GRATE_MEMORY_FLAG in
/// `arg_cages`.
pub fn raw_threei_syscall(syscall: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let this_cage = getcageid();
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

/// Whether `path` names a regular file on the host. Only regular files are
/// staged into IMFS.
pub fn is_regular_file(path: &str) -> bool {
    let c_path = match CString::new(path) {
        Ok(path) => path,
        Err(_) => return false,
    };

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

/// Read a whole host file through 3i.
pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let c_path = CString::new(path).map_err(|_| "path contains interior NUL".to_string())?;
    let this_cage = getcageid();
    let same_cage = [
        this_cage, this_cage, this_cage, this_cage, this_cage, this_cage,
    ];

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
    let mut buf = vec![0u8; READ_CHUNK_SIZE];

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
            let _ = raw_threei_syscall(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0], same_cage);
            return Err(format!("read failed: {}", nread));
        }
        if nread == 0 {
            break;
        }
        data.extend_from_slice(&buf[..nread as usize]);
    }

    let close_ret = raw_threei_syscall(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0], same_cage);
    if close_ret < 0 {
        return Err(format!("close failed: {}", close_ret));
    }

    Ok(data)
}

/// The outcome of packing a PRELOADS list.
#[derive(Debug, Default)]
pub struct BuildReport {
    /// The finished archive, or None when no entry could be read.
    pub archive: Option<Vec<u8>>,
    /// `host_path -> imfs_path` for every entry that went into the archive.
    pub staged: Vec<String>,
    /// One message per entry that was left out, and why.
    pub skipped: Vec<String>,
}

/// Read every valid entry of a colon-separated PRELOADS list from the host
/// and pack it into one archive. Every file gets permission bits `mode`.
pub fn build_archive(preloads: &str, mode: u32) -> BuildReport {
    let mut builder = ArchiveBuilder::new();
    let mut report = BuildReport::default();

    for entry in preloads.split(':') {
        let (imfs_path, host_path) = match parse_preload_entry(entry) {
            Some(paths) => paths,
            None => continue,
        };

        if !is_regular_file(host_path) {
            report
                .skipped
                .push(format!("{}: not a regular file", host_path));
            continue;
        }

        match read_file(host_path) {
            Ok(data) => {
                builder.push(imfs_path, mode, &data);
                report
                    .staged
                    .push(format!("{} -> {}", host_path, imfs_path));
            }
            Err(e) => report.skipped.push(format!("{}: {}", host_path, e)),
        }
    }

    if builder.entries() > 0 {
        report.archive = Some(builder.finish());
    }
    report
}
