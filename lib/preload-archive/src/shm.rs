//! Cage-side access to the runtime's shared-memory regions.
//!
//! The runtime can be given two regions of untrusted memory before the first
//! cage starts (lind-boot `--preload-shm` / `--dump-shm`, or the `[shm]`
//! section of a TriSeal keep's Enarx.toml):
//!
//! - a *preload* region holding a bundle of preload archives, packed on the
//!   host ahead of time by `mkpreload`;
//! - a *dump* region that a single archive of output files is written to at
//!   the end of the run.
//!
//! Inside an enclave both regions are outside it: the runtime copies between
//! them and cage memory directly, so neither reading a preload nor writing a
//! dump leaves the enclave. (A TriSeal keep does not even ask the host to
//! commit a dump: the host reads its length from the archive after the keep
//! exits.)
//!
//! [`phase`] is here too: the runtime-level mark of where a run's phases
//! begin, such as the build after the preloads are staged.

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::getcageid;

use crate::host::raw_threei_syscall;

/// `SHM_INFO(out: *mut [u64; 2])`: the preload region's length and the dump
/// region's capacity (0 for a region that is not configured).
pub const SYS_LIND_SHM_INFO: u64 = 2001;
/// `SHM_READ(offset, dst, len)`: copy `len` bytes of the preload region,
/// starting at `offset`, to `dst`. Returns 0.
pub const SYS_LIND_SHM_READ: u64 = 2002;
/// `SHM_DUMP(src, len)`: copy `len` bytes from `src` to the start of the dump
/// region and commit them. Returns 0.
pub const SYS_LIND_SHM_DUMP: u64 = 2003;
/// `PHASE(n)`: the workload entered phase `n`. Returns 0.
pub const SYS_LIND_PHASE: u64 = 2004;

/// The phase that starts when IMFS runs the program, after staging.
pub const PHASE_RUN: u64 = 1;

/// Sizes of the runtime's regions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShmInfo {
    pub preload_len: u64,
    pub dump_capacity: u64,
}

fn call(nr: u64, args: [u64; 3], grate_ptr: [bool; 3]) -> i32 {
    let this_cage = getcageid();
    let cage = |is_ptr: bool| {
        if is_ptr {
            this_cage | GRATE_MEMORY_FLAG
        } else {
            this_cage
        }
    };
    raw_threei_syscall(
        nr,
        [args[0], args[1], args[2], 0, 0, 0],
        [
            cage(grate_ptr[0]),
            cage(grate_ptr[1]),
            cage(grate_ptr[2]),
            this_cage,
            this_cage,
            this_cage,
        ],
    )
}

/// The runtime's regions, or the negative errno if the runtime has none
/// (`-ENOSYS` from a runtime that does not know these calls).
pub fn info() -> Result<ShmInfo, i32> {
    let mut out = [0u64; 2];
    let ret = call(
        SYS_LIND_SHM_INFO,
        [out.as_mut_ptr() as u64, 0, 0],
        [true, false, false],
    );
    if ret < 0 {
        return Err(ret);
    }
    Ok(ShmInfo {
        preload_len: out[0],
        dump_capacity: out[1],
    })
}

/// Copy `buf.len()` bytes of the preload region, starting at `offset`.
pub fn read(offset: u64, buf: &mut [u8]) -> Result<(), i32> {
    if buf.is_empty() {
        return Ok(());
    }
    let ret = call(
        SYS_LIND_SHM_READ,
        [offset, buf.as_mut_ptr() as u64, buf.len() as u64],
        [false, true, false],
    );
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Write `bytes` (a dump archive) to the dump region and commit it.
pub fn dump(bytes: &[u8]) -> Result<(), i32> {
    let ret = call(
        SYS_LIND_SHM_DUMP,
        [bytes.as_ptr() as u64, bytes.len() as u64, 0],
        [true, false, false],
    );
    if ret < 0 { Err(ret) } else { Ok(()) }
}

/// Tell the runtime that the workload entered phase `n`, so that it can
/// count from there what the run asks of the host. A runtime without phase
/// marks fails the call, which is harmless.
pub fn phase(n: u64) -> Result<(), i32> {
    let ret = call(SYS_LIND_PHASE, [n, 0, 0], [false, false, false]);
    if ret < 0 { Err(ret) } else { Ok(()) }
}
