use std::sync::atomic::AtomicBool;

use crate::state::norm_fd;
use grate_rs::constants::error::{EFAULT, EINVAL};
use grate_rs::{copy_data_between_cages, getcageid};

/// Set from `--log` at startup; read by `rlog!`.
pub static LOG: AtomicBool = AtomicBool::new(false);

/// `eprintln!` with a `[revoke-grate]` prefix, only when `--log` is set. The
/// arguments are not formatted at all when logging is off.
macro_rules! rlog {
    ($($arg:tt)*) => {
        if $crate::utils::LOG.load(::std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[revoke-grate] {}", format_args!($($arg)*));
        }
    };
}
pub(crate) use rlog;

/// Upper bound on iovcnt, matches Linux IOV_MAX.
const IOV_MAX: u64 = 1024;
/// Size of `struct iovec` in a wasm32 cage: { u32 iov_base; u32 iov_len; }.
const IOVEC_SIZE: u64 = 8;
/// Chunk size used when writing zeros into a cage buffer.
const ZERO_CHUNK: usize = 64 * 1024;
static ZEROS: [u8; ZERO_CHUNK] = [0; ZERO_CHUNK];

#[inline]
pub fn neg(e: i32) -> i64 {
    -(e as i64)
}

// ── Cage memory helpers ─────────────────────────────────────────────

/// Write `len` zero bytes to `dst` in `cage`. Returns bytes written, or
/// -EFAULT if nothing could be written.
pub fn zero_fill(cage: u64, dst: u64, len: u64) -> i64 {
    let this = getcageid();
    let mut done: u64 = 0;
    while done < len {
        let n = (len - done).min(ZERO_CHUNK as u64);
        if copy_data_between_cages(
            this,
            cage,
            ZEROS.as_ptr() as u64,
            this,
            dst + done,
            cage,
            n,
            0,
        )
        .is_err()
        {
            return if done > 0 { done as i64 } else { neg(EFAULT) };
        }
        done += n;
    }
    done as i64
}

/// Read a wasm32 iovec array from `cage`. Returns (base, len) pairs.
pub fn read_iovecs(cage: u64, ptr: u64, cnt: u64) -> Result<Vec<(u64, u64)>, i64> {
    let cnt = norm_fd(cnt); // low 32 bits, same as an int argument
    if cnt > IOV_MAX {
        return Err(neg(EINVAL));
    }
    if cnt == 0 {
        return Ok(Vec::new());
    }
    let this = getcageid();
    let mut raw = vec![0u32; (cnt * 2) as usize];
    copy_data_between_cages(
        this,
        cage,
        ptr,
        cage,
        raw.as_mut_ptr() as u64,
        this,
        cnt * IOVEC_SIZE,
        0,
    )
    .map_err(|_| neg(EFAULT))?;
    Ok(raw.chunks(2).map(|p| (p[0] as u64, p[1] as u64)).collect())
}

pub fn iov_total(iovs: &[(u64, u64)]) -> i64 {
    iovs.iter().map(|&(_, l)| l).sum::<u64>() as i64
}

/// First byte of a path argument. `Ok(None)` for a NULL pointer.
pub fn arg_first_byte(cage: u64, ptr: u64) -> Result<Option<u8>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let this = getcageid();
    let mut b: u8 = 0;
    copy_data_between_cages(this, cage, ptr, cage, &mut b as *mut u8 as u64, this, 1, 0)
        .map_err(|_| neg(EFAULT))?;
    Ok(Some(b))
}
