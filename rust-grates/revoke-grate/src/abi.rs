//! The revokefd syscall ABI. Kept in sync with `include/lind_revokefd.h`.
//!
//! ```text
//! revokefd(target_cage, fd, flags) -> 0 | -errno
//! ```
//!
//! - `target_cage`: cage whose fd is revoked. May be the caller itself.
//! - `fd`:          fd slot in that cage. Must currently be open.
//! - `flags`:       low byte selects the mode; all other bits are reserved and
//!                  must be zero.
//!
//! Errors: `EINVAL` (bad flags), `ESRCH` (cage not under this grate or dead),
//! `EBADF` (fd not open in the target), `EPERM` (refused by `authorize`).

use crate::state::Mode;

/// Clear of Linux numbers, the 3i calls (1001-1003) and the 2001-2999 range
/// used by lind-perf benchmarks and other grates.
pub const SYS_REVOKEFD: u64 = 3001;

pub const REVOKE_MODE_MASK: u32 = 0xff;
pub const REVOKE_MODE_NULL: u32 = 0;
pub const REVOKE_MODE_ZERO: u32 = 1;

/// Decode `flags` into a mode, rejecting unknown modes and reserved bits.
pub fn decode_flags(flags: u32) -> Option<Mode> {
    if flags & !REVOKE_MODE_MASK != 0 {
        return None;
    }
    match flags & REVOKE_MODE_MASK {
        REVOKE_MODE_NULL => Some(Mode::Null),
        REVOKE_MODE_ZERO => Some(Mode::Zero),
        _ => None,
    }
}
