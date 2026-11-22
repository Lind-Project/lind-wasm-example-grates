//! revokefd syscall ABI to sync with `include/lind_revokefd.h`.
//!
//! ```text
//! revokefd(target_cage, fd, flags = REVOKE_MODE_NULL | REVOKE_MODE_ZERO) -> 0 | -errno
//! ```
//!
//! Errors:
//! `EINVAL` (bad flags), `ESRCH` (invalid cage), `EBADF` (invalid fd),
//! `EPERM` (refused by the grate's custom authorization policy)

use crate::state::Mode;

/// High enough to not be in conflict with linux, benchmark, or tee/clamping
/// syscall numbers.
pub const SYS_REVOKEFD: u64 = 4001;

pub const REVOKE_MODE_MASK: u32 = 0xff;
pub const REVOKE_MODE_NULL: u32 = 0;
pub const REVOKE_MODE_ZERO: u32 = 1;

/// Decode `flags` into a `Mode`
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
