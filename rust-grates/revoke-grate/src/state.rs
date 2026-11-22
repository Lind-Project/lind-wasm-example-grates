//! Revocation table state.
//!
//! Maintains a map of (cageid, fd) -> Option<Mode> representing whether a given tuple
//! is revoked, and if it is revoked which mode was used to revoke it.
//!
//! Apart from the revokefd syscall, the following can also modify this state:
//!
//! - dup calls: copies the state to the new fd. If a non-revoked fd is dup'd to a revoked fd,
//! the revocation gets cleared.
//! - close clears it
//! - fork copies the table to the forked cage.
//! - exec clears the revocation if the FD was opened with close-on-exec

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Behave like `/dev/null`: reads return EOF, writes are swallowed.
    Null,
    /// Behave like `/dev/zero`: reads return zero bytes, writes are swallowed.
    Zero,
}

static REVOKED: Mutex<BTreeMap<(u64, u64), Mode>> = Mutex::new(BTreeMap::new());

fn table() -> std::sync::MutexGuard<'static, BTreeMap<(u64, u64), Mode>> {
    // A panic while holding the lock would poison it; keep revoking anyway.
    REVOKED.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn revoke(cage: u64, fd: u64, mode: Mode) {
    table().insert((cage, norm_fd(fd)), mode);
}

pub fn unrevoke(cage: u64, fd: u64) {
    table().remove(&(cage, norm_fd(fd)));
}

pub fn lookup(cage: u64, fd: u64) -> Option<Mode> {
    table().get(&(cage, norm_fd(fd))).copied()
}

/// All revoked fds of a cage.
pub fn fds_of(cage: u64) -> Vec<(u64, Mode)> {
    table()
        .range((cage, 0)..=(cage, u64::MAX))
        .map(|(&(_, fd), &m)| (fd, m))
        .collect()
}

/// Copy every entry of `parent` to `child` (fork inherits descriptors).
pub fn inherit(parent: u64, child: u64) {
    let mut t = table();
    let entries: Vec<(u64, Mode)> = t
        .range((parent, 0)..=(parent, u64::MAX))
        .map(|(&(_, fd), &m)| (fd, m))
        .collect();
    for (fd, m) in entries {
        t.insert((child, fd), m);
    }
}
/// fd arguments arrive as u64; only the low 32 bits are meaningful. Negative
/// values (AT_FDCWD, -1) normalize to large numbers that never match an entry.
#[inline]
pub fn norm_fd(raw: u64) -> u64 {
    raw as u32 as u64
}

// Cage tree.
//
// Used to check whether this grate can see a cageid provided (i.e. if it was ever
// registered).
static CAGES: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

fn cages() -> std::sync::MutexGuard<'static, BTreeMap<u64, u64>> {
    CAGES.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn add_cage(cage: u64, parent: u64) {
    cages().insert(cage, parent);
}

pub fn is_known_cage(cage: u64) -> bool {
    cages().contains_key(&cage)
}
