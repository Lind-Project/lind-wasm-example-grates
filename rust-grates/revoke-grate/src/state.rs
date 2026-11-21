//! Revocation table.
//!
//! Maps `(cageid, fd)` -> `Mode`. An entry means "fd slot `fd` in cage
//! `cageid` is revoked": syscalls the cage makes on it are emulated as if the
//! descriptor pointed at `/dev/null` or `/dev/zero`, while the real underlying
//! descriptor stays open (so the fd number cannot be reused by the kernel and
//! alias some new object while still marked revoked).
//!
//! Entries are created by the `revoke` syscall and then follow the descriptor:
//! - `dup`/`dup2`/`dup3`/`fcntl(F_DUPFD*)` copy the entry to the new fd
//! - `dup2`/`dup3` onto a revoked fd from a non-revoked fd clear it
//! - `close` clears it
//! - `fork` copies all of the parent's entries to the child
//! - `exec` clears entries whose real fd is close-on-exec
//!
//! The lock is never held across a threei call.

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

// ── Cage tree ───────────────────────────────────────────────────────
//
// Every cage routed through this grate, mapped to its parent. Filled at
// startup (the grate's child) and on each process clone. Used to reject
// revokes aimed at cages this grate cannot intercept, and is the data a
// descendant-only permission check would need.
//
// Exited cages are not removed (the grate does not intercept exit), but cage
// IDs are never reused and calls into a dead cage fail with ESRCH anyway.

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

/// Parent of `cage`, if known.
#[allow(dead_code)] // for a future permission check
pub fn parent_of(cage: u64) -> Option<u64> {
    cages().get(&cage).copied()
}
