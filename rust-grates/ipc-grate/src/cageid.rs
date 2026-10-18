//! This grate's cage id, asked of the runtime once.
//!
//! `grate_rs::getcageid()` is `getpid()`, a syscall through 3i, and the
//! handlers ask for the id on every call that copies data between cages
//! (read and write once, stat twice). The id is kept after the first call
//! instead. A fork makes the child a new cage (a grate's fork gives the
//! child its own id and its own handler workers), so the child forgets it:
//! an atfork handler, registered before the id is first kept, clears it in
//! the child of every fork.

use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};

/// No id kept yet.
const UNSET: u64 = u64::MAX;

static CAGEID: AtomicU64 = AtomicU64::new(UNSET);

unsafe extern "C" {
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> i32;
}

unsafe extern "C" fn forget_cageid() {
    CAGEID.store(UNSET, Ordering::Relaxed);
}

/// This grate's cage id (see the module documentation).
pub fn getcageid() -> u64 {
    let id = CAGEID.load(Ordering::Relaxed);
    if id != UNSET {
        return id;
    }
    static ATFORK: Once = Once::new();
    ATFORK.call_once(|| unsafe {
        pthread_atfork(None, None, Some(forget_cageid));
    });
    let id = grate_rs::getcageid();
    CAGEID.store(id, Ordering::Relaxed);
    id
}
