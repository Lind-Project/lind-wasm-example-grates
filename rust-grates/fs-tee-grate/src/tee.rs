use std::{collections::HashMap, ffi::CString, sync::Mutex};

use grate_rs::constants::fs::{O_CREAT, O_WRONLY};

/// Track which part of the exec chain fs-tee is currently walking.
///
/// Encountering `%}` advances the phase.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TeePhase {
    Secondary,
    Target,
}

impl TeePhase {
    pub fn next(self) -> Self {
        match self {
            TeePhase::Secondary => TeePhase::Target,
            TeePhase::Target => TeePhase::Target,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TeeRoute {
    /// Alternate syscall number used to reach the secondary handler, when one exists.
    pub secondary_alt: Option<u64>,
}

pub struct TeeState {
    /// Current phase in the exec chain.
    pub phase: TeePhase,

    /// Map `(cage, syscall)` to the route fs-tee should use for that call.
    pub tee_routes: HashMap<(u64, u64), TeeRoute>,

    /// Record every `register_handler` call so the target cage can be rewritten before exec.
    pub interposition_map: Vec<(u64, u64, u64, u64)>,

    /// Top-most cage inside the tee boundary.
    pub secondary_top: u64,

    /// Entry cage for the tee boundary. Relevant calls into the secondary stack are forwarded
    /// through this cage.
    pub secondary_entry: u64,

    /// Most recent fork return value. Both primary and secondary paths must observe the same
    /// result.
    pub fork_return: u64,

    /// FD used for fs-tee's secondary-path log output.
    pub secondary_log_fd: i32,

    /// Cage ID of the first executed target cage.
    pub target_cage: u64,

    /// Monotonic allocator for alternate syscall numbers.
    alt_nr: u64,
}

impl TeeState {
    /// Create a fresh tee state and open the secondary log file.
    pub fn new() -> Self {
        let secondary_log_fd = unsafe {
            libc::open(
                CString::new("fs-tee-secondary.log").unwrap().as_ptr(),
                O_CREAT | O_WRONLY,
                0755,
            )
        };

        Self {
            phase: TeePhase::Secondary,
            tee_routes: HashMap::new(),
            interposition_map: Vec::new(),
            secondary_entry: 0,
            secondary_top: 0,
            fork_return: 0,
            alt_nr: 3000,
            secondary_log_fd,
            target_cage: 0,
        }
    }

    /// Allocate a new alternate syscall number for a secondary handler.
    pub fn alloc_alt(&mut self) -> u64 {
        self.alt_nr += 1;
        return self.alt_nr;
    }
}

pub static TEE_STATE: Mutex<Option<TeeState>> = Mutex::new(None);

/// Access the global tee state.
///
/// Panics if the state has not been initialized yet.
pub fn with_tee<F, R>(f: F) -> R
where
    F: FnOnce(&mut TeeState) -> R,
{
    let mut guard = TEE_STATE.lock().unwrap();
    let ret = f(guard.as_mut().expect("TeeState not initialized"));

    ret
}
