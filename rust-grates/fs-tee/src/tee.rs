use std::{collections::HashMap, ffi::CString, sync::Mutex};

use grate_rs::constants::fs::{O_CREAT, O_WRONLY};

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
    /// Alt syscall number for the secondary handler.
    pub secondary_alt: Option<u64>,
}

pub struct TeeState {
    pub phase: TeePhase,
    pub tee_routes: HashMap<(u64, u64), TeeRoute>,

    pub interposition_map: Vec<(u64, u64, u64, u64)>,

    pub secondary_top: u64,

    pub secondary_entry: u64,

    pub fork_return: u64,

    pub secondary_log_fd: i32,

    pub target_cage: u64,

    alt_nr: u64,
}

impl TeeState {
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
            // primary_target: 0,
            interposition_map: Vec::new(),

            secondary_entry: 0,
            secondary_top: 0,

            fork_return: 0,
            alt_nr: 3000,

            secondary_log_fd,
            target_cage: 0,
        }
    }

    pub fn alloc_alt(&mut self) -> u64 {
        self.alt_nr += 1;
        return self.alt_nr;
    }
}

pub static TEE_STATE: Mutex<Option<TeeState>> = Mutex::new(None);

/// Access the global tee state. Panics if not initialized.
pub fn with_tee<F, R>(f: F) -> R
where
    F: FnOnce(&mut TeeState) -> R,
{
    let mut guard = TEE_STATE.lock().unwrap();
    let ret = f(guard.as_mut().expect("TeeState not initialized"));

    ret
}
