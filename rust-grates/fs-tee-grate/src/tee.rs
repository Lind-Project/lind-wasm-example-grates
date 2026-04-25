use std::{collections::HashMap, sync::Mutex};

#[derive(Copy, Clone, Debug)]
pub enum TeePhase {
    Init,
    Primary,
    Secondary,
    Target,
}

impl TeePhase {
    pub fn next(self) -> Self {
        match self {
            TeePhase::Init => TeePhase::Primary,
            TeePhase::Primary => TeePhase::Secondary,
            TeePhase::Secondary => TeePhase::Target,
            TeePhase::Target => TeePhase::Target, // or panic!() if that's invalid
        }
    }
}

#[derive(Clone, Debug)]
pub struct TeeRoute {
    /// Alt syscall number for the primary handler.
    pub primary_alt: Option<u64>,
    /// Alt syscall number for the secondary handler.
    pub secondary_alt: Option<u64>,
}

pub struct TeeState {
    pub phase: TeePhase,
    pub tee_routes: HashMap<(u64, u64), TeeRoute>,

    pub primary_target: u64,

    pub interposition_map: Vec<(u64, u64, u64, u64)>,

    alt_nr: u64,
}

impl TeeState {
    pub fn new() -> Self {
        Self {
            phase: TeePhase::Primary,
            tee_routes: HashMap::new(),
            primary_target: 0,
            interposition_map: Vec::new(),
            alt_nr: 3000,
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
