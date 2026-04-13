use std::{collections::HashMap, sync::Mutex};

pub static TEE_STATE: Mutex<Option<TeeState>> = Mutex::new(None);

#[derive(Debug)]
pub struct TeeState {
    pub interposition_map: Vec<(u64, u64, u64, u64)>,
    pub target_cage_id: u64,
    pub tee_cage_id: u64,

    pub primary_target_cage: Option<u64>,
    pub secondary_target_cage: Option<u64>,

    pub tee_route: HashMap<(u64, u64), TeeRoute>,

    pub exiting: bool,

    next_alt: u64,
}

#[derive(Clone, Debug)]
pub struct TeeRoute {
    /// Alt syscall number for the primary handler.
    pub primary_alt: Option<u64>,
    /// Alt syscall number for the secondary handler.
    pub secondary_alt: Option<u64>,
    // Whether we've already registered the tee dispatch handler
    // on the target cage for this syscall.
    // pub tee_handler_registered: bool,
}

/// Access the global tee state. Panics if not initialized.
pub fn with_tee<F, R>(f: F) -> R
where
    F: FnOnce(&mut TeeState) -> R,
{
    let mut guard = TEE_STATE.lock().unwrap();
    f(guard.as_mut().expect("TeeState not initialized"))
}

impl TeeState {
    pub fn new(tee_cage_id: u64) -> Self {
        Self {
            interposition_map: Vec::new(), 
            target_cage_id: 0,
            tee_cage_id: tee_cage_id,
            tee_route: HashMap::new(), 
            next_alt: 3000,

            primary_target_cage: None, 
            secondary_target_cage: None,

            exiting: false,
        }
    }

    pub fn alloc_alt(&mut self) -> u64 {
        self.next_alt += 1;

        return self.next_alt;
    }

    pub fn set_target_cage_id(&mut self, target_cage_id: u64) {
        self.target_cage_id = target_cage_id;
    }
}
