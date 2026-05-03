//! Global state and routing helpers for the namespace grate.
//!
//! This module contains:
//!   - Global routing table: (cage_id, syscall_nr) → alt syscall number
//!   - Clamp phase flag and prefix condition
//!   - Per-cage clamped status tracking
//!   - Helpers for reading paths from cage memory and making syscalls

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use grate_rs::{copy_data_between_cages, make_threei_call};

// =====================================================================
//  Global state
// =====================================================================

pub struct NSClampState {
    /// Routing table: (cage_id, syscall_nr) → alt syscall number.
    /// When a clamped grate registers a handler, we store the alt number here.
    routes: Option<HashMap<(u64, u64), u64>>,

    /// The namespace grate's own cage ID.
    ns_cage_id: u64,

    /// Cage ID captured at the clamp entry point.
    clamp_entry_cage: u64,

    /// The path prefix condition for routing.
    routing_prefix: Option<String>,

    /// Set of cage IDs that are inside the clamp.
    clamped_cages: Option<HashMap<u64, ()>>,

    /// Alt syscall number allocator — starts well above Lind's 1001-1003 range.
    /// Each intercepted register_handler call gets a unique alt number.
    alt_allocator: u64,

    /// Recorded inner-grate handler registrations as
    /// `(target_cage, syscall_nr, grate_id, handler_fn_ptr)`.
    interposition_map: Vec<(u64, u64, u64, u64)>,
}

impl NSClampState {
    pub fn new(ns_cage_id: u64, prefix: String) -> Self {
        Self {
            routes: None,
            ns_cage_id: ns_cage_id,
            clamp_entry_cage: 0,
            routing_prefix: Some(prefix),
            clamped_cages: None,
            alt_allocator: 3000,
            interposition_map: Vec::new(),
        }
    }
}

pub static CLAMP_STATE: Mutex<Option<NSClampState>> = Mutex::new(None);
static LOGGING_ENABLED: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if $crate::helpers::logging_enabled() {
            println!($($arg)*);
        }
    };
}

/// Initialize all global state. Called once at startup.
pub fn init_globals(ns_cage_id: u64, prefix: String, logging_enabled: bool) {
    *CLAMP_STATE.lock().unwrap() = Some(NSClampState::new(ns_cage_id, prefix));
    LOGGING_ENABLED.store(logging_enabled, Ordering::Relaxed);
}

// =====================================================================
//  Accessors
// =====================================================================

/// Return the namespace grate's own cage ID.
pub fn get_ns_cage_id() -> u64 {
    CLAMP_STATE.lock().unwrap().as_ref().unwrap().ns_cage_id
}

/// Return the cage ID saved at the clamp entry point.
pub fn get_clamp_entry() -> u64 {
    CLAMP_STATE
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clamp_entry_cage
}

pub fn get_routing_prefix() -> String {
    CLAMP_STATE
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .routing_prefix
        .as_ref()
        .unwrap()
        .clone()
}

/// Allocate the next available alt syscall number.
pub fn alloc_alt_syscall() -> u64 {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().unwrap();

    let nr = s.alt_allocator;
    s.alt_allocator += 1;
    nr
}

pub fn logging_enabled() -> bool {
    LOGGING_ENABLED.load(Ordering::Relaxed)
}

// =====================================================================
//  Cage tracking
// =====================================================================

pub fn set_clamp_entry(cage_id: u64) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    s.clamp_entry_cage = cage_id;
}

pub fn register_clamped_cage(cage_id: u64) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    s.clamped_cages
        .get_or_insert_with(HashMap::new)
        .insert(cage_id, ());
}

pub fn deregister_clamped_cage(cage_id: u64) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    if let Some(cages) = s.clamped_cages.as_mut() {
        cages.remove(&cage_id);
    }
}

pub fn is_cage_clamped(cage_id: u64) -> bool {
    CLAMP_STATE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| s.clamped_cages.as_ref())
        .map(|c| c.contains_key(&cage_id))
        .unwrap_or(false)
}

pub fn push_interposition_request(request: (u64, u64, u64, u64)) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    s.interposition_map.push(request);
}

pub fn get_interposition_request(target_cage: u64, fs_syscall: u64) -> Option<(u64, u64)> {
    CLAMP_STATE
        .lock()
        .unwrap()
        .as_ref()
        .expect("CLAMP_STATE not initialized")
        .interposition_map
        .iter()
        .find(|(child_cage, syscall_number, _, _)| {
            *child_cage == target_cage && *syscall_number == fs_syscall
        })
        .map(|(_, _, grate_id, handler_fn)| (*grate_id, *handler_fn))
}

// =====================================================================
//  Route table
// =====================================================================

pub fn set_route(cage_id: u64, syscall_nr: u64, alt_nr: u64) -> bool {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    s.routes
        .get_or_insert_with(HashMap::new)
        .insert((cage_id, syscall_nr), alt_nr)
        .is_some()
}

pub fn get_route(cage_id: u64, syscall_nr: u64) -> Option<u64> {
    CLAMP_STATE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|s| s.routes.as_ref())
        .and_then(|r| r.get(&(cage_id, syscall_nr)).copied())
}

pub fn clone_cage_routes(parent: u64, child: u64) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    if let Some(map) = s.routes.as_mut() {
        let parent_routes: Vec<(u64, u64)> = map
            .iter()
            .filter(|&(&(cid, _), _)| cid == parent)
            .map(|(&(_, nr), &alt)| (nr, alt))
            .collect();

        for (nr, alt) in parent_routes {
            map.insert((child, nr), alt);
        }
    }
}

pub fn remove_cage_state(cage_id: u64) {
    let mut state = CLAMP_STATE.lock().unwrap();
    let s = state.as_mut().expect("CLAMP_STATE not initialized");

    if let Some(routes) = s.routes.as_mut() {
        routes.retain(|&(cid, _), _| cid != cage_id);
    }

    if let Some(cages) = s.clamped_cages.as_mut() {
        cages.remove(&cage_id);
    }
}

// =====================================================================
//  Helpers for handlers
// =====================================================================

const MAX_PATH_LEN: usize = 4096;

/// Read a null-terminated path string from a cage's address space.
pub fn read_path_from_cage(path_ptr: u64, path_cage: u64) -> Option<String> {
    let ns_cage = get_ns_cage_id();
    let mut buf = vec![0u8; MAX_PATH_LEN];

    match copy_data_between_cages(
        ns_cage,
        path_cage,
        path_ptr,
        path_cage,
        buf.as_mut_ptr() as u64,
        ns_cage,
        MAX_PATH_LEN as u64,
        1,
    ) {
        Ok(_) => {}
        Err(_) => return None,
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_LEN);
    String::from_utf8(buf[..len].to_vec()).ok()
}

/// Check whether a path matches the routing prefix condition.
pub fn path_matches_prefix(path: &str) -> bool {
    path.starts_with(&get_routing_prefix())
}

/// Make a syscall via threei with the standard 6-arg pattern.
///
/// Uses ns_cage as the source cage for routing, and callingcage as the targetcage.
pub fn do_syscall(callingcage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let ns_cage = get_ns_cage_id();
    match make_threei_call(
        nr as u32,
        0,
        ns_cage,
        callingcage,
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// Make a syscall via threei, using the saved clamp-entry cage as source.
pub fn do_clamp_syscall(callingcage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    match make_threei_call(
        nr as u32,
        0,
        get_clamp_entry(),
        callingcage,
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}
