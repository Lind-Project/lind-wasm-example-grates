//! Global state and routing helpers for the namespace grate.
//!
//! This module contains:
//!   - Global routing table: (cage_id, syscall_nr) → alt syscall number
//!   - Clamp phase flag and prefix condition
//!   - Per-cage clamped status tracking
//!   - Helpers for reading paths from cage memory and making syscalls

use std::collections::HashMap;
use std::sync::Mutex;

use grate_rs::{copy_data_between_cages, make_threei_call};

// =====================================================================
//  Global state
// =====================================================================

/// Routing table: (cage_id, syscall_nr) → alt syscall number.
/// When a clamped grate registers a handler, we store the alt number here.
static ROUTES: Mutex<Option<HashMap<(u64, u64), u64>>> = Mutex::new(None);

/// The namespace grate's own cage ID.
static NS_CAGE_ID: Mutex<u64> = Mutex::new(0);

/// The path prefix condition for routing.
static ROUTING_PREFIX: Mutex<Option<String>> = Mutex::new(None);

/// Set of cage IDs that are inside the clamp.
static CLAMPED_CAGES: Mutex<Option<HashMap<u64, ()>>> = Mutex::new(None);

/// Alt syscall number allocator — starts well above Lind's 1001-1003 range.
/// Each intercepted register_handler call gets a unique alt number.
static ALT_ALLOCATOR: Mutex<u64> = Mutex::new(2000);

/// Initialize all global state. Called once at startup.
pub fn init_globals(ns_cage_id: u64, prefix: String) {
    *ROUTES.lock().unwrap() = Some(HashMap::new());
    *CLAMPED_CAGES.lock().unwrap() = Some(HashMap::new());
    *NS_CAGE_ID.lock().unwrap() = ns_cage_id;
    *ROUTING_PREFIX.lock().unwrap() = Some(prefix);
}

// =====================================================================
//  Accessors
// =====================================================================

pub fn get_ns_cage_id() -> u64 {
    *NS_CAGE_ID.lock().unwrap()
}

pub fn get_routing_prefix() -> String {
    ROUTING_PREFIX
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .unwrap_or_default()
}

/// Allocate the next available alt syscall number.
pub fn alloc_alt_syscall() -> u64 {
    let mut next = ALT_ALLOCATOR.lock().unwrap();
    let nr = *next;
    *next += 1;
    nr
}

// =====================================================================
//  Cage tracking
// =====================================================================

/// Record that this cage is inside the clamp.
pub fn register_clamped_cage(cage_id: u64) {
    let mut cages = CLAMPED_CAGES.lock().unwrap();
    cages.as_mut().unwrap().insert(cage_id, ());
}

/// Remove a cage's clamped status. Done when we hit %}
pub fn deregister_clamped_cage(cage_id: u64) {
    let mut cages = CLAMPED_CAGES.lock().unwrap();
    cages.as_mut().unwrap().remove(&cage_id);
}

pub fn is_cage_clamped(cage_id: u64) -> bool {
    CLAMPED_CAGES
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.contains_key(&cage_id))
        .unwrap_or(false)
}

// =====================================================================
//  Route table
// =====================================================================

/// Store the alt syscall number for a (cage, syscall) pair.
/// Returns whether an alt was already registered for this pair.
pub fn set_route(cage_id: u64, syscall_nr: u64, alt_nr: u64) -> bool {
    let mut routes = ROUTES.lock().unwrap();
    routes
        .as_mut()
        .unwrap()
        .insert((cage_id, syscall_nr), alt_nr)
        .is_some()
}

/// Look up the alt syscall number for a (cage, syscall) pair.
pub fn get_route(cage_id: u64, syscall_nr: u64) -> Option<u64> {
    ROUTES
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|r| r.get(&(cage_id, syscall_nr)).copied())
}

/// Copy all routes from parent cage to child cage.
pub fn clone_cage_routes(parent: u64, child: u64) {
    let mut routes = ROUTES.lock().unwrap();
    if let Some(map) = routes.as_mut() {
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

/// Remove all state for a cage (routes + clamped status).
pub fn remove_cage_state(cage_id: u64) {
    if let Some(routes) = ROUTES.lock().unwrap().as_mut() {
        routes.retain(|&(cid, _), _| cid != cage_id);
    }
    if let Some(cages) = CLAMPED_CAGES.lock().unwrap().as_mut() {
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
