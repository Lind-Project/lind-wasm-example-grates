//! Global state and routing helpers for the net namespace grate.
//!
//! Mirrors the FS namespace grate's helpers.rs but routes by port range
//! instead of path prefix.

use std::collections::HashMap;
use std::sync::Mutex;

use grate_rs::{copy_data_between_cages, make_threei_call};

// =====================================================================
//  Global state
// =====================================================================

/// Routing table: (cage_id, syscall_nr) -> alt syscall number.
static ROUTES: Mutex<Option<HashMap<(u64, u64), u64>>> = Mutex::new(None);

/// The namespace grate's own cage ID.
static NS_CAGE_ID: Mutex<u64> = Mutex::new(0);

/// Port range for routing: (low, high) inclusive.
static PORT_RANGE: Mutex<(u16, u16)> = Mutex::new((0, 0));

/// Set of cage IDs inside the clamp.
static CLAMPED_CAGES: Mutex<Option<HashMap<u64, ()>>> = Mutex::new(None);

/// Alt syscall number allocator — starts above Lind's 1001-1003 range.
static ALT_ALLOCATOR: Mutex<u64> = Mutex::new(2000);

/// Initialize all global state. Called once at startup.
pub fn init_globals(ns_cage_id: u64, port_low: u16, port_high: u16) {
    *ROUTES.lock().unwrap() = Some(HashMap::new());
    *CLAMPED_CAGES.lock().unwrap() = Some(HashMap::new());
    *NS_CAGE_ID.lock().unwrap() = ns_cage_id;
    *PORT_RANGE.lock().unwrap() = (port_low, port_high);
}

// =====================================================================
//  Accessors
// =====================================================================

pub fn get_ns_cage_id() -> u64 {
    *NS_CAGE_ID.lock().unwrap()
}

pub fn get_port_range() -> (u16, u16) {
    *PORT_RANGE.lock().unwrap()
}

pub fn alloc_alt_syscall() -> u64 {
    let mut next = ALT_ALLOCATOR.lock().unwrap();
    let nr = *next;
    *next += 1;
    nr
}

// =====================================================================
//  Cage tracking
// =====================================================================

pub fn register_clamped_cage(cage_id: u64) {
    let mut cages = CLAMPED_CAGES.lock().unwrap();
    cages.as_mut().unwrap().insert(cage_id, ());
}

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

pub fn set_route(cage_id: u64, syscall_nr: u64, alt_nr: u64) -> bool {
    let mut routes = ROUTES.lock().unwrap();
    routes
        .as_mut()
        .unwrap()
        .insert((cage_id, syscall_nr), alt_nr)
        .is_some()
}

pub fn get_route(cage_id: u64, syscall_nr: u64) -> Option<u64> {
    ROUTES
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|r| r.get(&(cage_id, syscall_nr)).copied())
}

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

pub fn remove_cage_state(cage_id: u64) {
    if let Some(routes) = ROUTES.lock().unwrap().as_mut() {
        routes.retain(|&(cid, _), _| cid != cage_id);
    }
    if let Some(cages) = CLAMPED_CAGES.lock().unwrap().as_mut() {
        cages.remove(&cage_id);
    }
}

// =====================================================================
//  Port matching
// =====================================================================

/// Check whether a port falls in the clamped range.
pub fn port_in_range(port: u16) -> bool {
    let (low, high) = get_port_range();
    port >= low && port <= high
}

/// Extract the port from a sockaddr buffer. Handles AF_INET (family=2)
/// and AF_INET6 (family=10). Returns None for other families or if
/// the buffer is too short.
pub fn extract_port_from_sockaddr(buf: &[u8]) -> Option<u16> {
    if buf.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        2 => {
            // AF_INET: port at offset 2, big-endian
            Some(u16::from_be_bytes([buf[2], buf[3]]))
        }
        10 => {
            // AF_INET6: port at offset 2, big-endian
            if buf.len() >= 4 {
                Some(u16::from_be_bytes([buf[2], buf[3]]))
            } else {
                None
            }
        }
        _ => None,
    }
}

const MAX_PATH_LEN: usize = 4096;

/// Read a null-terminated path string from a cage's address space.
/// Used by exec_handler to detect the %} boundary.
pub fn read_path_from_cage(path_ptr: u64, path_cage: u64) -> Option<String> {
    let ns_cage = get_ns_cage_id();
    let mut buf = vec![0u8; MAX_PATH_LEN];

    match copy_data_between_cages(
        ns_cage, path_cage,
        path_ptr, path_cage,
        buf.as_mut_ptr() as u64, ns_cage,
        MAX_PATH_LEN as u64, 0,
    ) {
        Ok(_) => {}
        Err(_) => return None,
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_LEN);
    String::from_utf8(buf[..len].to_vec()).ok()
}

/// Read a sockaddr from cage memory and extract the port.
pub fn read_port_from_cage(addr_ptr: u64, addr_cage: u64, addrlen: u64) -> Option<u16> {
    let ns_cage = get_ns_cage_id();
    let len = std::cmp::min(addrlen as usize, 128);
    let mut buf = vec![0u8; len];

    match copy_data_between_cages(
        ns_cage, addr_cage,
        addr_ptr, addr_cage,
        buf.as_mut_ptr() as u64, ns_cage,
        len as u64, 0,
    ) {
        Ok(_) => extract_port_from_sockaddr(&buf),
        Err(_) => None,
    }
}

// =====================================================================
//  Syscall forwarding
// =====================================================================

pub fn do_syscall(callingcage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let ns_cage = get_ns_cage_id();
    match make_threei_call(
        nr as u32, 0, ns_cage, callingcage,
        args[0], arg_cages[0], args[1], arg_cages[1], args[2], arg_cages[2],
        args[3], arg_cages[3], args[4], arg_cages[4], args[5], arg_cages[5], 0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}
