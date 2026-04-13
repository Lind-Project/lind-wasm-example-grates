//! Tee grate core — interposition logic and dispatch.
//!
//! The tee grate duplicates every intercepted syscall across two independent
//! handler chains (primary and secondary). The primary's return value is
//! authoritative. The secondary is best-effort: errors are logged, never
//! propagated to the caller.
//!
//! # How it works
//!
//! The tee grate interposes on `register_handler` (syscall 1001). When a grate
//! in either the primary or secondary stack calls `register_handler`, tee
//! intercepts it, allocates alt syscall numbers, and registers its own dispatch
//! handler on the target cage. At dispatch time, the tee handler calls both the
//! primary and secondary handlers via `make_threei_call` and returns the
//! primary's result.
//!
//! # Dispatch model
//!
//! Synchronous: call primary, then secondary, return primary's result.
//! The WASM environment is single-threaded, so background threads aren't
//! practical. The bounded buffer (default 64KB) caps how much pointer-argument
//! data we pre-copy for the secondary path.
//!
//! # Primary-only syscalls
//!
//! Syscalls with process-level side effects are NOT duplicated:
//! fork, clone, execve, exit. These are forwarded only to the primary handler
//! (or passed through to kernel if no primary handler exists).

use std::collections::HashMap;
use std::sync::Mutex;

use grate_rs::constants::*;
use grate_rs::make_threei_call;

// =====================================================================
//  Constants
// =====================================================================

/// Default maximum bytes to copy for secondary pointer arguments.
pub const DEFAULT_SECONDARY_BUFFER_LIMIT: usize = 64 * 1024;

/// Syscalls that must NOT be duplicated — forwarded to primary only.
/// These have process-level side effects (new cage, cage death, address
/// space replacement) that would break if executed twice.
pub const PRIMARY_ONLY_SYSCALLS: &[u64] = &[
    SYS_FORK,   // 57
    SYS_CLONE,  // 56
    SYS_EXEC,   // 59 (execve)
    SYS_EXIT,   // 60
];

/// Base for alt syscall numbers — well above Lind's 1001-1003 range.
const ALT_SYSCALL_BASE: u64 = 2000;

// =====================================================================
//  Global state
// =====================================================================

/// Global tee state, accessible from extern "C" handler functions.
pub static TEE_STATE: Mutex<Option<TeeState>> = Mutex::new(None);

/// Access the global tee state. Panics if not initialized.
pub fn with_tee<F, R>(f: F) -> R
where
    F: FnOnce(&mut TeeState) -> R,
{
    let mut guard = TEE_STATE.lock().unwrap();
    f(guard.as_mut().expect("TeeState not initialized"))
}

// =====================================================================
//  Route table
//
//  For each (cage_id, syscall_nr), we store the alt syscall numbers for
//  both the primary and secondary handlers. When the tee dispatch handler
//  fires, it calls both.
// =====================================================================

/// A route entry for a single (cage, syscall) pair.
#[derive(Clone, Debug)]
pub struct TeeRoute {
    /// Alt syscall number for the primary handler.
    pub primary_alt: Option<u64>,
    /// Alt syscall number for the secondary handler.
    pub secondary_alt: Option<u64>,
    /// Whether we've already registered the tee dispatch handler
    /// on the target cage for this syscall.
    pub tee_handler_registered: bool,
}

/// The complete tee grate state.
pub struct TeeState {
    /// The tee grate's own cage ID.
    pub tee_cage_id: u64,

    /// Route table: (cage_id, syscall_nr) → TeeRoute.
    pub routes: HashMap<(u64, u64), TeeRoute>,

    /// Cage ID of the primary grate process.
    /// Registrations from this grate_id go into primary_alt.
    pub primary_grate_id: Option<u64>,

    /// Cage ID of the secondary grate process.
    /// Registrations from this grate_id go into secondary_alt.
    pub secondary_grate_id: Option<u64>,

    /// Whether we are still intercepting register_handler calls.
    /// Set to false when the %} exec boundary is detected, meaning
    /// both grate stacks have finished registering their handlers.
    pub intercepting: bool,

    /// Next available alt syscall number.
    pub next_alt: u64,

    /// Maximum bytes to copy for secondary pointer arguments.
    pub secondary_buffer_limit: usize,

    /// Set of cage IDs managed by the tee grate.
    pub managed_cages: HashMap<u64, ()>,
}

impl TeeState {
    pub fn new(tee_cage_id: u64, secondary_buffer_limit: usize) -> Self {
        TeeState {
            tee_cage_id,
            routes: HashMap::new(),
            primary_grate_id: None,
            secondary_grate_id: None,
            intercepting: true,
            next_alt: ALT_SYSCALL_BASE,
            secondary_buffer_limit,
            managed_cages: HashMap::new(),
        }
    }

    /// Allocate the next alt syscall number.
    pub fn alloc_alt(&mut self) -> u64 {
        let nr = self.next_alt;
        self.next_alt += 1;
        nr
    }

    /// Record a handler registration from one of the tee'd grates.
    ///
    /// Determines whether the registering grate is primary or secondary based
    /// on grate_id, allocates an alt syscall number, and stores the route.
    ///
    /// Primary/secondary is auto-assigned by order of first appearance:
    /// the first grate_id we see becomes primary, the second becomes secondary.
    ///
    /// Returns the alt syscall number that was allocated.
    pub fn record_registration(
        &mut self,
        target_cage: u64,
        syscall_nr: u64,
        grate_id: u64,
    ) -> u64 {
        // Auto-assign primary/secondary based on order of first appearance.
        let is_primary = if self.primary_grate_id == Some(grate_id) {
            true
        } else if self.secondary_grate_id == Some(grate_id) {
            false
        } else if self.primary_grate_id.is_none() {
            self.primary_grate_id = Some(grate_id);
            true
        } else if self.secondary_grate_id.is_none() {
            self.secondary_grate_id = Some(grate_id);
            false
        } else {
            // More than two grates — treat extras as secondary.
            eprintln!(
                "[tee-grate] warning: unknown grate_id={}, treating as secondary",
                grate_id
            );
            false
        };

        let alt_nr = self.alloc_alt();

        let route = self
            .routes
            .entry((target_cage, syscall_nr))
            .or_insert_with(|| TeeRoute {
                primary_alt: None,
                secondary_alt: None,
                tee_handler_registered: false,
            });

        if is_primary {
            route.primary_alt = Some(alt_nr);
        } else {
            route.secondary_alt = Some(alt_nr);
        }

        // Track this cage.
        self.managed_cages.insert(target_cage, ());

        alt_nr
    }

    /// Mark the tee dispatch handler as registered for a (cage, syscall).
    pub fn mark_handler_registered(&mut self, target_cage: u64, syscall_nr: u64) {
        if let Some(route) = self.routes.get_mut(&(target_cage, syscall_nr)) {
            route.tee_handler_registered = true;
        }
    }

    /// Check if the tee handler is already registered for a (cage, syscall).
    pub fn is_handler_registered(&self, target_cage: u64, syscall_nr: u64) -> bool {
        self.routes
            .get(&(target_cage, syscall_nr))
            .map(|r| r.tee_handler_registered)
            .unwrap_or(false)
    }

    /// Look up the route for a (cage, syscall).
    pub fn get_route(&self, cage_id: u64, syscall_nr: u64) -> Option<&TeeRoute> {
        self.routes.get(&(cage_id, syscall_nr))
    }

    /// Check if a cage is managed by the tee grate.
    pub fn is_managed(&self, cage_id: u64) -> bool {
        self.managed_cages.contains_key(&cage_id)
    }

    /// Clone route table entries from parent to child cage (on fork).
    pub fn clone_cage_state(&mut self, parent: u64, child: u64) {
        let parent_routes: Vec<_> = self
            .routes
            .iter()
            .filter(|&(&(cid, _), _)| cid == parent)
            .map(|(&(_, syscall_nr), route)| ((child, syscall_nr), route.clone()))
            .collect();
        for (key, val) in parent_routes {
            self.routes.insert(key, val);
        }
        self.managed_cages.insert(child, ());
    }

    /// Remove all state for a cage (on exit).
    pub fn remove_cage_state(&mut self, cage_id: u64) {
        self.routes.retain(|&(cid, _), _| cid != cage_id);
        self.managed_cages.remove(&cage_id);
    }
}

// =====================================================================
//  Dispatch logic
// =====================================================================

/// Execute a syscall via make_threei_call.
///
/// source_cage (tee grate) is used for handler table lookup.
/// calling_cage is the cage that made the syscall — used as operational target.
pub fn do_syscall(calling_cage: u64, nr: u64, args: &[u64; 6], arg_cages: &[u64; 6]) -> i32 {
    let tee_cage = {
        let guard = TEE_STATE.lock().unwrap();
        guard.as_ref().expect("TeeState not initialized").tee_cage_id
    };
    match make_threei_call(
        nr as u32, 0, tee_cage, calling_cage,
        args[0], arg_cages[0],
        args[1], arg_cages[1],
        args[2], arg_cages[2],
        args[3], arg_cages[3],
        args[4], arg_cages[4],
        args[5], arg_cages[5],
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

/// Core tee dispatch: call primary, then secondary, return primary's result.
///
/// For primary-only syscalls (fork, exec, exit, clone), the secondary is
/// skipped entirely. Secondary errors are logged to stderr and never
/// propagated to the caller.
pub fn tee_dispatch(
    syscall_nr: u64,
    cage_id: u64,
    args: [u64; 6],
    arg_cages: [u64; 6],
) -> i32 {
    let (primary_alt, secondary_alt) = {
        let guard = TEE_STATE.lock().unwrap();
        let state = guard.as_ref().expect("TeeState not initialized");
        let route = match state.get_route(cage_id, syscall_nr) {
            Some(r) => r,
            None => {
                // No route — passthrough to kernel.
                return do_syscall(cage_id, syscall_nr, &args, &arg_cages);
            }
        };
        (route.primary_alt, route.secondary_alt)
    };

    // ── Primary dispatch ────────────────────────────────────────────
    // Use the alt syscall if registered, otherwise passthrough the
    // original syscall number (goes to kernel).
    let primary_nr = primary_alt.unwrap_or(syscall_nr);
    let primary_result = do_syscall(cage_id, primary_nr, &args, &arg_cages);

    // ── Secondary dispatch (best-effort) ────────────────────────────
    // Skip for syscalls with process-level side effects — executing
    // fork/exec/exit twice would create duplicate cages or kill the
    // wrong process.
    if PRIMARY_ONLY_SYSCALLS.contains(&syscall_nr) {
        return primary_result;
    }

    if let Some(sec_alt) = secondary_alt {
        // Call secondary with the same args. Each handler does its own
        // copy_data_between_cages internally, so the two paths don't
        // share any local buffers.
        let sec_result = do_syscall(cage_id, sec_alt, &args, &arg_cages);

        // Log secondary errors but never propagate them.
        if sec_result < 0 {
            eprintln!(
                "[tee-grate] secondary error: syscall={} ret={}",
                syscall_nr, sec_result
            );
        }
    }

    // Always return the primary's result.
    primary_result
}

// =====================================================================
//  Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> TeeState {
        TeeState::new(100, DEFAULT_SECONDARY_BUFFER_LIMIT)
    }

    #[test]
    fn test_auto_assign_primary_secondary() {
        let mut state = make_state();

        // First grate to register becomes primary.
        state.record_registration(10, SYS_OPEN, 200);
        assert_eq!(state.primary_grate_id, Some(200));
        assert_eq!(state.secondary_grate_id, None);

        // Second grate becomes secondary.
        state.record_registration(10, SYS_OPEN, 300);
        assert_eq!(state.primary_grate_id, Some(200));
        assert_eq!(state.secondary_grate_id, Some(300));
    }

    #[test]
    fn test_route_stores_both_alts() {
        let mut state = make_state();

        // Primary registers OPEN.
        let primary_alt = state.record_registration(10, SYS_OPEN, 200);

        // Secondary registers OPEN.
        let secondary_alt = state.record_registration(10, SYS_OPEN, 300);

        let route = state.get_route(10, SYS_OPEN).unwrap();
        assert_eq!(route.primary_alt, Some(primary_alt));
        assert_eq!(route.secondary_alt, Some(secondary_alt));
    }

    #[test]
    fn test_primary_only_syscalls() {
        // fork, clone, exec, exit should not be duplicated.
        assert!(PRIMARY_ONLY_SYSCALLS.contains(&SYS_FORK));
        assert!(PRIMARY_ONLY_SYSCALLS.contains(&SYS_CLONE));
        assert!(PRIMARY_ONLY_SYSCALLS.contains(&SYS_EXEC));
        assert!(PRIMARY_ONLY_SYSCALLS.contains(&SYS_EXIT));

        // Regular syscalls should not be in the list.
        assert!(!PRIMARY_ONLY_SYSCALLS.contains(&SYS_OPEN));
        assert!(!PRIMARY_ONLY_SYSCALLS.contains(&SYS_READ));
        assert!(!PRIMARY_ONLY_SYSCALLS.contains(&SYS_WRITE));
    }

    #[test]
    fn test_clone_cage_state() {
        let mut state = make_state();

        state.record_registration(10, SYS_OPEN, 200);
        state.record_registration(10, SYS_OPEN, 300);
        state.record_registration(10, SYS_WRITE, 200);

        // Clone parent cage 10 to child cage 20.
        state.clone_cage_state(10, 20);

        // Child should have the same routes.
        assert!(state.get_route(20, SYS_OPEN).is_some());
        assert!(state.get_route(20, SYS_WRITE).is_some());
        assert!(state.is_managed(20));
    }

    #[test]
    fn test_remove_cage_state() {
        let mut state = make_state();

        state.record_registration(10, SYS_OPEN, 200);
        assert!(state.is_managed(10));

        state.remove_cage_state(10);
        assert!(!state.is_managed(10));
        assert!(state.get_route(10, SYS_OPEN).is_none());
    }

    #[test]
    fn test_alt_allocation_is_unique() {
        let mut state = make_state();

        let a1 = state.alloc_alt();
        let a2 = state.alloc_alt();
        let a3 = state.alloc_alt();

        assert_ne!(a1, a2);
        assert_ne!(a2, a3);
        assert_eq!(a1, ALT_SYSCALL_BASE);
        assert_eq!(a2, ALT_SYSCALL_BASE + 1);
    }
}
