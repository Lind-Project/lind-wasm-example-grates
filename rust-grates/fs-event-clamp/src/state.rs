//! Bookkeeping for fs-event-clamp.
//!
//! The clamp records every handler registration made inside its `%{ ... %}` block and the
//! fork tree of those cages. When the program cage reaches `%}`, the registrations it would have
//! inherited from the clamped grates are resolved into a pending handler set. The set is
//! installed on the cage once it opens a matching path.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, OnceLock};

use regex::bytes::Regex;

/// 3i's `handlefunccage` sentinel for removing a `(cage, syscall)` entry.
pub const THREEI_DEREGISTER: u64 = 500;

/// syscall_nr -> (grate_id, handler_fn_ptr)
pub type HandlerSet = HashMap<u64, (u64, u64)>;

#[derive(Default)]
pub struct State {
    /// Nesting depth of `%{ ... %}` blocks seen in exec chains; our own block is depth 1.
    depth: usize,
    /// Registrations made by the clamped grates, keyed by the cage they target.
    registrations: HashMap<u64, HandlerSet>,
    /// child cage -> parent cage, for cages forked inside the clamp.
    parents: HashMap<u64, u64>,
    /// Program cages that have not opened a matching path yet, with their deferred handlers.
    pending: HashMap<u64, HandlerSet>,
    /// Program cages whose syscalls are routed to the clamped grates.
    audited: HashSet<u64>,
}

static NS_CAGE: OnceLock<u64> = OnceLock::new();
static REGEX: OnceLock<Regex> = OnceLock::new();
static STATE: Mutex<Option<State>> = Mutex::new(None);

pub fn init(ns_cage: u64, regex: Regex) {
    NS_CAGE.set(ns_cage).unwrap();
    REGEX.set(regex).unwrap();
    *STATE.lock().unwrap() = Some(State::new());
}

pub fn ns_cage() -> u64 {
    *NS_CAGE.get().unwrap()
}

pub fn regex() -> &'static Regex {
    REGEX.get().unwrap()
}

/// Lock the global state. Never hold the guard across a 3i call: handlers can be re-entered.
pub fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard: MutexGuard<Option<State>> = STATE.lock().unwrap();
    f(guard.as_mut().unwrap())
}

fn apply(set: &mut HandlerSet, nr: u64, grate_id: u64, handler_fn: u64) {
    if grate_id == THREEI_DEREGISTER {
        set.remove(&nr);
    } else {
        set.insert(nr, (grate_id, handler_fn));
    }
}

impl State {
    pub fn new() -> Self {
        State {
            depth: 1,
            ..Default::default()
        }
    }

    pub fn enter_block(&mut self) {
        self.depth += 1;
    }

    /// Returns true when the `%}` closes our own block (i.e. the cage is the program).
    pub fn exit_block(&mut self) -> bool {
        self.depth = self.depth.saturating_sub(1);
        self.depth == 0
    }

    pub fn is_program(&self, cage: u64) -> bool {
        self.pending.contains_key(&cage) || self.audited.contains(&cage)
    }

    pub fn is_pending(&self, cage: u64) -> bool {
        self.pending.contains_key(&cage)
    }

    #[cfg(test)]
    pub fn is_audited(&self, cage: u64) -> bool {
        self.audited.contains(&cage)
    }

    /// Record a register_handler call. Returns true if it was deferred (not to be forwarded yet).
    pub fn record_registration(&mut self, target: u64, nr: u64, grate_id: u64, fn_ptr: u64) -> bool {
        if let Some(set) = self.pending.get_mut(&target) {
            apply(set, nr, grate_id, fn_ptr);
            return true;
        }
        if !self.audited.contains(&target) {
            apply(self.registrations.entry(target).or_default(), nr, grate_id, fn_ptr);
        }
        false
    }

    /// The handlers `cage` would have inherited from the clamped grates: its own registrations
    /// overriding those of its ancestors, mirroring 3i's handler-table inheritance on fork.
    fn inherited_handlers(&self, cage: u64) -> HandlerSet {
        let mut chain = vec![cage];
        while let Some(&parent) = self.parents.get(chain.last().unwrap()) {
            if chain.contains(&parent) {
                break;
            }
            chain.push(parent);
        }
        let mut set = HandlerSet::new();
        for cage in chain.iter().rev() {
            if let Some(regs) = self.registrations.get(cage) {
                set.extend(regs);
            }
        }
        set
    }

    /// The cage crossed `%}`: defer everything it inherited from the clamped grates.
    pub fn start_program(&mut self, cage: u64) {
        let handlers = self.inherited_handlers(cage);
        self.registrations.remove(&cage);
        self.pending.insert(cage, handlers);
    }

    /// If `cage` is pending and `path` matches, mark it audited and return the handlers to
    /// install.
    pub fn take_activation(&mut self, cage: u64, path: &[u8], regex: &Regex) -> Option<HandlerSet> {
        if !self.pending.contains_key(&cage) || !regex.is_match(path) {
            return None;
        }
        self.audited.insert(cage);
        self.pending.remove(&cage)
    }

    pub fn on_fork(&mut self, parent: u64, child: u64) {
        if let Some(set) = self.pending.get(&parent) {
            let set = set.clone();
            self.pending.insert(child, set);
        } else if self.audited.contains(&parent) {
            self.audited.insert(child);
        } else {
            self.parents.insert(child, parent);
        }
    }

    pub fn on_exit(&mut self, cage: u64) {
        self.registrations.remove(&cage);
        self.pending.remove(&cage);
        self.audited.remove(&cage);
        self.parents.remove(&cage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u64 = 10;
    const B: u64 = 11;
    const P: u64 = 12;

    fn regex() -> Regex {
        Regex::new("secret$").unwrap()
    }

    /// `%{ A B %} P`: A registers on B's cage, B registers on P before P crosses `%}`.
    fn stacked() -> State {
        let mut s = State::new();
        s.on_fork(A, B);
        assert!(!s.record_registration(B, 0, A, 100));
        assert!(!s.record_registration(B, 1, A, 101));
        s.on_fork(B, P);
        assert!(!s.record_registration(P, 1, B, 201));
        assert!(!s.record_registration(P, 107, B, 207));
        s
    }

    #[test]
    fn program_inherits_registrations_through_the_clamped_stack() {
        let mut s = stacked();
        s.start_program(P);
        let want = HandlerSet::from([(0, (A, 100)), (1, (B, 201)), (107, (B, 207))]);
        assert_eq!(s.pending[&P], want);
    }

    #[test]
    fn activation_is_sticky_matching_and_inherited() {
        let mut s = stacked();
        s.start_program(P);
        // Late registration while pending is deferred, and deregistration is honoured.
        assert!(s.record_registration(P, 2048, B, 300));
        assert!(s.record_registration(P, 107, THREEI_DEREGISTER, 0));
        s.on_fork(P, 20);

        assert!(s.take_activation(P, b"/tmp/public", &regex()).is_none());
        let handlers = s.take_activation(P, b"/tmp/secret", &regex()).unwrap();
        assert_eq!(handlers.get(&2048), Some(&(B, 300)));
        assert!(!handlers.contains_key(&107));
        assert!(s.is_audited(P) && s.take_activation(P, b"/tmp/secret", &regex()).is_none());

        // Registrations on audited cages are forwarded immediately.
        assert!(!s.record_registration(P, 2049, B, 301));
        // A child forked before activation still has its own pending set; one forked after
        // activation is audited.
        assert!(s.is_pending(20) && !s.is_audited(20));
        s.on_fork(P, 21);
        assert!(s.is_audited(21));

        s.on_exit(P);
        assert!(!s.is_program(P) && s.is_program(20) && s.is_program(21));
    }
}
