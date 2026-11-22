//! Keeping a descriptor number meaning one thing between looking at it and using it.
//!
//! A handler is given a descriptor *number*. To act on it, it first finds out what the number
//! refers to (`fstat`), then forwards the call. A program with a second thread can change what
//! the number refers to in between (`close`, `dup2`), and so aim the call at something else:
//!
//! - a write whose placeholder has just been replaced by the key, at a file it can read back;
//! - a read that was judged to be of an ordinary file, at a connection that carries a key.
//!
//! The gate closes that gap. Calls that use a number register on it; calls that rebind a number
//! (`close`, `dup2`, `dup3`, and `connect`, which changes what a socket is) announce themselves
//! and wait for the registered calls to be done. Everything here is bookkeeping only: the
//! waiting itself is done by the caller, with the state unlocked.

use std::collections::HashMap;

/// (cage, descriptor number).
pub type Key = (u64, u64);

#[derive(Debug, Default, PartialEq)]
struct Slot {
    /// Calls that are finding out what the number refers to.
    deciding: u32,
    /// Writes of a key that are under way.
    writing: u32,
    /// Reads that were found to need nothing done and were forwarded as they came.
    reading: u32,
    /// A call is rebinding the number. One at a time.
    rebinding: bool,
}

/// What a call goes on to do once it knows what its descriptor is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Then {
    /// Nothing that a rebinding call need wait for.
    Nothing,
    /// Write a key to the connection.
    Write,
    /// Read, with no redaction.
    PlainRead,
}

#[derive(Debug, Default)]
pub struct Gate {
    slots: HashMap<Key, Slot>,
}

impl Gate {
    fn update(&mut self, key: Key, f: impl FnOnce(&mut Slot)) {
        // A slot can have been dropped by `forget` under a call that is still running.
        let slot = self.slots.entry(key).or_default();
        f(slot);
        if *slot == Slot::default() {
            self.slots.remove(&key);
        }
    }

    fn count(slot: &mut Slot, then: Then) -> Option<&mut u32> {
        match then {
            Then::Nothing => None,
            Then::Write => Some(&mut slot.writing),
            Then::PlainRead => Some(&mut slot.reading),
        }
    }

    /// A call is about to find out what `key` refers to. False while the number is being
    /// rebound: the caller waits and tries again, or goes ahead without relying on the answer.
    pub fn begin(&mut self, key: Key) -> bool {
        if self.slots.get(&key).is_some_and(|s| s.rebinding) {
            return false;
        }
        self.update(key, |s| s.deciding += 1);
        true
    }

    /// The call that began on `key` knows what it refers to and goes on to do `then`.
    pub fn decided(&mut self, key: Key, then: Then) {
        self.update(key, |s| {
            s.deciding = s.deciding.saturating_sub(1);
            if let Some(n) = Gate::count(s, then) {
                *n += 1;
            }
        });
    }

    /// A read that needs no look at its descriptor (nothing carries a key yet) is under way.
    pub fn begin_plain_read(&mut self, key: Key) -> bool {
        if self.slots.get(&key).is_some_and(|s| s.rebinding) {
            return false;
        }
        self.update(key, |s| s.reading += 1);
        true
    }

    /// What a call went on to do is done.
    pub fn end(&mut self, key: Key, then: Then) {
        self.update(key, |s| {
            if let Some(n) = Gate::count(s, then) {
                *n = n.saturating_sub(1);
            }
        });
    }

    /// A call wants to rebind `key`. True: it is the one doing so, and from now on no call
    /// begins on the number. False: another rebinding is under way, and the caller tries again.
    pub fn rebind_begin(&mut self, key: Key) -> bool {
        if self.slots.get(&key).is_some_and(|s| s.rebinding) {
            return false;
        }
        self.update(key, |s| s.rebinding = true);
        true
    }

    /// Whether the rebinding may go ahead: no call on `key` is between looking and using.
    ///
    /// A plain read that is registered may have reached the kernel long ago and be waiting there
    /// for data, on whatever the number referred to then; rebinding does not disturb it. Or it
    /// may be an instant from getting there. The two cannot be told apart, so the caller waits
    /// for plain reads only for a short while (`patient`), which is ample for the second kind.
    pub fn rebind_ready(&self, key: Key, patient: bool) -> bool {
        self.slots
            .get(&key)
            .is_none_or(|s| s.deciding == 0 && s.writing == 0 && (!patient || s.reading == 0))
    }

    pub fn rebind_end(&mut self, key: Key) {
        self.update(key, |s| s.rebinding = false);
    }

    /// The numbers that have a plain read under way.
    pub fn plain_reads(&self) -> Vec<Key> {
        self.slots
            .iter()
            .filter(|(_, s)| s.reading > 0)
            .map(|(k, _)| *k)
            .collect()
    }

    /// `cage` has exited or become another program: its other threads' calls will not end.
    pub fn forget(&mut self, cage: u64) {
        self.slots.retain(|k, _| k.0 != cage);
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FD: Key = (7, 5);

    #[test]
    fn a_rebinding_waits_for_a_write_of_a_key() {
        let mut gate = Gate::default();
        assert!(gate.begin(FD));
        assert!(gate.rebind_begin(FD));
        assert!(!gate.rebind_ready(FD, true));
        gate.decided(FD, Then::Write);
        // However long it takes.
        assert!(!gate.rebind_ready(FD, true));
        assert!(!gate.rebind_ready(FD, false));
        gate.end(FD, Then::Write);
        assert!(gate.rebind_ready(FD, true));
        gate.rebind_end(FD);
        assert!(gate.is_empty());
    }

    #[test]
    fn nothing_begins_on_a_number_that_is_being_rebound() {
        let mut gate = Gate::default();
        assert!(gate.rebind_begin(FD));
        assert!(gate.rebind_ready(FD, true));
        assert!(!gate.begin(FD));
        assert!(!gate.begin_plain_read(FD));
        // Nor does a second rebinding of it.
        assert!(!gate.rebind_begin(FD));
        // Other numbers, and the same number in another cage, are not held up.
        assert!(gate.begin((7, 6)));
        assert!(gate.begin((8, 5)));
        gate.rebind_end(FD);
        assert!(gate.begin(FD));
        assert!(gate.rebind_begin(FD));
    }

    #[test]
    fn a_rebinding_waits_for_a_plain_read_only_while_patient() {
        let mut gate = Gate::default();
        assert!(gate.begin(FD));
        gate.decided(FD, Then::PlainRead);
        assert_eq!(gate.plain_reads(), [FD]);
        assert!(gate.rebind_begin(FD));
        assert!(!gate.rebind_ready(FD, true));
        assert!(gate.rebind_ready(FD, false));
        gate.rebind_end(FD);
        gate.end(FD, Then::PlainRead);
        assert!(gate.plain_reads().is_empty());
        assert!(gate.is_empty());

        assert!(gate.begin_plain_read(FD));
        assert_eq!(gate.plain_reads(), [FD]);
        gate.end(FD, Then::PlainRead);
        assert!(gate.is_empty());
    }

    #[test]
    fn a_call_that_needs_nothing_holds_nothing_up() {
        let mut gate = Gate::default();
        assert!(gate.begin(FD));
        gate.decided(FD, Then::Nothing);
        gate.end(FD, Then::Nothing);
        assert!(gate.is_empty());
        assert!(gate.rebind_ready(FD, true));
    }

    #[test]
    fn a_cage_that_is_gone_holds_nothing_up() {
        let mut gate = Gate::default();
        assert!(gate.begin(FD));
        gate.decided(FD, Then::Write);
        assert!(gate.begin((8, 5)));
        gate.forget(7);
        assert!(gate.rebind_ready(FD, true));
        // A call of the forgotten cage that ends after all does no harm.
        gate.end(FD, Then::Write);
        assert!(gate.rebind_ready(FD, true));
        assert!(!gate.is_empty());
        gate.decided((8, 5), Then::Nothing);
        assert!(gate.is_empty());
    }
}
