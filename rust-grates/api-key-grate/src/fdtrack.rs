//! Which descriptors refer to which key-carrying connection, to know when a connection is gone.
//!
//! Whether a call is on such a connection is decided by looking at the socket itself, never by
//! this table. The table only counts the descriptors a connection has, across `dup` and `fork`,
//! so that the grate can forget a connection when the last one is closed. Erring towards
//! remembering one too long costs a little memory; forgetting one early would stop redacting
//! what it receives, so entries are only dropped on a `close`, a `dup2` over them, or an exit.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct FdTracker {
    /// cage -> descriptor -> connection
    cages: HashMap<u64, HashMap<u64, u64>>,
    /// connection -> number of descriptors (and pins) referring to it
    refs: HashMap<u64, usize>,
}

impl FdTracker {
    #[cfg(test)]
    pub fn get(&self, cage: u64, fd: u64) -> Option<u64> {
        self.cages.get(&cage)?.get(&fd).copied()
    }

    /// The descriptors `cage` has on connections.
    pub fn of(&self, cage: u64) -> Vec<(u64, u64)> {
        self.cages
            .get(&cage)
            .map(|fds| fds.iter().map(|(fd, conn)| (*fd, *conn)).collect())
            .unwrap_or_default()
    }

    /// Keep `conn` alive while a call that is about to give it another descriptor is under way.
    pub fn pin(&mut self, conn: u64) {
        *self.refs.entry(conn).or_default() += 1;
    }

    /// Drop a pin. True if nothing refers to `conn` any more.
    pub fn unpin(&mut self, conn: u64) -> bool {
        let Some(count) = self.refs.get_mut(&conn) else {
            return false;
        };
        *count -= 1;
        if *count == 0 {
            self.refs.remove(&conn);
            return true;
        }
        false
    }

    /// `fd` in `cage` now refers to `conn`. Returns the connection it referred to before, if
    /// that one now has no descriptor left.
    pub fn insert(&mut self, cage: u64, fd: u64, conn: u64) -> Option<u64> {
        self.pin(conn);
        let old = self.cages.entry(cage).or_default().insert(fd, conn)?;
        self.unpin(old).then_some(old)
    }

    /// `fd` in `cage` is closed. Returns its connection if that now has no descriptor left.
    pub fn remove(&mut self, cage: u64, fd: u64) -> Option<u64> {
        let fds = self.cages.get_mut(&cage)?;
        let conn = fds.remove(&fd)?;
        if fds.is_empty() {
            self.cages.remove(&cage);
        }
        self.unpin(conn).then_some(conn)
    }

    /// `cage` is gone. Returns the connections that now have no descriptor left.
    pub fn exit(&mut self, cage: u64) -> Vec<u64> {
        let fds = self.cages.remove(&cage).unwrap_or_default();
        fds.into_values().filter(|conn| self.unpin(*conn)).collect()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.cages.is_empty() && self.refs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_lasts_until_its_last_descriptor() {
        let mut t = FdTracker::default();
        assert_eq!(t.insert(1, 5, 100), None);
        assert_eq!(t.insert(1, 6, 100), None);
        assert_eq!(t.get(1, 5), Some(100));
        assert_eq!(t.get(1, 7), None);
        assert_eq!(t.remove(1, 5), None);
        assert_eq!(t.remove(1, 5), None);
        assert_eq!(t.remove(1, 6), Some(100));
        assert!(t.is_empty());
    }

    #[test]
    fn a_descriptor_given_another_connection_lets_go_of_the_first() {
        let mut t = FdTracker::default();
        t.insert(1, 5, 100);
        assert_eq!(t.insert(1, 5, 200), Some(100));
        assert_eq!(t.insert(1, 5, 200), None);
        assert_eq!(t.remove(1, 5), Some(200));
        assert!(t.is_empty());
    }

    #[test]
    fn a_fork_and_an_exit() {
        let mut t = FdTracker::default();
        t.insert(1, 5, 100);
        t.insert(1, 9, 200);
        // What the clone handler does: pin, copy, unpin.
        let held = t.of(1);
        for (_, conn) in &held {
            t.pin(*conn);
        }
        for (fd, conn) in &held {
            t.insert(2, *fd, *conn);
        }
        for (_, conn) in &held {
            assert!(!t.unpin(*conn));
        }
        assert_eq!(t.get(2, 9), Some(200));

        assert!(t.exit(1).is_empty());
        assert_eq!(t.remove(2, 5), Some(100));
        assert_eq!(t.exit(2), [200]);
        assert!(t.exit(3).is_empty());
        assert!(t.is_empty());
    }

    #[test]
    fn a_pin_keeps_a_connection_through_a_close() {
        let mut t = FdTracker::default();
        t.insert(1, 5, 100);
        t.pin(100);
        // Another thread closes the descriptor while a dup of it is under way.
        assert_eq!(t.remove(1, 5), None);
        assert_eq!(t.insert(1, 6, 100), None);
        assert!(!t.unpin(100));
        assert_eq!(t.remove(1, 6), Some(100));
        // A pin on something unknown is dropped quietly.
        assert!(!t.unpin(999));
        assert!(t.is_empty());
    }
}
