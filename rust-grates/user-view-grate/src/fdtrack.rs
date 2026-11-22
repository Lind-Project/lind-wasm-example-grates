//! Which descriptors refer to which writable view.
//!
//! A writable view is merged into the real file when the user is done with it, and "done" means
//! the last descriptor for it is gone. Descriptors multiply through `dup`, `fork` and `exec`, so
//! each one is recorded here, per cage, and each view is counted.
//!
//! Read-only views are not tracked: nothing has to happen when they close.

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdEntry {
    pub view: u64,
    pub cloexec: bool,
}

/// A descriptor stopped referring to `view`. `last` is set when it was the final one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Released {
    pub view: u64,
    pub last: bool,
}

#[derive(Default)]
pub struct FdTracker {
    cages: HashMap<u64, HashMap<u64, FdEntry>>,
    refs: HashMap<u64, usize>,
}

impl FdTracker {
    /// No view descriptor is open anywhere.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    pub fn get(&self, cage: u64, fd: u64) -> Option<FdEntry> {
        self.cages.get(&cage)?.get(&fd).copied()
    }

    /// The views `cage` holds a descriptor for, each listed once.
    pub fn views_of(&self, cage: u64) -> Vec<u64> {
        let mut views: Vec<u64> = match self.cages.get(&cage) {
            Some(fds) => fds.values().map(|e| e.view).collect(),
            None => return Vec::new(),
        };
        views.sort_unstable();
        views.dedup();
        views
    }

    /// Record that `fd` in `cage` refers to a view. If `fd` was already recorded it has been
    /// replaced (as by `dup2`), and the old entry is released.
    pub fn insert(&mut self, cage: u64, fd: u64, entry: FdEntry) -> Option<Released> {
        *self.refs.entry(entry.view).or_insert(0) += 1;
        let old = self.cages.entry(cage).or_default().insert(fd, entry);
        old.map(|old| self.release(old.view))
    }

    pub fn remove(&mut self, cage: u64, fd: u64) -> Option<Released> {
        let fds = self.cages.get_mut(&cage)?;
        let old = fds.remove(&fd)?;
        if fds.is_empty() {
            self.cages.remove(&cage);
        }
        Some(self.release(old.view))
    }

    pub fn set_cloexec(&mut self, cage: u64, fd: u64, cloexec: bool) {
        if let Some(entry) = self.cages.get_mut(&cage).and_then(|fds| fds.get_mut(&fd)) {
            entry.cloexec = cloexec;
        }
    }

    /// `child` starts with a copy of `parent`'s descriptors.
    pub fn fork(&mut self, parent: u64, child: u64) {
        let Some(fds) = self.cages.get(&parent).cloned() else {
            return;
        };
        for entry in fds.values() {
            *self.refs.entry(entry.view).or_insert(0) += 1;
        }
        // A cage id is never reused, so `child` has no entries of its own to release.
        self.cages.insert(child, fds);
    }

    /// `cage` is about to exec: its close-on-exec descriptors go away.
    pub fn exec(&mut self, cage: u64) -> Vec<Released> {
        let Some(fds) = self.cages.get_mut(&cage) else {
            return Vec::new();
        };
        let closing: Vec<u64> = fds
            .iter()
            .filter(|(_, e)| e.cloexec)
            .map(|(fd, _)| *fd)
            .collect();
        closing
            .into_iter()
            .filter_map(|fd| self.remove(cage, fd))
            .collect()
    }

    /// `cage` is gone, and all its descriptors with it.
    pub fn exit(&mut self, cage: u64) -> Vec<Released> {
        let Some(fds) = self.cages.remove(&cage) else {
            return Vec::new();
        };
        fds.values().map(|e| self.release(e.view)).collect()
    }

    fn release(&mut self, view: u64) -> Released {
        let count = self
            .refs
            .get_mut(&view)
            .expect("a recorded descriptor's view is counted");
        *count -= 1;
        let last = *count == 0;
        if last {
            self.refs.remove(&view);
        }
        Released { view, last }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(view: u64, cloexec: bool) -> FdEntry {
        FdEntry { view, cloexec }
    }

    #[test]
    fn open_and_close() {
        let mut t = FdTracker::default();
        assert!(t.is_empty());
        assert_eq!(t.insert(1, 3, entry(7, false)), None);
        assert_eq!(t.get(1, 3), Some(entry(7, false)));
        assert_eq!(t.get(1, 4), None);
        assert_eq!(t.get(2, 3), None);
        assert_eq!(
            t.remove(1, 3),
            Some(Released {
                view: 7,
                last: true
            })
        );
        assert_eq!(t.remove(1, 3), None);
        assert!(t.is_empty());
    }

    #[test]
    fn dup_keeps_the_view_until_the_last_close() {
        let mut t = FdTracker::default();
        t.insert(1, 3, entry(7, false));
        t.insert(1, 4, entry(7, false));
        assert!(!t.remove(1, 3).unwrap().last);
        assert!(t.remove(1, 4).unwrap().last);
    }

    #[test]
    fn dup2_over_a_view_descriptor_releases_it() {
        let mut t = FdTracker::default();
        t.insert(1, 3, entry(7, false));
        t.insert(1, 4, entry(8, false));
        // dup2(3, 4): fd 4 now refers to view 7, and view 8 lost its only descriptor.
        assert_eq!(
            t.insert(1, 4, entry(7, false)),
            Some(Released {
                view: 8,
                last: true
            })
        );
        assert_eq!(t.views_of(1), vec![7]);
        // dup2(3, 3) leaves the count where it was.
        assert_eq!(
            t.insert(1, 3, entry(7, false)),
            Some(Released {
                view: 7,
                last: false
            })
        );
        assert!(!t.remove(1, 3).unwrap().last);
        assert!(t.remove(1, 4).unwrap().last);
    }

    #[test]
    fn fork_shares_views_with_the_child() {
        let mut t = FdTracker::default();
        t.insert(1, 3, entry(7, false));
        t.fork(1, 2);
        // The parent closing first does not end the view: the child still has it.
        assert!(!t.remove(1, 3).unwrap().last);
        assert_eq!(
            t.exit(2),
            vec![Released {
                view: 7,
                last: true
            }]
        );
        assert!(t.is_empty());
        // Forking a cage with nothing recorded records nothing.
        t.fork(5, 6);
        assert!(t.is_empty());
    }

    #[test]
    fn exec_drops_only_cloexec_descriptors() {
        let mut t = FdTracker::default();
        t.insert(1, 3, entry(7, true));
        t.insert(1, 4, entry(8, false));
        t.insert(1, 5, entry(9, false));
        t.set_cloexec(1, 5, true);
        let mut gone = t.exec(1);
        gone.sort_by_key(|r| r.view);
        assert_eq!(
            gone,
            vec![
                Released {
                    view: 7,
                    last: true
                },
                Released {
                    view: 9,
                    last: true
                }
            ]
        );
        assert_eq!(t.views_of(1), vec![8]);
    }
}
