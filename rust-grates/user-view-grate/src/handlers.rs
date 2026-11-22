//! The syscall handlers.
//!
//! **Which file is protected.** A rule names a path, but a call is matched by the file it reaches
//! (device and inode), not by the text of its path. A symlink, a hard link, a relative path or
//! `..` therefore lead to the same view. The file a rule's path names is looked up again on every
//! call that could reach it, and files it named earlier stay protected, so rotating a log or
//! moving its directory does not open a way around the rule.
//!
//! **Opening.** When a cage opens a protected file and its user has a view, the grate renders the
//! view into a fresh unlinked file and opens *that* for the cage. From then on `read`, `lseek`,
//! `mmap`, `fstat` and the rest work on the view directly and are not intercepted. The real file
//! is never open in the cage.
//!
//! **Writing.** A writable view is merged into the real file when a descriptor for it is closed
//! or synced, and when the cage holding it execs or exits. The merge only ever replaces lines
//! the user could see, with lines the user could see (`view.rs`).

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::is_thread_clone;

use crate::fdtrack::{FdEntry, FdTracker, Released};
use crate::policy::{Grant, Identity, Policy};
use crate::sys::{self, Arg, EACCES, EEXIST, EIO, ENOTDIR, EPERM, FileId, OwnFd, Stat};
use crate::view::{CompiledView, MergeError};

const O_ACCMODE: u64 = 0o3;
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;
const O_CLOEXEC: u64 = 0o2000000;
const F_DUPFD: u64 = 0;
const F_SETFD: u64 = 2;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FD_CLOEXEC: u64 = 1;

/// How many files a rule's path is remembered to have named.
const MAX_KNOWN: usize = 8;
/// How many exited cages are remembered (see `clone_handler`).
const MAX_GONE: usize = 1024;

/// A writable view some cage has open.
struct LiveView {
    rule: usize,
    who: String,
    view: Arc<CompiledView>,
    /// The grate's own descriptor for the file the cage reads and writes.
    backing: OwnFd,
    /// The user's view of the real file when it was last read or merged. The backing file
    /// differing from this is what "the user changed something" means.
    synced: Vec<u8>,
}

/// What a user gets for a file.
enum Access {
    Raw,
    Deny,
    View(Arc<CompiledView>, String),
}

struct State {
    policy: Policy,
    fixed_user: Option<Identity>,
    tmpdir: String,
    /// Each rule's path, as a C string.
    paths: Vec<CString>,
    /// Each rule's protected files: every file its path has been seen to name.
    known: Vec<VecDeque<FileId>>,
    compiled: HashMap<(usize, usize, Identity), Arc<CompiledView>>,
    fds: FdTracker,
    views: HashMap<u64, LiveView>,
    next_view: u64,
    gone: VecDeque<u64>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
/// Whether the policy protects any file. When it does not, every call is forwarded untouched.
static HAS_RULES: AtomicBool = AtomicBool::new(false);

fn has_rules() -> bool {
    HAS_RULES.load(Ordering::Relaxed)
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.as_mut().expect("handlers run after init"))
}

pub fn init(policy: Policy, fixed_user: Option<Identity>, tmpdir: String) {
    sys::me();
    let paths = policy
        .files
        .iter()
        .map(|f| CString::new(f.path.as_str()).expect("a policy line has no NUL"))
        .collect();
    let mut state = State {
        known: vec![VecDeque::new(); policy.files.len()],
        policy,
        fixed_user,
        tmpdir,
        paths,
        compiled: HashMap::new(),
        fds: FdTracker::default(),
        views: HashMap::new(),
        next_view: 1,
        gone: VecDeque::new(),
    };
    state.refresh();
    HAS_RULES.store(!state.paths.is_empty(), Ordering::Relaxed);
    *STATE.lock().unwrap() = Some(state);
}

/// Merge every view that is still open. Called when the grate shuts down.
pub fn commit_all() {
    with(|st| {
        let ids: Vec<u64> = st.views.keys().copied().collect();
        for id in ids {
            let _ = st.sync(id);
        }
        st.views.clear();
    });
}

impl State {
    /// Note which file each rule's path names now.
    fn refresh(&mut self) {
        for (path, known) in self.paths.iter().zip(&mut self.known) {
            let Ok(st) = sys::stat_path(sys::me(), Arg::Mine(path.as_ptr() as u64), true) else {
                continue;
            };
            if st.regular && !known.contains(&st.id) {
                if known.len() == MAX_KNOWN {
                    known.pop_front();
                }
                known.push_back(st.id);
            }
        }
    }

    /// The rule protecting the file a call reached, if any.
    fn rule_for(&self, found: &Result<Stat, i64>) -> Option<(usize, FileId)> {
        let st = found.as_ref().ok().filter(|st| st.regular)?;
        let rule = self.known.iter().position(|ids| ids.contains(&st.id))?;
        Some((rule, st.id))
    }

    fn identity(&self, cage: u64) -> Result<Identity, i64> {
        match &self.fixed_user {
            Some(who) => Ok(who.clone()),
            None => Ok(self.policy.identity_for_uid(sys::geteuid(cage)?)),
        }
    }

    /// What `cage`'s user gets for the file of `rule`. Any doubt is a denial.
    fn access(&mut self, rule: usize, cage: u64) -> Access {
        let Ok(who) = self.identity(cage) else {
            return Access::Deny;
        };
        let file = &self.policy.files[rule];
        let (block, grant) = file.grant_for(&who);
        let spec = match grant {
            Grant::Raw => return Access::Raw,
            Grant::Deny => return Access::Deny,
            Grant::View(spec) => spec,
        };
        let key = (rule, block, who);
        if let Some(view) = self.compiled.get(&key) {
            return Access::View(view.clone(), key.2.name);
        }
        match spec.compile(&key.2) {
            Ok(view) => {
                let view = Arc::new(view);
                let name = key.2.name.clone();
                self.compiled.insert(key, view.clone());
                Access::View(view, name)
            }
            Err(e) => {
                eprintln!("user-view-grate: {}: user {}: {e}", file.path, key.2.name);
                Access::Deny
            }
        }
    }

    /// The real file of `rule`, provided its path still names `id`, the file the call reached.
    fn read_real(&self, rule: usize, id: FileId) -> Result<Vec<u8>, i64> {
        let path = &self.policy.files[rule].path;
        let real = OwnFd::open(path, O_RDONLY as i32, 0).map_err(|_| -EACCES)?;
        // The call may have reached a file the path named earlier. Its content cannot be read by
        // path any more, and the user is not handed some other file's view in its place.
        if real.stat().map_err(|_| -EACCES)?.id != id {
            return Err(-EACCES);
        }
        real.read_all()
    }

    /// Open the user's view of `rule`'s file for `cage`. Returns the cage's new descriptor.
    fn serve(
        &mut self,
        cage: u64,
        rule: usize,
        id: FileId,
        view: Arc<CompiledView>,
        who: String,
        flags: u64,
    ) -> i64 {
        let writing = flags & O_ACCMODE != O_RDONLY;
        if (writing || flags & (O_TRUNC | O_APPEND) != 0) && !view.writable {
            return -EACCES;
        }
        if flags & O_DIRECTORY != 0 {
            return -ENOTDIR;
        }
        if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            return -EEXIST;
        }

        let synced = match self.read_real(rule, id) {
            Ok(raw) => view.render(&raw),
            Err(e) => return e,
        };
        // A view opened with O_TRUNC starts empty, as the file would.
        let initial: &[u8] = if flags & O_TRUNC != 0 { &[] } else { &synced };

        let name = match sys::random_name() {
            Ok(random) => format!("{}/.user-view-{random}", self.tmpdir),
            Err(e) => return e,
        };
        let Ok(c_name) = CString::new(name.as_str()) else {
            return -EIO;
        };
        let backing = match OwnFd::open(&name, (O_RDWR | O_CREAT | O_EXCL) as i32, 0o600) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("user-view-grate: cannot create a view file in {}", self.tmpdir);
                return e;
            }
        };
        let fd = match backing.write_all(initial) {
            // The cage's own open, with its access mode and status flags, of the view.
            Ok(()) => sys::call(
                cage,
                SYS_OPEN,
                &[
                    Arg::Mine(c_name.as_ptr() as u64),
                    Arg::Val(flags & !(O_CREAT | O_EXCL | O_TRUNC | sys::O_NOFOLLOW)),
                    Arg::Val(0),
                ],
            ),
            Err(e) => e,
        };
        // The name exists only long enough for the cage's open.
        sys::unlink(&name);
        if fd < 0 || !writing {
            // A read-only view needs nothing further: `backing` closes here.
            return fd;
        }

        let view_id = self.next_view;
        self.next_view += 1;
        self.views.insert(
            view_id,
            LiveView {
                rule,
                who,
                view,
                backing,
                synced,
            },
        );
        self.track(
            cage,
            fd as u64,
            FdEntry {
                view: view_id,
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
        fd
    }

    /// Merge what the user changed in a view into the real file. Nothing changed, nothing done.
    fn sync(&mut self, view_id: u64) -> Result<(), i64> {
        let Some(live) = self.views.get_mut(&view_id) else {
            return Ok(());
        };
        let edited = live.backing.read_all()?;
        if edited == live.synced {
            return Ok(());
        }

        let path = &self.policy.files[live.rule].path;
        let real = OwnFd::open(path, O_RDWR as i32, 0)?;
        real.lock(true);
        let result = real.read_all().and_then(|raw| {
            match live.view.merge(&raw, &edited) {
                Ok(merged) => real.write_all(&merged),
                Err(MergeError::NotOwnLine { line }) => {
                    eprintln!(
                        "user-view-grate: {path}: edit by {} not applied: line {line} is not one of their lines",
                        live.who
                    );
                    Err(-EPERM)
                }
            }
        });
        real.lock(false);
        result?;
        live.synced = edited;
        Ok(())
    }

    fn track(&mut self, cage: u64, fd: u64, entry: FdEntry) {
        if let Some(old) = self.fds.insert(cage, fd, entry) {
            self.release(old);
        }
    }

    /// A descriptor for a view is gone. After the last one the view is merged and forgotten.
    fn release(&mut self, released: Released) {
        if released.last {
            let _ = self.sync(released.view);
            self.views.remove(&released.view);
        }
    }

    /// Whether `cage`'s user is kept from changing the file a path names: true when the file is
    /// protected and the user does not have it raw.
    fn guards(&mut self, cage: u64, found: &Result<Stat, i64>) -> bool {
        match self.rule_for(found) {
            Some((rule, _)) => !matches!(self.access(rule, cage), Access::Raw),
            None => false,
        }
    }
}

/// The arguments of an intercepted call.
struct Call {
    args: [(u64, u64); 6],
}

impl Call {
    fn val(&self, i: usize) -> u64 {
        self.args[i].0
    }

    fn arg(&self, i: usize) -> Arg {
        Arg::From(self.args[i].0, self.args[i].1)
    }

    /// The cage that made the call: the cage half of its first argument. When that argument is a
    /// pointer some grate above supplied from its own memory, the second argument's is used.
    fn cage(&self) -> u64 {
        let first = self.args[0].1;
        if first & GRATE_MEMORY_FLAG != 0 {
            self.args[1].1
        } else {
            first
        }
    }

    fn forward(&self, nr: u64) -> i64 {
        self.forward_args(nr, &self.args)
    }

    fn forward_args(&self, nr: u64, args: &[(u64, u64); 6]) -> i64 {
        let args = args.map(|(v, cage)| Arg::From(v, cage));
        sys::call(self.cage(), nr, &args)
    }
}

macro_rules! handler {
    ($name:ident, |$call:ident| $body:expr) => {
        pub extern "C" fn $name(
            _grate: u64,
            a1: u64,
            c1: u64,
            a2: u64,
            c2: u64,
            a3: u64,
            c3: u64,
            a4: u64,
            c4: u64,
            a5: u64,
            c5: u64,
            a6: u64,
            c6: u64,
        ) -> i64 {
            let $call = Call {
                args: [(a1, c1), (a2, c2), (a3, c3), (a4, c4), (a5, c5), (a6, c6)],
            };
            $body
        }
    };
}

/// What to do with an open once its path has been looked at.
enum Step {
    Return(i64),
    /// Forward the call as it came.
    Forward,
    /// Forward it, then look at what it opened.
    Check,
}

/// `open` (`at` false: path, flags, mode) and `openat` (`at` true: dirfd, path, flags, mode).
fn open(call: &Call, at: bool) -> i64 {
    let nr = if at { SYS_OPENAT } else { SYS_OPEN };
    if !has_rules() {
        return call.forward(nr);
    }
    let flags_at = if at { 2 } else { 1 };
    let flags = call.val(flags_at);
    let cage = call.cage();

    // What the path names now, links followed, as the open itself would resolve it.
    let before = if at {
        sys::stat_at(cage, call.arg(0), call.arg(1), true)
    } else {
        sys::stat_path(cage, call.arg(0), true)
    };
    // The state is not held across a forwarded open, which may block (a FIFO, say).
    let step = with(|st| {
        st.refresh();
        let Some((rule, id)) = st.rule_for(&before) else {
            return Step::Check;
        };
        match st.access(rule, cage) {
            Access::Raw => Step::Forward,
            Access::Deny => Step::Return(-EACCES),
            Access::View(view, who) => Step::Return(st.serve(cage, rule, id, view, who, flags)),
        }
    });
    match step {
        Step::Return(ret) => return ret,
        Step::Forward => return call.forward(nr),
        Step::Check => {}
    }

    // Not a protected file as far as its path showed. The path can be made to name one between
    // that look and the open, so the open is not allowed to truncate, and what it opened is
    // looked at again.
    let mut args = call.args;
    args[flags_at].0 = flags & !O_TRUNC;
    let fd = call.forward_args(nr, &args);
    if fd < 0 {
        return fd;
    }
    let after = sys::fstat(cage, fd as u64);
    if !matches!(&after, Ok(st) if st.regular) {
        return fd;
    }
    let served = with(|st| {
        if before.is_err() {
            // The open may have created the file a rule names.
            st.refresh();
        }
        let (rule, id) = st.rule_for(&after)?;
        match st.access(rule, cage) {
            Access::Raw => None,
            Access::Deny => {
                sys::close(cage, fd as u64);
                Some(-EACCES)
            }
            Access::View(view, who) => {
                sys::close(cage, fd as u64);
                // O_CREAT and O_EXCL were satisfied by the open that just happened.
                Some(st.serve(cage, rule, id, view, who, flags & !(O_CREAT | O_EXCL)))
            }
        }
    });
    if let Some(ret) = served {
        return ret;
    }
    if flags & O_TRUNC != 0 && flags & O_ACCMODE != O_RDONLY {
        sys::call(cage, SYS_FTRUNCATE, &[Arg::Val(fd as u64), Arg::Val(0)]);
    }
    fd
}

handler!(open_handler, |call| open(&call, false));
handler!(openat_handler, |call| open(&call, true));

handler!(close_handler, |call| {
    let (cage, fd) = (call.cage(), call.val(0));
    let merged = with(|st| {
        let Some(entry) = st.fds.get(cage, fd) else {
            return Ok(());
        };
        let merged = st.sync(entry.view);
        if let Some(Released { view, last: true }) = st.fds.remove(cage, fd) {
            st.views.remove(&view);
        }
        merged
    });
    let ret = call.forward(SYS_CLOSE);
    // An edit that could not be applied is reported by the close that would have applied it.
    match merged {
        Err(e) if ret >= 0 => e,
        _ => ret,
    }
});

fn sync_then_forward(call: &Call, nr: u64) -> i64 {
    let (cage, fd) = (call.cage(), call.val(0));
    let merged = with(|st| match st.fds.get(cage, fd) {
        Some(entry) => st.sync(entry.view),
        None => Ok(()),
    });
    match merged {
        Ok(()) => call.forward(nr),
        Err(e) => e,
    }
}

handler!(fsync_handler, |call| sync_then_forward(&call, SYS_FSYNC));
handler!(fdatasync_handler, |call| sync_then_forward(
    &call,
    SYS_FDATASYNC
));

handler!(dup_handler, |call| {
    let ret = call.forward(SYS_DUP);
    if ret >= 0 {
        let (cage, old) = (call.cage(), call.val(0));
        with(|st| {
            if let Some(entry) = st.fds.get(cage, old) {
                st.track(
                    cage,
                    ret as u64,
                    FdEntry {
                        view: entry.view,
                        cloexec: false,
                    },
                );
            }
        });
    }
    ret
});

/// `dup2` and `dup3`: `new` is closed, then made a copy of `old`.
fn dup_onto(call: &Call, nr: u64, cloexec: bool) -> i64 {
    let (cage, old, new) = (call.cage(), call.val(0), call.val(1));
    if old != new {
        with(|st| {
            if let Some(entry) = st.fds.get(cage, new) {
                let _ = st.sync(entry.view);
            }
        });
    }
    let ret = call.forward(nr);
    if ret >= 0 && old != new {
        with(|st| match st.fds.get(cage, old) {
            Some(entry) => st.track(
                cage,
                new,
                FdEntry {
                    view: entry.view,
                    cloexec,
                },
            ),
            None => {
                if let Some(released) = st.fds.remove(cage, new) {
                    st.release(released);
                }
            }
        });
    }
    ret
}

handler!(dup2_handler, |call| dup_onto(&call, SYS_DUP2, false));
handler!(dup3_handler, |call| {
    let cloexec = call.val(2) & O_CLOEXEC != 0;
    dup_onto(&call, SYS_DUP3, cloexec)
});

handler!(fcntl_handler, |call| {
    let ret = call.forward(SYS_FCNTL);
    let cmd = call.val(1);
    if ret >= 0 && matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC | F_SETFD) {
        let (cage, fd) = (call.cage(), call.val(0));
        with(|st| {
            let Some(entry) = st.fds.get(cage, fd) else {
                return;
            };
            if cmd == F_SETFD {
                st.fds.set_cloexec(cage, fd, call.val(2) & FD_CLOEXEC != 0);
            } else {
                st.track(
                    cage,
                    ret as u64,
                    FdEntry {
                        view: entry.view,
                        cloexec: cmd == F_DUPFD_CLOEXEC,
                    },
                );
            }
        });
    }
    ret
});

handler!(clone_handler, |call| {
    let ret = call.forward(SYS_CLONE);
    if ret > 0 && !is_thread_clone(call.val(0), call.args[0].1) {
        let (parent, child) = (call.cage(), ret as u64);
        with(|st| {
            // The child may already have run and exited. Its descriptors are then not recorded,
            // for there will be no exit to forget them at.
            if !st.gone.contains(&child) {
                st.fds.fork(parent, child);
            }
        });
    }
    ret
});

handler!(execve_handler, |call| {
    let cage = call.cage();
    with(|st| {
        for released in st.fds.exec(cage) {
            st.release(released);
        }
    });
    call.forward(SYS_EXECVE)
});

// One thread leaves. The cage keeps its descriptors, but what it wrote so far is merged.
handler!(exit_handler, |call| {
    let cage = call.cage();
    with(|st| {
        for view in st.fds.views_of(cage) {
            let _ = st.sync(view);
        }
    });
    call.forward(SYS_EXIT)
});

handler!(exit_group_handler, |call| {
    let cage = call.cage();
    with(|st| {
        // Merged now even if another cage still holds the view and would merge it later.
        for view in st.fds.views_of(cage) {
            let _ = st.sync(view);
        }
        for released in st.fds.exit(cage) {
            st.release(released);
        }
        if st.gone.len() == MAX_GONE {
            st.gone.pop_front();
        }
        st.gone.push_back(cage);
    });
    call.forward(SYS_EXIT_GROUP)
});

/// Forward a call that changes the files its paths name, unless one of them is protected from
/// this cage's user. `find` looks the paths up, without following a final symlink where the
/// call itself would not.
fn forward_unless_guarded<const N: usize>(
    call: &Call,
    nr: u64,
    find: impl FnOnce(u64) -> [Result<Stat, i64>; N],
) -> i64 {
    if !has_rules() {
        return call.forward(nr);
    }
    let cage = call.cage();
    let found = find(cage);
    let guarded = with(|st| {
        st.refresh();
        found.iter().any(|f| st.guards(cage, f))
    });
    if guarded { -EACCES } else { call.forward(nr) }
}

// A view is the only way a user without raw access changes a protected file. They cannot cut it
// short, remove it, move it away or put another file in its place.

handler!(truncate_handler, |call| {
    forward_unless_guarded(&call, SYS_TRUNCATE, |cage| {
        [sys::stat_path(cage, call.arg(0), true)]
    })
});

handler!(unlink_handler, |call| {
    forward_unless_guarded(&call, SYS_UNLINK, |cage| {
        [sys::stat_path(cage, call.arg(0), false)]
    })
});

handler!(unlinkat_handler, |call| {
    forward_unless_guarded(&call, SYS_UNLINKAT, |cage| {
        [sys::stat_at(cage, call.arg(0), call.arg(1), false)]
    })
});

handler!(rename_handler, |call| {
    forward_unless_guarded(&call, SYS_RENAME, |cage| {
        [
            sys::stat_path(cage, call.arg(0), false),
            sys::stat_path(cage, call.arg(1), false),
        ]
    })
});

fn rename_at(call: &Call, nr: u64) -> i64 {
    forward_unless_guarded(call, nr, |cage| {
        [
            sys::stat_at(cage, call.arg(0), call.arg(1), false),
            sys::stat_at(cage, call.arg(2), call.arg(3), false),
        ]
    })
}

handler!(renameat_handler, |call| rename_at(&call, SYS_RENAMEAT));
handler!(renameat2_handler, |call| rename_at(&call, SYS_RENAMEAT2));
