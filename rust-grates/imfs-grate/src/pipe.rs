//! Userspace pipes, modeled on ipc-grate.
//!
//! A pipe is a `Pip` node; both ends are IMFS fds whose `perfdinfo` holds the
//! direction and `O_NONBLOCK`. Buffers and refcounts live here, outside the
//! IMFS mutex, so blocking calls and the fdtables close handler never hold it.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use grate_rs::constants::fs::{O_ACCMODE, O_WRONLY};

use crate::imfs::IMFS_FDKIND;

pub const PIPE_CAPACITY: usize = 65536;

/// Missing from grate_rs::constants::fs.
pub const O_NONBLOCK: i32 = 0o4000;

/// A blocked call holds a 3i worker; after this many naps it returns EINTR
/// so the caller retries and the worker is freed.
const MAX_NAPS_PER_CALL: u32 = 50;

const EINTR: i32 = -4;
const EAGAIN: i32 = -11;
const EPIPE: i32 = -32;

/// node index -> live pipe.
static PIPES: Mutex<Option<HashMap<usize, Arc<PipeBuffer>>>> = Mutex::new(None);

/// Fully closed pipe nodes, reclaimed by the next `create_pipe`.
static DEAD_PIPES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Cages that exited before the fork handler built their fd table.
static EARLY_EXITS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

pub struct PipeBuffer {
    buf: Mutex<VecDeque<u8>>,
    read_refs: AtomicU32,
    write_refs: AtomicU32,
}

/// Sleep 1 ms. True if interrupted.
fn nap_signal_aware() -> bool {
    let interrupted = unsafe {
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        libc::nanosleep(&ts, std::ptr::null_mut()) < 0
    };
    if interrupted {
        static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            crate::log!("first interrupted nap: errno {}", errno);
        }
    }
    interrupted
}

pub fn is_write_end(flags: i32) -> bool {
    (flags & O_ACCMODE) == O_WRONLY
}

impl PipeBuffer {
    pub fn new(capacity: usize) -> Self {
        PipeBuffer {
            buf: Mutex::new(VecDeque::with_capacity(capacity)),
            read_refs: AtomicU32::new(1),
            write_refs: AtomicU32::new(1),
        }
    }

    /// Bytes read, 0 at EOF, or -errno.
    pub fn read(&self, dst: &mut [u8], nonblocking: bool) -> i32 {
        if dst.is_empty() {
            return 0;
        }
        let mut naps = 0u32;
        loop {
            {
                let mut b = self.buf.lock().unwrap();
                let n = dst.len().min(b.len());
                if n > 0 {
                    for (i, byte) in b.drain(..n).enumerate() {
                        dst[i] = byte;
                    }
                    return n as i32;
                }
            }
            if self.write_refs.load(Ordering::Acquire) == 0 {
                return 0;
            }
            if nonblocking {
                return EAGAIN;
            }
            naps += 1;
            if nap_signal_aware() || naps >= MAX_NAPS_PER_CALL {
                return EINTR;
            }
        }
    }

    /// Bytes written, or -errno if nothing was written.
    pub fn write(&self, src: &[u8], nonblocking: bool) -> i32 {
        if src.is_empty() {
            return 0;
        }
        let mut written = 0usize;
        let mut naps = 0u32;
        loop {
            if self.read_refs.load(Ordering::Acquire) == 0 {
                return EPIPE;
            }
            {
                let mut b = self.buf.lock().unwrap();
                let space = PIPE_CAPACITY.saturating_sub(b.len());
                let n = space.min(src.len() - written);
                b.extend(&src[written..written + n]);
                written += n;
            }
            if written == src.len() {
                return written as i32;
            }
            if nonblocking {
                return if written > 0 { written as i32 } else { EAGAIN };
            }
            naps += 1;
            if nap_signal_aware() || naps >= MAX_NAPS_PER_CALL {
                return if written > 0 { written as i32 } else { EINTR };
            }
        }
    }

    pub fn refs(&self) -> (u32, u32) {
        (
            self.read_refs.load(Ordering::Acquire),
            self.write_refs.load(Ordering::Acquire),
        )
    }

    pub fn incr_ref(&self, flags: i32) {
        if is_write_end(flags) {
            self.write_refs.fetch_add(1, Ordering::AcqRel);
        } else {
            self.read_refs.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub fn decr_ref(&self, flags: i32) {
        let counter = if is_write_end(flags) {
            &self.write_refs
        } else {
            &self.read_refs
        };
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1));
    }
}

fn with_pipes<R>(f: impl FnOnce(&mut HashMap<usize, Arc<PipeBuffer>>) -> R) -> R {
    let mut guard = PIPES.lock().unwrap();
    f(guard.get_or_insert_with(HashMap::new))
}

pub fn register(node_idx: usize, pipe: Arc<PipeBuffer>) {
    with_pipes(|m| {
        m.insert(node_idx, pipe);
    });
}

pub fn get(node_idx: usize) -> Option<Arc<PipeBuffer>> {
    with_pipes(|m| m.get(&node_idx).cloned())
}

/// The pipe behind `fd` and the end's flags, or None for a non-pipe fd.
pub fn pipe_for_fd(cage_id: u64, fd: u64) -> Option<(Arc<PipeBuffer>, i32)> {
    let entry = fdtables::translate_virtual_fd(cage_id, fd).ok()?;
    if entry.fdkind != IMFS_FDKIND {
        return None;
    }
    let pipe = get(entry.underfd as usize)?;
    Some((pipe, entry.perfdinfo as i32))
}

/// fdtables close handler for IMFS_FDKIND. `remaining` counts fds still on this node.
pub fn on_fd_closed(entry: fdtables::FDTableEntry, remaining: u64) -> Result<(), i32> {
    let node_idx = entry.underfd as usize;
    if let Some(pipe) = get(node_idx) {
        pipe.decr_ref(entry.perfdinfo as i32);
        let (r, w) = pipe.refs();
        crate::log!(
            "pipe close: node {} flags {:#o} remaining-fds {} refs r={} w={}",
            node_idx,
            entry.perfdinfo,
            remaining,
            r,
            w
        );
        if remaining == 0 {
            with_pipes(|m| {
                m.remove(&node_idx);
            });
            DEAD_PIPES.lock().unwrap().push(node_idx);
        }
    }
    Ok(())
}

pub fn add_ref_for_entry(entry: &fdtables::FDTableEntry) {
    if entry.fdkind != IMFS_FDKIND {
        return;
    }
    if let Some(pipe) = get(entry.underfd as usize) {
        pipe.incr_ref(entry.perfdinfo as i32);
    }
}

pub fn note_early_exit(cage_id: u64) {
    EARLY_EXITS.lock().unwrap().push(cage_id);
}

pub fn take_early_exit(cage_id: u64) -> bool {
    let mut v = EARLY_EXITS.lock().unwrap();
    match v.iter().position(|c| *c == cage_id) {
        Some(i) => {
            v.remove(i);
            true
        }
        None => false,
    }
}

pub fn take_dead() -> Vec<usize> {
    std::mem::take(&mut *DEAD_PIPES.lock().unwrap())
}
