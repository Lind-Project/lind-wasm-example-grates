//! IPC grate core — pipe management and fd lifecycle.
//!
//! Manages a global registry of userspace pipes. Each pipe() or pipe2() call
//! allocates a PipeBuffer and registers both endpoints in fdtables.
//!
//! fdtables usage:
//!   - fdkind = IPC_PIPE (1) for pipe endpoints, IPC_SOCKET (3) for sockets
//!   - underfd = pipe_id (index into PIPES registry) or socket_id
//!   - perfdinfo = open flags (O_RDONLY/O_WRONLY tells us which end)
//!
//! For fds that are NOT ours (fdtables lookup fails or fdkind == 0),
//! handlers forward to make_syscall — ipc-grate is transparent to non-pipe traffic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::ffi::{sem_t, sem_init, sem_wait, sem_post, sem_destroy, mmap, munmap};
use grate_rs::constants::mman::*;
use core::ffi::c_void;

/// Shared-memory semaphore used as a fork gate.
///
/// std::sync::Mutex does NOT synchronize across Lind runtime threads (each
/// forked cage runs on its own runtime thread).  POSIX semaphores on
/// mmap(MAP_SHARED) memory DO work because the memory is physically shared.
///
/// The semaphore is allocated once in `init_fork_sem()` and its address stored
/// here.  Value 0 means a fork is in progress (child blocks); value 1 means
/// idle (child proceeds immediately).
static FORK_SEM_ADDR: AtomicU64 = AtomicU64::new(0);

/// Allocate and initialise the fork semaphore.  Called once from main().
pub fn init_fork_sem() {
    let ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<sem_t>(),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED {
        panic!("[ipc-grate] mmap for fork semaphore failed");
    }
    if unsafe { sem_init(ptr as *mut sem_t, 1, 1) } < 0 {
        panic!("[ipc-grate] sem_init for fork semaphore failed");
    }
    FORK_SEM_ADDR.store(ptr as u64, Ordering::Release);
}

fn fork_sem() -> *mut sem_t {
    FORK_SEM_ADDR.load(Ordering::Acquire) as *mut sem_t
}

/// Acquire the fork gate (blocks if a fork is in progress).
pub fn fork_lock() {
    let sem = fork_sem();
    if !sem.is_null() {
        unsafe { sem_wait(sem) };
    }
}

/// Release the fork gate.
pub fn fork_unlock() {
    let sem = fork_sem();
    if !sem.is_null() {
        unsafe { sem_post(sem) };
    }
}

use crate::pipe::{PipeBuffer, PIPE_CAPACITY};
use crate::socket::{SocketRegistry, IPC_SOCKET};

// =====================================================================
//  Constants
// =====================================================================

/// fdtables fdkind for pipe endpoints (both read and write ends).
/// The direction is determined by perfdinfo flags (O_RDONLY vs O_WRONLY).
pub const IPC_PIPE: u32 = 1;

/// O_NONBLOCK flag value.
pub const O_NONBLOCK: i32 = 0o4000;

/// O_CLOEXEC flag value.
pub const O_CLOEXEC: i32 = 0o2000000;

/// O_RDONLY
pub const O_RDONLY: i32 = 0;

/// O_WRONLY
pub const O_WRONLY: i32 = 1;

/// O_ACCMODE — mask for read/write direction bits.
pub const O_ACCMODE: i32 = 3;

// fcntl ops
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;

// =====================================================================
//  Global state
// =====================================================================

/// Global IPC state.
pub static IPC_STATE: Mutex<Option<IpcState>> = Mutex::new(None);

/// Access the global IPC state.
pub fn with_ipc<F, R>(f: F) -> R
where
    F: FnOnce(&mut IpcState) -> R,
{
    let mut guard = IPC_STATE.lock().unwrap();
    f(guard.as_mut().expect("IPC state not initialized"))
}

/// Global IPC state: pipe registry + socket registry.
pub struct IpcState {
    /// pipe_id → PipeBuffer. Shared across cages via Arc.
    pub pipes: HashMap<u64, Arc<PipeBuffer>>,
    /// Next pipe_id to allocate.
    pub next_pipe_id: u64,
    /// The IPC grate's own cage ID.
    pub grate_cage_id: u64,
    /// Socket state: socket registry, accept queue, bind paths/ports.
    pub sockets: SocketRegistry,
    /// Pending AF_INET sockets: (cage_id, kernel_fd) → socket_id.
    /// At socket() time we forward AF_INET to kernel and get a real fd.
    /// We track it here until bind/connect tells us whether it's loopback.
    /// If loopback: we close the kernel fd and take over with pipes.
    /// If not: we drop the entry and let kernel own it.
    pub pending_inet: HashMap<(u64, u64), u64>,
}

impl IpcState {
    pub fn new(grate_cage_id: u64) -> Self {
        IpcState {
            pipes: HashMap::new(),
            next_pipe_id: 0,
            grate_cage_id,
            sockets: SocketRegistry::new(),
            pending_inet: HashMap::new(),
        }
    }

    /// Create a new pipe and register both fds in fdtables for the given cage.
    ///
    /// Both ends use the same fdkind (IPC_PIPE). The direction is encoded
    /// in perfdinfo: O_RDONLY for the read end, O_WRONLY for the write end.
    ///
    /// Returns (read_fd, write_fd) on success, or a negative errno on failure.
    pub fn create_pipe(&mut self, cage_id: u64, flags: i32) -> Result<(i32, i32), i32> {
        ensure_cage_exists(cage_id);

        let pipe_id = self.next_pipe_id;
        self.next_pipe_id += 1;

        let pipe = Arc::new(PipeBuffer::new(PIPE_CAPACITY));
        self.pipes.insert(pipe_id, pipe);

        let cloexec = (flags & O_CLOEXEC) != 0;
        let fl = flags & O_NONBLOCK;

        // Read end: perfdinfo = O_RDONLY | optional O_NONBLOCK.
        let read_fd = match fdtables::get_unused_virtual_fd(
            cage_id, IPC_PIPE, pipe_id, cloexec, (O_RDONLY | fl) as u64,
        ) {
            Ok(fd) => fd as i32,
            Err(_) => return Err(-24), // EMFILE
        };

        // Write end: perfdinfo = O_WRONLY | optional O_NONBLOCK.
        let write_fd = match fdtables::get_unused_virtual_fd(
            cage_id, IPC_PIPE, pipe_id, cloexec, (O_WRONLY | fl) as u64,
        ) {
            Ok(fd) => fd as i32,
            Err(_) => {
                let _ = fdtables::close_virtualfd(cage_id, read_fd as u64);
                return Err(-24);
            }
        };

        Ok((read_fd, write_fd))
    }

    /// Look up a pipe by its pipe_id (stored as underfd in fdtables).
    pub fn get_pipe(&self, pipe_id: u64) -> Option<Arc<PipeBuffer>> {
        self.pipes.get(&pipe_id).cloned()
    }
}

/// Check if a fd belongs to the IPC grate (pipe endpoint or socket).
/// Returns (underfd, fdkind, flags) or None if it's not ours.
///
/// If the cage doesn't exist in fdtables (fork in progress on another thread),
/// briefly acquires the shared-memory fork semaphore to block until the
/// parent's fork_handler has finished copying the fdtable + bumping refcounts.
pub fn lookup_ipc_fd(cage_id: u64, fd: u64) -> Option<(u64, u32, i32)> {
    if !fdtables::check_cage_exists(cage_id) {
        // Fork is likely in progress — block until parent finishes setup.
        fork_lock();
        fork_unlock();
        // If cage still doesn't exist, it's genuinely unknown.
        if !fdtables::check_cage_exists(cage_id) {
            return None;
        }
    }
    match fdtables::translate_virtual_fd(cage_id, fd) {
        Ok(entry) if entry.fdkind == IPC_PIPE || entry.fdkind == IPC_SOCKET => {
            Some((entry.underfd, entry.fdkind, entry.perfdinfo as i32))
        }
        _ => None,
    }
}

/// Check if perfdinfo flags indicate a read-end pipe fd.
pub fn is_read_end(flags: i32) -> bool {
    (flags & O_ACCMODE) == O_RDONLY
}

/// Check if perfdinfo flags indicate a write-end pipe fd.
pub fn is_write_end(flags: i32) -> bool {
    (flags & O_ACCMODE) == O_WRONLY
}

/// Initialize the global IPC state.
pub fn init(grate_cage_id: u64) {
    *IPC_STATE.lock().unwrap() = Some(IpcState::new(grate_cage_id));
}

/// Ensure a cage exists in fdtables. Idempotent — safe to call multiple times.
///
/// Uses the shared-memory fork semaphore to prevent the TOCTOU race where two
/// concurrent handlers both see the cage as missing and both try to init it.
pub fn ensure_cage_exists(cage_id: u64) {
    fork_lock();
    if !fdtables::check_cage_exists(cage_id) {
        fdtables::init_empty_cage(cage_id);
    }
    fork_unlock();
}

// =====================================================================
//  Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> IpcState {
        fdtables::refresh();
        fdtables::init_empty_cage(1);
        IpcState::new(100)
    }

    #[test]
    fn test_create_pipe_returns_two_fds() {
        let mut state = setup();
        let (rfd, wfd) = state.create_pipe(1, 0).unwrap();
        assert!(rfd >= 0);
        assert!(wfd >= 0);
        assert_ne!(rfd, wfd);
    }

    #[test]
    fn test_both_ends_same_fdkind() {
        let mut state = setup();
        let (rfd, wfd) = state.create_pipe(1, 0).unwrap();

        let read_entry = fdtables::translate_virtual_fd(1, rfd as u64).unwrap();
        let write_entry = fdtables::translate_virtual_fd(1, wfd as u64).unwrap();

        // Both ends use the same fdkind.
        assert_eq!(read_entry.fdkind, IPC_PIPE);
        assert_eq!(write_entry.fdkind, IPC_PIPE);
    }

    #[test]
    fn test_direction_from_flags() {
        let mut state = setup();
        let (rfd, wfd) = state.create_pipe(1, 0).unwrap();

        let read_entry = fdtables::translate_virtual_fd(1, rfd as u64).unwrap();
        let write_entry = fdtables::translate_virtual_fd(1, wfd as u64).unwrap();

        // Direction is in perfdinfo flags.
        assert!(is_read_end(read_entry.perfdinfo as i32));
        assert!(is_write_end(write_entry.perfdinfo as i32));
    }

    #[test]
    fn test_pipe_fds_share_same_underfd() {
        let mut state = setup();
        let (rfd, wfd) = state.create_pipe(1, 0).unwrap();

        let read_entry = fdtables::translate_virtual_fd(1, rfd as u64).unwrap();
        let write_entry = fdtables::translate_virtual_fd(1, wfd as u64).unwrap();
        assert_eq!(read_entry.underfd, write_entry.underfd);
    }

    #[test]
    fn test_pipe_read_write_through_registry() {
        let mut state = setup();
        let (_rfd, _wfd) = state.create_pipe(1, 0).unwrap();

        let read_entry = fdtables::translate_virtual_fd(1, _rfd as u64).unwrap();
        let pipe = state.get_pipe(read_entry.underfd).unwrap();

        pipe.write(b"test data", 9, false);
        let mut buf = [0u8; 64];
        let nr = pipe.read(&mut buf, 64, false);
        assert_eq!(nr, 9);
        assert_eq!(&buf[..9], b"test data");
    }

    #[test]
    fn test_o_cloexec_flag() {
        let mut state = setup();
        let (rfd, wfd) = state.create_pipe(1, O_CLOEXEC).unwrap();

        let read_entry = fdtables::translate_virtual_fd(1, rfd as u64).unwrap();
        assert!(read_entry.should_cloexec);

        let write_entry = fdtables::translate_virtual_fd(1, wfd as u64).unwrap();
        assert!(write_entry.should_cloexec);
    }

    #[test]
    fn test_close_pipe_fd() {
        let mut state = setup();
        let (rfd, _wfd) = state.create_pipe(1, 0).unwrap();

        let _ = fdtables::close_virtualfd(1, rfd as u64);
        assert!(fdtables::translate_virtual_fd(1, rfd as u64).is_err());
    }
}
