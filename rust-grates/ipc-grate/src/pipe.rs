//! Ring buffer pipe implementation using the `ringbuf` crate.
//!
//! Modeled on safeposix-rust's EmulatedPipe: a lock-free circular buffer
//! split into Producer (write) and Consumer (read) halves, with atomic
//! refcounts for each endpoint and an EOF flag.
//!
//! # Thread safety
//!
//! `ringbuf`'s Producer and Consumer are a lock-free SPSC pair — they are
//! designed to be used from two separate threads without external locking.
//! We do NOT wrap them in Mutex because std::sync::Mutex does not synchronize
//! across Lind runtime threads (each forked cage runs on its own runtime
//! thread).  Using Mutex here would give a false sense of safety and actively
//! corrupt the ringbuf state when both sides "acquire" what they think is
//! exclusive access.
//!
//! # Blocking
//!
//! Sleep in short (~1µs requested → ~50µs kernel-timer-rounded) chunks
//! via `libc::nanosleep`, which forwards to the host's `clock_nanosleep`.
//! `lind_send_signal` interrupts blocking host syscalls on the user
//! cage's main thread by sending SIGUSR2 via `tkill`; since the grate
//! runs on that thread, our `nanosleep` is the syscall that gets
//! interrupted.  A negative return means EINTR — the read/write loop
//! bails so the cage's signal handler can run.
//!
//! # Capacity
//!
//! Default 65,536 bytes (same as safeposix PIPE_CAPACITY and Linux default).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::cell::UnsafeCell;

use ringbuf::RingBuffer;
use ringbuf::{Consumer, Producer};

/// Sleep ~50µs (1µs requested, kernel rounds up to its timer
/// granularity) in a way that's interruptible by signals queued for
/// the calling user cage.  Returns `true` if the sleep was
/// interrupted; caller should propagate -EINTR so the cage's signal
/// handler runs before the syscall is retried.
fn nap_signal_aware() -> bool {
    unsafe {
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 1_000 };
        libc::nanosleep(&ts, std::ptr::null_mut()) < 0
    }
}

/// Default pipe capacity in bytes (64 KB, matching Linux and safeposix-rust).
pub const PIPE_CAPACITY: usize = 65536;

/// A userspace pipe backed by a `ringbuf` ring buffer.
///
/// Both endpoints (read and write) share the same PipeBuffer via Arc.
/// Producer and Consumer are lock-free SPSC — no Mutex needed.
pub struct PipeBuffer {
    /// Producer half — writers push bytes here.  Only accessed from writer thread.
    producer: UnsafeCell<Producer<u8>>,
    /// Consumer half — readers pull bytes here.  Only accessed from reader thread.
    consumer: UnsafeCell<Consumer<u8>>,
    /// Number of open write-end file descriptors.
    pub write_refs: AtomicU32,
    /// Number of open read-end file descriptors.
    pub read_refs: AtomicU32,
    /// Set to true when the last write-end closes.
    pub eof: AtomicBool,
}

// SAFETY: Producer and Consumer are SPSC halves designed for cross-thread use.
// Each half is only accessed from one side (reader or writer) at a time.
unsafe impl Send for PipeBuffer {}
unsafe impl Sync for PipeBuffer {}

impl PipeBuffer {
    /// Create a new pipe with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let rb = RingBuffer::new(capacity);
        let (prod, cons) = rb.split();

        PipeBuffer {
            producer: UnsafeCell::new(prod),
            consumer: UnsafeCell::new(cons),
            write_refs: AtomicU32::new(1),
            read_refs: AtomicU32::new(1),
            eof: AtomicBool::new(false),
        }
    }

    /// Read from the pipe.  Blocks (~50µs nanosleep chunks) until data
    /// is available, EOF is reached, or a signal is delivered.
    ///
    /// Returns:
    ///   > 0: number of bytes read
    ///   0: EOF (all write ends closed and buffer drained)
    ///   -4: EINTR (signal queued for the calling cage)
    ///   -11: EAGAIN (nonblocking mode, no data available)
    pub fn read(&self, dst: &mut [u8], count: usize, nonblocking: bool) -> i32 {
        let read_count = count.min(dst.len());

        loop {
            // SAFETY: only one reader thread accesses the consumer at a time
            // (SPSC contract — one consumer per pipe).
            let n = unsafe { (*self.consumer.get()).pop_slice(&mut dst[..read_count]) };
            if n > 0 {
                return n as i32;
            }

            // Buffer is empty. Check for EOF.
            if self.eof.load(Ordering::Acquire) {
                return 0;
            }

            if nonblocking {
                return -11; // EAGAIN
            }

            // Sleep a short signal-interruptible chunk before retry.
            // Without signal-awareness here, postgres' SetLatch /
            // SIGTERM during a blocking pipe read goes unobserved.
            if nap_signal_aware() {
                return -4; // EINTR
            }
        }
    }

    /// Write to the pipe.  Blocks (~50µs nanosleep chunks) until space
    /// is available, all read ends close, or a signal is delivered.
    ///
    /// Returns:
    ///   > 0: number of bytes written (full count, or partial on signal /
    ///        nonblocking)
    ///   -4: EINTR (signal arrived before any bytes were written; if
    ///       some bytes were already written we return the short count
    ///       per POSIX write(2) semantics)
    ///   -11: EAGAIN (nonblocking mode, pipe full and nothing written)
    ///   -32: EPIPE (all read ends closed — broken pipe)
    pub fn write(&self, src: &[u8], count: usize, nonblocking: bool) -> i32 {
        if self.read_refs.load(Ordering::Acquire) == 0 {
            return -32; // EPIPE
        }

        let write_count = count.min(src.len());
        let mut total_written = 0;

        while total_written < write_count {
            // SAFETY: only one writer thread accesses the producer at a time
            // (SPSC contract — one producer per pipe).
            let n = unsafe {
                (*self.producer.get()).push_slice(&src[total_written..write_count])
            };
            total_written += n;

            if total_written >= write_count {
                break;
            }

            // Check for broken pipe.
            if self.read_refs.load(Ordering::Acquire) == 0 {
                return -32; // EPIPE
            }

            if nonblocking {
                if total_written > 0 {
                    return total_written as i32;
                }
                return -11; // EAGAIN
            }

            // Signal-aware sleep — see read() above for rationale.
            if nap_signal_aware() {
                if total_written > 0 {
                    return total_written as i32;
                }
                return -4; // EINTR
            }
        }

        total_written as i32
    }

    /// Increment the write-end reference count (called on dup of a write fd).
    pub fn incr_write_ref(&self) {
        self.write_refs.fetch_add(1, Ordering::Release);
    }

    /// Decrement the write-end reference count. Sets EOF if this was the last
    /// write-end, so readers know no more data is coming.
    pub fn decr_write_ref(&self) {
        let prev = self.write_refs.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.eof.store(true, Ordering::Release);
        }
    }

    /// Increment the read-end reference count (called on dup of a read fd).
    pub fn incr_read_ref(&self) {
        self.read_refs.fetch_add(1, Ordering::Release);
    }

    /// Decrement the read-end reference count.
    pub fn decr_read_ref(&self) {
        self.read_refs.fetch_sub(1, Ordering::AcqRel);
    }

    /// Check if the pipe has data available for reading.
    pub fn has_data(&self) -> bool {
        // SAFETY: read-only length check, safe from any thread.
        unsafe { !(*self.consumer.get()).is_empty() }
    }

    /// Check if the pipe has space available for writing.
    pub fn has_space(&self) -> bool {
        // SAFETY: read-only length check, safe from any thread.
        unsafe { !(*self.producer.get()).is_full() }
    }

    /// Number of bytes currently available to read from this pipe.
    /// Used by ioctl(FIONREAD) on IPC pipes/sockets.
    pub fn bytes_available(&self) -> usize {
        // SAFETY: read-only length check, safe from any thread.
        unsafe { (*self.consumer.get()).len() }
    }
}

// =====================================================================
//  Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_basic_read_write() {
        let pipe = PipeBuffer::new(1024);

        let data = b"hello pipe";
        let nw = pipe.write(data, data.len(), false);
        assert_eq!(nw, data.len() as i32);

        let mut buf = [0u8; 64];
        let nr = pipe.read(&mut buf, 64, false);
        assert_eq!(nr, data.len() as i32);
        assert_eq!(&buf[..data.len()], data);
    }

    #[test]
    fn test_eof_on_last_writer_close() {
        let pipe = PipeBuffer::new(1024);

        pipe.write(b"data", 4, false);
        pipe.decr_write_ref();

        let mut buf = [0u8; 64];
        let nr = pipe.read(&mut buf, 64, false);
        assert_eq!(nr, 4);
        assert_eq!(&buf[..4], b"data");

        // Next read should return 0 (EOF).
        let nr = pipe.read(&mut buf, 64, false);
        assert_eq!(nr, 0);
    }

    #[test]
    fn test_eagain_nonblocking_read() {
        let pipe = PipeBuffer::new(1024);

        let mut buf = [0u8; 64];
        let nr = pipe.read(&mut buf, 64, true);
        assert_eq!(nr, -11); // EAGAIN
    }

    #[test]
    fn test_epipe_on_broken_pipe() {
        let pipe = PipeBuffer::new(1024);
        pipe.decr_read_ref();

        let nw = pipe.write(b"data", 4, false);
        assert_eq!(nw, -32); // EPIPE
    }

    #[test]
    fn test_write_ref_counting() {
        let pipe = PipeBuffer::new(1024);

        pipe.incr_write_ref();
        pipe.incr_write_ref();
        assert_eq!(pipe.write_refs.load(Ordering::Relaxed), 3);

        pipe.decr_write_ref();
        assert!(!pipe.eof.load(Ordering::Relaxed));
        pipe.decr_write_ref();
        assert!(!pipe.eof.load(Ordering::Relaxed));
        pipe.decr_write_ref();
        assert!(pipe.eof.load(Ordering::Relaxed));
    }

    #[test]
    fn test_ring_buffer_wraparound() {
        let pipe = PipeBuffer::new(16);

        // Fill most of the buffer.
        let data = [0xAA; 12];
        pipe.write(&data, 12, false);

        // Read 8 bytes (consumer advances).
        let mut buf = [0u8; 8];
        pipe.read(&mut buf, 8, false);
        assert_eq!(buf, [0xAA; 8]);

        // Write 10 more — this wraps around in the ring.
        let data2 = [0xBB; 10];
        let nw = pipe.write(&data2, 10, false);
        assert_eq!(nw, 10);

        // Read everything: 4 remaining 0xAA + 10 0xBB = 14 bytes.
        let mut buf2 = [0u8; 14];
        let nr = pipe.read(&mut buf2, 14, false);
        assert_eq!(nr, 14);
        assert_eq!(&buf2[..4], &[0xAA; 4]);
        assert_eq!(&buf2[4..], &[0xBB; 10]);
    }

    #[test]
    fn test_blocking_read_with_concurrent_write() {
        let pipe = Arc::new(PipeBuffer::new(1024));
        let pipe_writer = pipe.clone();

        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            pipe_writer.write(b"delayed data", 12, false);
        });

        let mut buf = [0u8; 64];
        let nr = pipe.read(&mut buf, 64, false);
        assert_eq!(nr, 12);
        assert_eq!(&buf[..12], b"delayed data");

        writer.join().unwrap();
    }

    #[test]
    fn test_full_pipe_blocks_writer() {
        let pipe = Arc::new(PipeBuffer::new(32));
        let pipe_reader = pipe.clone();

        // Fill completely.
        let data = [0xFF; 32];
        pipe.write(&data, 32, false);

        // Nonblocking write on full pipe should return EAGAIN.
        let nw = pipe.write(&[0x00], 1, true);
        assert_eq!(nw, -11);

        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let mut buf = [0u8; 16];
            pipe_reader.read(&mut buf, 16, false);
        });

        // Blocking write should succeed after reader drains.
        let nw = pipe.write(&[0x00; 8], 8, false);
        assert_eq!(nw, 8);

        reader.join().unwrap();
    }
}
