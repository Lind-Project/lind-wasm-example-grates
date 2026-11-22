//! The syscall handlers.
//!
//! **Going out.** A socket connected to an address a key may go to is a *connection that carries
//! keys*. What the program sends on it passes through this grate, where each placeholder is
//! replaced by its key (`swap.rs`). Anywhere else a placeholder goes out as a placeholder.
//!
//! **Coming in.** What the program receives on such a connection also passes through this grate,
//! where each key is replaced by its placeholder, so a host that sends the key back does not
//! hand it to the program. Reads of a key file are answered with the placeholder in the same
//! way.
//!
//! **What a descriptor is.** Whether a call is on a connection that carries keys, or on a key
//! file, is decided by looking at the descriptor itself (`fstat`: sockets and files have an
//! identity), not by remembering which numbers were connected or opened. A descriptor that was
//! duplicated, inherited across `fork` or `exec`, or reached through another name is still the
//! same socket or file. `gate.rs` keeps a number from being pointed at something else between
//! that look and the call that acts on it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::is_thread_clone;

use crate::fdtrack::FdTracker;
use crate::gate::{Gate, Key, Then};
use crate::policy::{KeyRule, parse_sockaddr};
use crate::swap::{Inbound, Outbound, Secret};
use crate::sys::{self, Arg, EACCES, EINPROGRESS, EINVAL, FileId, O_CLOEXEC};

pub const SYS_COPY_FILE_RANGE: u64 = 326;

const EBADF: i64 = 9;
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 1030;
const MSG_PEEK: u64 = 2;
const MAP_ANONYMOUS: u64 = 0x20;
const SEEK_CUR: u64 = 1;
const IOV_MAX: u64 = 1024;
/// `struct msghdr` as glibc hands it over, in the host's layout: where its fields are.
const MSGHDR_SIZE: usize = 56;
const MSG_NAME: usize = 0;
const MSG_NAMELEN: usize = 8;
const MSG_IOV: usize = 16;
const MSG_IOVLEN: usize = 24;
const MSG_CONTROLLEN: usize = 40;
const MSG_FLAGS: usize = 48;

/// Data crosses this grate's memory in pieces of at most this size.
const CHUNK: usize = 256 << 10;
/// The most a vectored write is gathered into; the rest is left for the program's next call.
const GATHER_MAX: usize = 1 << 20;
/// How many naps a rebinding call waits for plain reads: 20 ms (see `gate.rs`).
const PATIENCE: u32 = 100;

/// A socket connected, or being connected, to an address some key may go to.
struct Conn {
    /// The secrets whose placeholders are replaced on the way out. Empty while it is in doubt
    /// where the socket is connected to.
    swap: Mutex<Vec<usize>>,
    /// Held for the length of a send, so that keys go out whole and in order.
    out: Mutex<Outbound>,
    /// Held for the length of a receive, so that the stream is redacted in the order it is read.
    inn: Mutex<Inbound>,
}

#[derive(Default)]
struct State {
    conns: HashMap<u64, Arc<Conn>>,
    /// Which connection a socket is.
    by_id: HashMap<FileId, u64>,
    next_conn: u64,
    /// The descriptors each connection has; a connection with none is forgotten.
    fds: FdTracker,
    gate: Gate,
}

static SECRETS: OnceLock<Vec<Secret>> = OnceLock::new();
static RULES: OnceLock<Vec<KeyRule>> = OnceLock::new();
/// What a program reads from each key file: its content with placeholders for keys.
static VIEWS: OnceLock<HashMap<FileId, Vec<u8>>> = OnceLock::new();
static STATE: Mutex<Option<State>> = Mutex::new(None);

fn secrets() -> &'static [Secret] {
    SECRETS.get().expect("handlers run after init")
}

fn views() -> &'static HashMap<FileId, Vec<u8>> {
    VIEWS.get().expect("handlers run after init")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The shared state is held only for bookkeeping, never across a syscall or a wait.
fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    f(lock(&STATE).as_mut().expect("handlers run after init"))
}

/// `secrets[i]` is the key of `rules[i]`; `views` maps each key file to what is read from it.
pub fn init(secrets: Vec<Secret>, rules: Vec<KeyRule>, views: HashMap<FileId, Vec<u8>>) {
    sys::me();
    let _ = SECRETS.set(secrets);
    let _ = RULES.set(rules);
    let _ = VIEWS.set(views);
    *lock(&STATE) = Some(State::default());
}

impl State {
    fn conn_of(&self, id: FileId) -> Option<Arc<Conn>> {
        self.conns.get(self.by_id.get(&id)?).cloned()
    }

    /// The connection for socket `id`, made if there is none, with `fd` of `cage` as its
    /// first descriptor.
    fn adopt(&mut self, cage: u64, fd: u64, id: FileId) -> Arc<Conn> {
        if let Some(conn) = self.conn_of(id) {
            return conn;
        }
        self.next_conn += 1;
        let conn = Arc::new(Conn {
            swap: Mutex::new(Vec::new()),
            out: Mutex::new(Outbound::default()),
            inn: Mutex::new(Inbound::default()),
        });
        self.conns.insert(self.next_conn, conn.clone());
        self.by_id.insert(id, self.next_conn);
        self.point(cage, fd, Some(self.next_conn));
        conn
    }

    /// `fd` of `cage` now refers to `conn`, or to nothing that carries keys.
    fn point(&mut self, cage: u64, fd: u64, conn: Option<u64>) {
        let orphan = match conn {
            Some(conn) => self.fds.insert(cage, fd, conn),
            None => self.fds.remove(cage, fd),
        };
        if let Some(orphan) = orphan {
            self.forget(orphan);
        }
    }

    fn unpin(&mut self, conn: u64) {
        if self.fds.unpin(conn) {
            self.forget(conn);
        }
    }

    fn forget(&mut self, conn: u64) {
        self.conns.remove(&conn);
        self.by_id.retain(|_, c| *c != conn);
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
        let args = self.args.map(|(v, cage)| Arg::From(v, cage));
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

// ---------------------------------------------------------------------------------------------
// What a descriptor is
// ---------------------------------------------------------------------------------------------

enum What {
    /// Nothing this grate has to do anything about.
    Other,
    /// A connection that carries keys.
    Carries(Arc<Conn>),
    /// A key file, and what is read from it.
    KeyFile(&'static [u8]),
}

fn what(cage: u64, fd: u64) -> What {
    match sys::fstat(cage, fd) {
        Ok(st) if st.socket => with(|s| s.conn_of(st.id)).map_or(What::Other, What::Carries),
        Ok(st) if st.regular => views()
            .get(&st.id)
            .map_or(What::Other, |v| What::KeyFile(v)),
        _ => What::Other,
    }
}

/// The connection that socket `fd` of `cage` is, pinned so that it outlives the call under way.
fn pinned(cage: u64, fd: u64) -> Option<u64> {
    if with(|st| st.conns.is_empty()) {
        return None;
    }
    let id = sys::fstat(cage, fd).ok().filter(|st| st.socket)?.id;
    with(|st| {
        let conn = st.by_id.get(&id).copied()?;
        st.fds.pin(conn);
        Some(conn)
    })
}

/// A call that reads from descriptor `fd_at` of its arguments. It is forwarded as it came unless
/// the descriptor is a connection that carries keys or a key file; then `special` answers it.
fn reading(call: &Call, fd_at: usize, nr: u64, special: impl FnOnce(What) -> i64) -> i64 {
    enum Start {
        Wait,
        Plain,
        Look,
    }
    let key = (call.cage(), call.val(fd_at));
    loop {
        let start = with(|st| {
            // With no connection carrying keys and no key file, there is nothing a descriptor
            // could turn out to be.
            let plain = st.conns.is_empty() && views().is_empty();
            let begun = if plain {
                st.gate.begin_plain_read(key)
            } else {
                st.gate.begin(key)
            };
            match (begun, plain) {
                (false, _) => Start::Wait,
                (true, true) => Start::Plain,
                (true, false) => Start::Look,
            }
        });
        match start {
            // The number is being rebound. What it refers to is settled in a moment.
            Start::Wait => sys::nap(),
            Start::Plain => break,
            Start::Look => match what(key.0, key.1) {
                What::Other => {
                    with(|st| st.gate.decided(key, Then::PlainRead));
                    break;
                }
                found => {
                    with(|st| st.gate.decided(key, Then::Nothing));
                    return special(found);
                }
            },
        }
    }
    let ret = call.forward(nr);
    with(|st| st.gate.end(key, Then::PlainRead));
    ret
}

/// Run `rebind`, a call that changes what descriptor `key` refers to, when no other call is
/// between looking at that descriptor and using it. `after` records the outcome.
fn rebinding<R>(key: Key, rebind: impl FnOnce() -> R, after: impl FnOnce(&mut State, &R)) -> R {
    while !with(|st| st.gate.rebind_begin(key)) {
        sys::nap();
    }
    let mut naps = 0;
    while !with(|st| st.gate.rebind_ready(key, naps < PATIENCE)) {
        sys::nap();
        naps += 1;
    }
    let ret = rebind();
    with(|st| {
        after(st, &ret);
        st.gate.rebind_end(key);
    });
    ret
}

// ---------------------------------------------------------------------------------------------
// Going out
// ---------------------------------------------------------------------------------------------

/// If descriptor `key` is a connection that carries keys, that connection, with a write on it
/// registered: `end_write` must follow.
fn begin_write(key: Key) -> Option<Arc<Conn>> {
    // While the number is being rebound the write goes out as it came, placeholders and all.
    if !with(|st| !st.conns.is_empty() && st.gate.begin(key)) {
        return None;
    }
    let conn = match what(key.0, key.1) {
        What::Carries(conn) => Some(conn),
        _ => None,
    };
    let then = if conn.is_some() {
        Then::Write
    } else {
        Then::Nothing
    };
    with(|st| st.gate.decided(key, then));
    conn
}

fn end_write(key: Key) {
    with(|st| st.gate.end(key, Then::Write));
}

/// What a program is sending.
enum Data<'a> {
    /// `len` bytes at an (address, cage) pair.
    There((u64, u64), usize),
    Here(&'a [u8]),
}

impl Data<'_> {
    fn len(&self) -> usize {
        match self {
            Data::There(_, len) => *len,
            Data::Here(data) => data.len(),
        }
    }

    fn get(&self, from: usize, n: usize) -> Result<Vec<u8>, i64> {
        match self {
            Data::There((addr, cage), _) => sys::copy_in((addr + from as u64, *cage), n),
            Data::Here(data) => Ok(data[from..from + n].to_vec()),
        }
    }
}

/// Send `data` on a connection that carries keys, each placeholder replaced by its key. The
/// program's bytes are copied here first and it is the copy that is searched and sent, so what
/// was searched is what goes out. `forward` sends a buffer of this grate's.
fn send(conn: &Conn, data: Data, forward: impl Fn(&[u8]) -> i64) -> i64 {
    let mut out = lock(&conn.out);
    // Read under the lock: a connect that is under way holds it and has emptied the list.
    let active = lock(&conn.swap).clone();
    let len = data.len();
    let mut done = 0;
    loop {
        let mut n = (len - done).min(CHUNK);
        let mut chunk = match data.get(done, n) {
            Ok(chunk) => chunk,
            Err(e) => return if done > 0 { done as i64 } else { e },
        };
        if done + n < len {
            n -= Outbound::trim(secrets(), &active, &chunk);
            chunk.truncate(n);
        }
        let regions = out.rewrite(secrets(), &active, &mut chunk);
        let sent = forward(&chunk);
        if sent < 0 {
            return if done > 0 { done as i64 } else { sent };
        }
        out.sent(secrets(), &regions, sent as usize);
        done += sent as usize;
        if (sent as usize) < n || done >= len {
            return done as i64;
        }
    }
}

/// The (address, length) pairs of an iovec array in a cage. glibc has already put the array in
/// the host's layout: two 64-bit fields each.
fn iovecs(at: (u64, u64), count: u64) -> Result<Vec<(u64, usize)>, i64> {
    if count > IOV_MAX {
        return Err(-EINVAL);
    }
    let raw = sys::copy_in(at, count as usize * 16)?;
    let field = |bytes: &[u8]| u64::from_ne_bytes(bytes.try_into().unwrap());
    Ok(raw
        .chunks_exact(16)
        .map(|v| (field(&v[..8]), field(&v[8..]) as usize))
        .collect())
}

/// The bytes an iovec array describes, up to `GATHER_MAX`.
fn gather(at: (u64, u64), count: u64) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    for (base, len) in iovecs(at, count)? {
        let room = GATHER_MAX - data.len();
        data.extend(sys::copy_in((base, at.1), len.min(room))?);
    }
    Ok(data)
}

/// How many bytes an iovec array has room for.
fn capacity(at: (u64, u64), count: u64) -> Result<usize, i64> {
    Ok(iovecs(at, count)?
        .iter()
        .fold(0usize, |sum, (_, len)| sum.saturating_add(*len)))
}

/// Put `data` into the buffers an iovec array describes.
fn scatter(at: (u64, u64), count: u64, mut data: &[u8]) -> Result<(), i64> {
    for (base, len) in iovecs(at, count)? {
        let n = len.min(data.len());
        sys::copy_out((base, at.1), &data[..n])?;
        data = &data[n..];
    }
    Ok(())
}

fn mine(buf: &[u8]) -> [Arg; 2] {
    [Arg::Mine(buf.as_ptr() as u64), Arg::Val(buf.len() as u64)]
}

// write(fd, buf, count)
handler!(write_handler, |call| {
    let key = (call.cage(), call.val(0));
    let Some(conn) = begin_write(key) else {
        return call.forward(SYS_WRITE);
    };
    let data = Data::There(call.args[1], call.val(2) as usize);
    let ret = send(&conn, data, |buf| {
        let [ptr, len] = mine(buf);
        sys::call(key.0, SYS_WRITE, &[call.arg(0), ptr, len])
    });
    end_write(key);
    ret
});

// sendto(fd, buf, len, flags, addr, addrlen)
handler!(sendto_handler, |call| {
    let key = (call.cage(), call.val(0));
    // With an address, the data goes to that address and not to where the socket is connected.
    if call.val(4) != 0 {
        return call.forward(SYS_SENDTO);
    }
    let Some(conn) = begin_write(key) else {
        return call.forward(SYS_SENDTO);
    };
    let data = Data::There(call.args[1], call.val(2) as usize);
    let ret = send(&conn, data, |buf| {
        let [ptr, len] = mine(buf);
        sys::call(
            key.0,
            SYS_SENDTO,
            &[call.arg(0), ptr, len, call.arg(3), call.arg(4), call.arg(5)],
        )
    });
    end_write(key);
    ret
});

// writev(fd, iov, iovcnt)
handler!(writev_handler, |call| {
    let key = (call.cage(), call.val(0));
    let Some(conn) = begin_write(key) else {
        return call.forward(SYS_WRITEV);
    };
    let ret = match gather(call.args[1], call.val(2)) {
        Ok(data) => send(&conn, Data::Here(&data), |buf| {
            let [ptr, len] = mine(buf);
            sys::call(key.0, SYS_WRITE, &[call.arg(0), ptr, len])
        }),
        Err(e) => e,
    };
    end_write(key);
    ret
});

// sendmsg(fd, msg, flags)
handler!(sendmsg_handler, |call| {
    let key = (call.cage(), call.val(0));
    let Some(conn) = begin_write(key) else {
        return call.forward(SYS_SENDMSG);
    };
    let sent: Result<Option<i64>, i64> = (|| {
        let msg = sys::copy_in(call.args[1], MSGHDR_SIZE)?;
        let field = |at: usize| u64::from_ne_bytes(msg[at..at + 8].try_into().unwrap());
        // A message with its own address or with control data is sent as it came.
        if field(MSG_NAME) != 0 || field(MSG_CONTROLLEN) != 0 {
            return Ok(None);
        }
        let data = gather((field(MSG_IOV), call.args[1].1), field(MSG_IOVLEN))?;
        Ok(Some(send(&conn, Data::Here(&data), |buf| {
            let [ptr, len] = mine(buf);
            sys::call(
                key.0,
                SYS_SENDTO,
                &[call.arg(0), ptr, len, call.arg(2), Arg::Val(0), Arg::Val(0)],
            )
        })))
    })();
    end_write(key);
    match sent {
        Ok(Some(ret)) => ret,
        Ok(None) => call.forward(SYS_SENDMSG),
        Err(e) => e,
    }
});

// ---------------------------------------------------------------------------------------------
// Coming in
// ---------------------------------------------------------------------------------------------

/// Receive on a connection that carries keys. The data arrives in this grate, where keys become
/// placeholders, and only then is it given to the program (`deliver`). `forward` receives into
/// a buffer of this grate's.
fn receive(
    conn: &Conn,
    want: usize,
    peek: bool,
    forward: impl FnOnce(&mut [u8]) -> i64,
    deliver: impl FnOnce(&[u8]) -> Result<(), i64>,
) -> i64 {
    let mut inn = lock(&conn.inn);
    let mut buf = vec![0u8; want.min(CHUNK)];
    let got = forward(&mut buf);
    if got <= 0 {
        return got;
    }
    buf.truncate(got as usize);
    if peek {
        // The same bytes will be read again: this look at them does not move the stream on.
        inn.clone().redact(secrets(), &mut buf);
    } else {
        inn.redact(secrets(), &mut buf);
    }
    match deliver(&buf) {
        Ok(()) => got,
        Err(e) => e,
    }
}

/// Answer a read of a key file. The read itself is made, into this grate, for what the kernel
/// says about it (how much, end of file, errors) and to move the file offset; `forward` makes it.
/// What the program is given is that many bytes of `view`, from `offset`.
fn read_key_file(
    view: &[u8],
    offset: i64,
    want: usize,
    forward: impl FnOnce(&mut [u8]) -> i64,
    deliver: impl FnOnce(&[u8]) -> Result<(), i64>,
) -> i64 {
    if offset < 0 {
        return offset;
    }
    let mut scratch = vec![0u8; want.min(CHUNK)];
    let got = forward(&mut scratch);
    if got <= 0 {
        return got;
    }
    let from = (offset as usize).min(view.len());
    let shown = &view[from..(from + got as usize).min(view.len())];
    match deliver(shown) {
        Ok(()) => shown.len() as i64,
        Err(e) => e,
    }
}

fn mine_mut(buf: &mut [u8]) -> [Arg; 2] {
    [
        Arg::Mine(buf.as_mut_ptr() as u64),
        Arg::Val(buf.len() as u64),
    ]
}

/// read (`vectored` false: fd, buf, count) and readv (`vectored` true: fd, iov, iovcnt).
fn read(call: &Call, vectored: bool) -> i64 {
    let nr = if vectored { SYS_READV } else { SYS_READ };
    reading(call, 0, nr, |found| {
        let cage = call.cage();
        let want = if vectored {
            match capacity(call.args[1], call.val(2)) {
                Ok(want) => want,
                Err(e) => return e,
            }
        } else {
            call.val(2) as usize
        };
        let forward = |buf: &mut [u8]| {
            let [ptr, len] = mine_mut(buf);
            sys::call(cage, SYS_READ, &[call.arg(0), ptr, len])
        };
        let deliver = |data: &[u8]| {
            if vectored {
                scatter(call.args[1], call.val(2), data)
            } else {
                sys::copy_out(call.args[1], data)
            }
        };
        match found {
            What::Carries(conn) => receive(&conn, want, false, forward, deliver),
            What::KeyFile(view) => {
                let here = sys::call(
                    cage,
                    SYS_LSEEK,
                    &[call.arg(0), Arg::Val(0), Arg::Val(SEEK_CUR)],
                );
                read_key_file(view, here, want, forward, deliver)
            }
            What::Other => unreachable!(),
        }
    })
}

handler!(read_handler, |call| read(&call, false));
handler!(readv_handler, |call| read(&call, true));

/// pread (`vectored` false: fd, buf, count, offset) and preadv (fd, iov, iovcnt, offset).
/// Registered only when there is a key file.
fn pread(call: &Call, vectored: bool) -> i64 {
    let nr = if vectored { SYS_PREADV } else { SYS_PREAD };
    reading(call, 0, nr, |found| {
        let What::KeyFile(view) = found else {
            // A socket has no offset to read at: the kernel says so.
            return call.forward(nr);
        };
        let want = if vectored {
            match capacity(call.args[1], call.val(2)) {
                Ok(want) => want,
                Err(e) => return e,
            }
        } else {
            call.val(2) as usize
        };
        let forward = |buf: &mut [u8]| {
            let [ptr, len] = mine_mut(buf);
            sys::call(
                call.cage(),
                SYS_PREAD,
                &[call.arg(0), ptr, len, call.arg(3)],
            )
        };
        let deliver = |data: &[u8]| {
            if vectored {
                scatter(call.args[1], call.val(2), data)
            } else {
                sys::copy_out(call.args[1], data)
            }
        };
        let offset = (call.val(3) as i64).max(0);
        read_key_file(view, offset, want, forward, deliver)
    })
}

handler!(pread_handler, |call| pread(&call, false));
handler!(preadv_handler, |call| pread(&call, true));

// recvfrom(fd, buf, len, flags, addr, addrlen)
handler!(recvfrom_handler, |call| {
    reading(&call, 0, SYS_RECVFROM, |found| {
        let What::Carries(conn) = found else {
            return call.forward(SYS_RECVFROM);
        };
        receive(
            &conn,
            call.val(2) as usize,
            call.val(3) & MSG_PEEK != 0,
            |buf| {
                let [ptr, len] = mine_mut(buf);
                sys::call(
                    call.cage(),
                    SYS_RECVFROM,
                    &[call.arg(0), ptr, len, call.arg(3), call.arg(4), call.arg(5)],
                )
            },
            |data| sys::copy_out(call.args[1], data),
        )
    })
});

// recvmsg(fd, msg, flags)
handler!(recvmsg_handler, |call| {
    reading(&call, 0, SYS_RECVMSG, |found| {
        let What::Carries(conn) = found else {
            return call.forward(SYS_RECVMSG);
        };
        let (at, cage) = call.args[1];
        let msg = match sys::copy_in((at, cage), MSGHDR_SIZE) {
            Ok(msg) => msg,
            Err(e) => return e,
        };
        let field = |at: usize| u64::from_ne_bytes(msg[at..at + 8].try_into().unwrap());
        let iov = ((field(MSG_IOV), cage), field(MSG_IOVLEN));
        let want = match capacity(iov.0, iov.1) {
            Ok(want) => want,
            Err(e) => return e,
        };
        receive(
            &conn,
            want,
            call.val(2) & MSG_PEEK != 0,
            |buf| {
                let [ptr, len] = mine_mut(buf);
                sys::call(
                    call.cage(),
                    SYS_RECVFROM,
                    &[call.arg(0), ptr, len, call.arg(2), Arg::Val(0), Arg::Val(0)],
                )
            },
            |data| {
                scatter(iov.0, iov.1, data)?;
                // The data is all that is received: no sender address, no control data.
                sys::copy_out((at + MSG_NAMELEN as u64, cage), &0u32.to_ne_bytes())?;
                sys::copy_out((at + MSG_CONTROLLEN as u64, cage), &0u64.to_ne_bytes())?;
                sys::copy_out((at + MSG_FLAGS as u64, cage), &0u32.to_ne_bytes())
            },
        )
    })
});

// mmap(addr, len, prot, flags, fd, offset). Registered only when there is a key file.
handler!(mmap_handler, |call| {
    if call.val(3) & MAP_ANONYMOUS != 0 || call.val(4) as i32 == -1 {
        return call.forward(SYS_MMAP);
    }
    reading(&call, 4, SYS_MMAP, |found| match found {
        // Mapped, the file's own bytes would be in the program's memory.
        What::KeyFile(_) => -EACCES,
        _ => call.forward(SYS_MMAP),
    })
});

// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags). Registered only when there is a
// key file.
handler!(copy_file_range_handler, |call| {
    reading(&call, 0, SYS_COPY_FILE_RANGE, |found| match found {
        // The copy would be made by the kernel, of the file's own bytes. A program that is
        // refused this falls back to reading and writing.
        What::KeyFile(_) => -EINVAL,
        _ => call.forward(SYS_COPY_FILE_RANGE),
    })
});

// ---------------------------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------------------------

/// Whether no read that was let through untouched is under way on socket `id`, under any
/// descriptor of any cage. Such a read would receive what arrives next as it is.
fn no_plain_read_on(id: FileId) -> bool {
    for _ in 0..=PATIENCE {
        let reading = with(|st| st.gate.plain_reads());
        let on_it = reading
            .iter()
            .any(|&(cage, fd)| sys::fstat(cage, fd).is_ok_and(|st| st.socket && st.id == id));
        if !on_it {
            return true;
        }
        sys::nap();
    }
    false
}

// connect(fd, addr, addrlen)
handler!(connect_handler, |call| {
    let (cage, fd) = (call.cage(), call.val(0));
    // The address is copied here, judged here, and it is this copy the socket is connected to:
    // a program cannot show one address and connect to another.
    let len = (call.val(2) as usize).min(128);
    let mut addr = sys::copy_in(call.args[1], len).unwrap_or_default();
    let parsed = parse_sockaddr(&addr);
    addr.resize(128, 0);
    let wanted: Vec<usize> = match parsed {
        Some((ip, port)) => RULES
            .get()
            .into_iter()
            .flatten()
            .enumerate()
            .filter(|(_, rule)| rule.allows(ip, port))
            .map(|(i, _)| i)
            .collect(),
        None => Vec::new(),
    };
    let forward = || match parsed {
        Some(_) => sys::call(
            cage,
            SYS_CONNECT,
            &[call.arg(0), Arg::Mine(addr.as_ptr() as u64), call.arg(2)],
        ),
        // Not an internet address: nowhere a key goes, and connected as the program asked.
        None => call.forward(SYS_CONNECT),
    };
    if wanted.is_empty() && with(|st| st.conns.is_empty()) {
        return forward();
    }

    let connect = || {
        let Some(id) = sys::fstat(cage, fd)
            .ok()
            .filter(|st| st.socket)
            .map(|st| st.id)
        else {
            return forward();
        };
        // The connection this socket is already, or a new one if a key may go where it is going.
        let conn = with(|st| match st.conn_of(id) {
            None if wanted.is_empty() => None,
            _ => Some(st.adopt(cage, fd, id)),
        });
        let Some(conn) = conn else {
            return forward();
        };
        // From here until the outcome is known no key goes out on the socket, by any descriptor:
        // sends wait for `out`, and find `swap` empty if they get it.
        let mut out = lock(&conn.out);
        let before = std::mem::take(&mut *lock(&conn.swap));
        let quiet = wanted.is_empty() || no_plain_read_on(id);
        let ret = forward();
        let connected = ret == 0 || ret == -EINPROGRESS;
        *lock(&conn.swap) = if !connected {
            // The socket is still connected to whatever it was connected to.
            before
        } else if quiet {
            *out = Outbound::default();
            wanted.clone()
        } else {
            eprintln!(
                "api-key-grate: a read was already waiting on a socket being connected; no key will be sent on it"
            );
            Vec::new()
        };
        ret
    };
    rebinding((cage, fd), connect, |_, _| {})
});

// ---------------------------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------------------------

// close(fd)
handler!(close_handler, |call| {
    let (cage, fd) = (call.cage(), call.val(0));
    rebinding(
        (cage, fd),
        || call.forward(SYS_CLOSE),
        |st, ret| {
            if *ret != -EBADF {
                st.point(cage, fd, None);
            }
        },
    )
});

/// dup2 and dup3 (old, new, ...): `new` is made to refer to what `old` does.
fn dup_onto(call: &Call, nr: u64) -> i64 {
    let (cage, old, new) = (call.cage(), call.val(0), call.val(1));
    if old == new {
        return call.forward(nr);
    }
    let conn = pinned(cage, old);
    rebinding(
        (cage, new),
        || call.forward(nr),
        |st, ret| {
            if *ret >= 0 {
                st.point(cage, new, conn);
            }
            if let Some(conn) = conn {
                st.unpin(conn);
            }
        },
    )
}

handler!(dup2_handler, |call| dup_onto(&call, SYS_DUP2));
handler!(dup3_handler, |call| dup_onto(&call, SYS_DUP3));

/// dup, and fcntl with F_DUPFD: a new descriptor for what `old` refers to, numbered `at_least`
/// or above. `plain` is the call as the program made it.
fn dup_new(
    call: &Call,
    old: u64,
    at_least: u64,
    cloexec: bool,
    plain: impl FnOnce() -> i64,
) -> i64 {
    let cage = call.cage();
    if with(|st| st.conns.is_empty()) {
        return plain();
    }
    // `old` is not rebound while this looks at it and duplicates it.
    let key = (cage, old);
    while !with(|st| st.gate.begin(key)) {
        sys::nap();
    }
    let ret = match pinned(cage, old) {
        None => plain(),
        Some(conn) => {
            let ret = dup_carrying(cage, old, at_least, cloexec, conn);
            with(|st| st.unpin(conn));
            ret
        }
    };
    with(|st| st.gate.decided(key, Then::Nothing));
    ret
}

/// Give connection `conn`, which carries keys, a new descriptor.
///
/// The kernel picks the number, so nothing can be announced about it beforehand, and a read
/// that was let through on that number while it was free could reach the connection the moment
/// the number refers to it. So the number is first taken by a socket connected to nothing, and
/// the connection is then put there the way `dup2` does it, with the gate held.
fn dup_carrying(cage: u64, old: u64, at_least: u64, cloexec: bool, conn: u64) -> i64 {
    let spare = sys::spare_socket(cage);
    if spare < 0 {
        return spare;
    }
    let mut number = spare;
    if (spare as u64) < at_least {
        number = sys::call(
            cage,
            SYS_FCNTL,
            &[
                Arg::Val(spare as u64),
                Arg::Val(F_DUPFD),
                Arg::Val(at_least),
            ],
        );
        sys::close(cage, spare as u64);
        if number < 0 {
            return number;
        }
    }
    let new = number as u64;
    let ret = rebinding(
        (cage, new),
        || {
            if cloexec {
                let args = [Arg::Val(old), Arg::Val(new), Arg::Val(O_CLOEXEC)];
                sys::call(cage, SYS_DUP3, &args)
            } else {
                sys::call(cage, SYS_DUP2, &[Arg::Val(old), Arg::Val(new)])
            }
        },
        |st, ret| {
            if *ret >= 0 {
                st.point(cage, new, Some(conn));
            }
        },
    );
    if ret < 0 {
        sys::close(cage, new);
    }
    ret
}

// dup(fd)
handler!(dup_handler, |call| {
    dup_new(&call, call.val(0), 0, false, || call.forward(SYS_DUP))
});

// fcntl(fd, cmd, arg)
handler!(fcntl_handler, |call| {
    let cmd = call.val(1);
    if cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC {
        return call.forward(SYS_FCNTL);
    }
    dup_new(
        &call,
        call.val(0),
        call.val(2),
        cmd == F_DUPFD_CLOEXEC,
        || call.forward(SYS_FCNTL),
    )
});

// clone(args): a fork gives the child every descriptor the parent has.
handler!(clone_handler, |call| {
    if is_thread_clone(call.val(0), call.args[0].1) {
        return call.forward(SYS_CLONE);
    }
    let parent = call.cage();
    let held = with(|st| {
        let held = st.fds.of(parent);
        for (_, conn) in &held {
            st.fds.pin(*conn);
        }
        held
    });
    let ret = call.forward(SYS_CLONE);
    with(|st| {
        for (fd, conn) in &held {
            if ret > 0 {
                st.point(ret as u64, *fd, Some(*conn));
            }
            st.unpin(*conn);
        }
    });
    ret
});

// execve(path, argv, envp): the cage's other threads are gone, and with them their calls.
handler!(execve_handler, |call| {
    let cage = call.cage();
    with(|st| st.gate.forget(cage));
    call.forward(SYS_EXECVE)
});

// exit_group(status)
handler!(exit_group_handler, |call| {
    let cage = call.cage();
    with(|st| {
        st.gate.forget(cage);
        for orphan in st.fds.exit(cage) {
            st.forget(orphan);
        }
    });
    call.forward(SYS_EXIT_GROUP)
});
