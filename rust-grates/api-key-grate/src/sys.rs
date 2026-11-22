//! Syscalls the grate makes, for itself and on behalf of a cage, and copies to and from a cage.
//!
//! Everything goes through `make_threei_call`, so a call continues down the grate stack the same
//! way a forwarded one does.

use std::ffi::CString;
use std::sync::OnceLock;

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::ffi::stat;
use grate_rs::{GrateError, copy_data_between_cages, make_threei_call};

pub const EIO: i64 = 5;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const EINPROGRESS: i64 = 115;

pub const O_CLOEXEC: u64 = 0o2000000;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;
const AF_INET: u64 = 2;
const SOCK_DGRAM: u64 = 2;
const CLOCK_MONOTONIC: u64 = 1;

/// The most a key file may hold. A key is far shorter.
const MAX_FILE_BYTES: usize = 64 << 10;

static ME: OnceLock<u64> = OnceLock::new();

/// This grate's cage id. The handlers run in the grate that called `init`, so the id is asked
/// for once.
pub fn me() -> u64 {
    *ME.get_or_init(grate_rs::getcageid)
}

/// One syscall argument.
#[derive(Clone, Copy)]
pub enum Arg {
    /// A plain value.
    Val(u64),
    /// A pointer into this grate's memory.
    Mine(u64),
    /// A (value, cage) pair received by a handler, passed on as it came.
    From(u64, u64),
}

/// Make syscall `nr` act on cage `target`. Returns the raw result: negative is `-errno`.
pub fn call(target: u64, nr: u64, args: &[Arg]) -> i64 {
    // Grates further down read the calling cage's id from the cage half of a value argument.
    let mut a = [(0u64, target); 6];
    for (slot, arg) in a.iter_mut().zip(args) {
        *slot = match *arg {
            Arg::Val(v) => (v, target),
            Arg::Mine(p) => (p, me() | GRATE_MEMORY_FLAG),
            Arg::From(v, cage) => (v, cage),
        };
    }
    match make_threei_call(
        nr as u32,
        0,
        me(),
        target,
        a[0].0,
        a[0].1,
        a[1].0,
        a[1].1,
        a[2].0,
        a[2].1,
        a[3].0,
        a[3].1,
        a[4].0,
        a[4].1,
        a[5].0,
        a[5].1,
        0,
    ) {
        Ok(ret) => ret,
        Err(GrateError::MakeSyscallError(ret)) => ret,
        Err(_) => -EIO,
    }
}

/// Copy `len` bytes out of a cage, from the (address, cage) pair a handler was given.
pub fn copy_in(from: (u64, u64), len: usize) -> Result<Vec<u8>, i64> {
    let mut data = vec![0u8; len];
    if len == 0 {
        return Ok(data);
    }
    if from.0 == 0 {
        return Err(-EFAULT);
    }
    copy_data_between_cages(
        me(),
        from.1,
        from.0,
        from.1,
        data.as_mut_ptr() as u64,
        me(),
        len as u64,
        0,
    )
    .map_err(|_| -EFAULT)?;
    Ok(data)
}

/// Copy `data` into a cage, to the (address, cage) pair a handler was given.
pub fn copy_out(to: (u64, u64), data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Ok(());
    }
    if to.0 == 0 {
        return Err(-EFAULT);
    }
    copy_data_between_cages(
        me(),
        to.1,
        data.as_ptr() as u64,
        me(),
        to.0,
        to.1,
        data.len() as u64,
        0,
    )
    .map_err(|_| -EFAULT)
}

/// Which file or socket a path or descriptor names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

pub struct Stat {
    pub id: FileId,
    pub regular: bool,
    pub socket: bool,
}

fn stat_result(ret: i64, st: &stat) -> Result<Stat, i64> {
    if ret < 0 {
        return Err(ret);
    }
    Ok(Stat {
        id: FileId {
            dev: st.st_dev,
            ino: st.st_ino,
        },
        regular: st.st_mode & S_IFMT == S_IFREG,
        socket: st.st_mode & S_IFMT == S_IFSOCK,
    })
}

pub fn fstat(target: u64, fd: u64) -> Result<Stat, i64> {
    let mut st = stat::default();
    let ret = call(
        target,
        SYS_FSTAT,
        &[Arg::Val(fd), Arg::Mine(&mut st as *mut stat as u64)],
    );
    stat_result(ret, &st)
}

pub fn close(target: u64, fd: u64) -> i64 {
    call(target, SYS_CLOSE, &[Arg::Val(fd)])
}

/// A new socket in cage `target` that is connected to nothing. It takes the lowest free
/// descriptor number, as any new descriptor would, and holds it.
pub fn spare_socket(target: u64) -> i64 {
    call(
        target,
        SYS_SOCKET,
        &[Arg::Val(AF_INET), Arg::Val(SOCK_DGRAM), Arg::Val(0)],
    )
}

/// Let other threads run for a fifth of a millisecond.
pub fn nap() {
    let pause: [i64; 2] = [0, 200_000];
    let ret = call(
        me(),
        SYS_NANOSLEEP,
        &[
            Arg::Val(CLOCK_MONOTONIC),
            Arg::Val(0),
            Arg::Mine(pause.as_ptr() as u64),
            Arg::Val(0),
        ],
    );
    if ret < 0 {
        call(me(), SYS_SCHED_YIELD, &[]);
    }
}

/// The grate's own descriptor for a file. Closed when dropped.
pub struct OwnFd(u64);

impl OwnFd {
    /// Open `path` for the grate itself.
    pub fn open(path: &str, flags: i32, mode: u32) -> Result<OwnFd, i64> {
        let c_path = CString::new(path).map_err(|_| -EIO)?;
        let fd = call(
            me(),
            SYS_OPEN,
            &[
                Arg::Mine(c_path.as_ptr() as u64),
                Arg::Val(flags as u64),
                Arg::Val(mode as u64),
            ],
        );
        if fd < 0 {
            Err(fd)
        } else {
            Ok(OwnFd(fd as u64))
        }
    }

    pub fn stat(&self) -> Result<Stat, i64> {
        fstat(me(), self.0)
    }

    /// Everything in the file, read from the start without moving any file offset.
    pub fn read_all(&self) -> Result<Vec<u8>, i64> {
        let mut data = Vec::new();
        let mut chunk = vec![0u8; 4096];
        loop {
            let n = call(
                me(),
                SYS_PREAD,
                &[
                    Arg::Val(self.0),
                    Arg::Mine(chunk.as_mut_ptr() as u64),
                    Arg::Val(chunk.len() as u64),
                    Arg::Val(data.len() as u64),
                ],
            );
            if n < 0 {
                return Err(n);
            }
            if n == 0 {
                return Ok(data);
            }
            data.extend_from_slice(&chunk[..n as usize]);
            if data.len() > MAX_FILE_BYTES {
                return Err(-EINVAL);
            }
        }
    }
}

impl Drop for OwnFd {
    fn drop(&mut self) {
        let _ = close(me(), self.0);
    }
}

/// Read a whole file by path, for the grate itself.
pub fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    OwnFd::open(path, fs::O_RDONLY, 0)?.read_all()
}

fn random_bytes(bytes: &mut [u8]) -> Result<(), i64> {
    let n = call(
        me(),
        SYS_GETRANDOM,
        &[
            Arg::Mine(bytes.as_mut_ptr() as u64),
            Arg::Val(bytes.len() as u64),
            Arg::Val(0),
        ],
    );
    if n != bytes.len() as i64 {
        return Err(if n < 0 { n } else { -EIO });
    }
    Ok(())
}

/// A uniform random number below `n`.
pub fn random_below(n: u32) -> Result<u32, i64> {
    // Numbers at the top of the range that would make some results likelier are drawn again.
    let fair = u32::MAX - u32::MAX % n;
    loop {
        let mut bytes = [0u8; 4];
        random_bytes(&mut bytes)?;
        let x = u32::from_ne_bytes(bytes);
        if x < fair {
            return Ok(x % n);
        }
    }
}
