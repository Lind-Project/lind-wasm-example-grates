//! Syscalls the grate makes, for itself and on behalf of a cage.
//!
//! Everything goes through `make_threei_call` (not `std::fs`, whose metadata is unreliable under
//! lind-wasm), so a call continues down the grate stack the same way a forwarded one does.

use std::ffi::CString;
use std::sync::OnceLock;

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::*;
use grate_rs::ffi::stat;
use grate_rs::{GrateError, make_threei_call};

pub const EPERM: i64 = 1;
pub const EIO: i64 = 5;
pub const EACCES: i64 = 13;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EFBIG: i64 = 27;

pub const O_NOFOLLOW: u64 = 0o400000;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const LOCK_EX: u64 = 2;
const LOCK_UN: u64 = 8;

/// A file bigger than this is not served as a view. A grate has 64 MiB of memory in all, and
/// serving a view holds the file and its rendering at once.
pub const MAX_VIEW_BYTES: usize = 8 << 20;

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

/// Which file a path or descriptor names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

pub struct Stat {
    pub id: FileId,
    pub regular: bool,
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
    })
}

/// `stat` (or `lstat` when `follow` is false) of a path argument, as cage `target`.
pub fn stat_path(target: u64, path: Arg, follow: bool) -> Result<Stat, i64> {
    let mut st = stat::default();
    let nr = if follow { SYS_STAT } else { SYS_LSTAT };
    let ret = call(target, nr, &[path, Arg::Mine(&mut st as *mut stat as u64)]);
    stat_result(ret, &st)
}

/// `fstatat` of a path argument relative to `dirfd`, as cage `target`.
pub fn stat_at(target: u64, dirfd: Arg, path: Arg, follow: bool) -> Result<Stat, i64> {
    let mut st = stat::default();
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    let ret = call(
        target,
        SYS_NEWFSTATAT,
        &[
            dirfd,
            path,
            Arg::Mine(&mut st as *mut stat as u64),
            Arg::Val(flags),
        ],
    );
    stat_result(ret, &st)
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
        if fd < 0 { Err(fd) } else { Ok(OwnFd(fd as u64)) }
    }

    pub fn stat(&self) -> Result<Stat, i64> {
        fstat(me(), self.0)
    }

    /// Everything in the file, read from the start without moving any file offset.
    pub fn read_all(&self) -> Result<Vec<u8>, i64> {
        let mut data = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
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
            if data.len() > MAX_VIEW_BYTES {
                return Err(-EFBIG);
            }
        }
    }

    /// Make the file hold exactly `data`.
    pub fn write_all(&self, data: &[u8]) -> Result<(), i64> {
        let mut done = 0;
        while done < data.len() {
            let n = call(
                me(),
                SYS_PWRITE,
                &[
                    Arg::Val(self.0),
                    Arg::Mine(data[done..].as_ptr() as u64),
                    Arg::Val((data.len() - done) as u64),
                    Arg::Val(done as u64),
                ],
            );
            if n <= 0 {
                return Err(if n < 0 { n } else { -EIO });
            }
            done += n as usize;
        }
        let ret = call(
            me(),
            SYS_FTRUNCATE,
            &[Arg::Val(self.0), Arg::Val(data.len() as u64)],
        );
        if ret < 0 { Err(ret) } else { Ok(()) }
    }

    /// Take or drop an exclusive `flock`, to keep other instances of this grate out while a file
    /// is rewritten. Best effort: a filesystem without `flock` is still served.
    pub fn lock(&self, exclusive: bool) {
        let op = if exclusive { LOCK_EX } else { LOCK_UN };
        let _ = call(me(), SYS_FLOCK, &[Arg::Val(self.0), Arg::Val(op)]);
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

pub fn unlink(path: &str) {
    if let Ok(c_path) = CString::new(path) {
        let _ = call(me(), SYS_UNLINK, &[Arg::Mine(c_path.as_ptr() as u64)]);
    }
}

/// Make sure `path` is a directory, creating it (as a shared, sticky one) if nothing is there.
pub fn ensure_dir(path: &str) -> Result<(), i64> {
    let c_path = CString::new(path).map_err(|_| -EIO)?;
    let name = Arg::Mine(c_path.as_ptr() as u64);
    let made = call(me(), SYS_MKDIR, &[name, Arg::Val(0o1777)]);
    if made < 0 && made != -EEXIST {
        return Err(made);
    }
    let mut st = stat::default();
    let ret = call(
        me(),
        SYS_STAT,
        &[name, Arg::Mine(&mut st as *mut stat as u64)],
    );
    if ret < 0 {
        return Err(ret);
    }
    if st.st_mode & S_IFMT != S_IFDIR {
        return Err(-ENOTDIR);
    }
    Ok(())
}

/// Sixteen random bytes as hex, for a file name nobody can guess.
pub fn random_name() -> Result<String, i64> {
    let mut bytes = [0u8; 16];
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
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The effective uid of cage `target`.
pub fn geteuid(target: u64) -> Result<u32, i64> {
    let ret = call(target, SYS_GETEUID, &[]);
    if ret < 0 { Err(ret) } else { Ok(ret as u32) }
}
