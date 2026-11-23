//! The grate keeps no per-descriptor state, because inside fs-routing-clamp it
//! never sees fork, exec or exit. Instead:
//!
//! A single lock serializes all encrypted I/O, which keeps read-modify-write of
//! partial blocks atomic across descriptors and processes. It is never held
//! while forwarding a call that could block.

use std::sync::{Mutex, MutexGuard, OnceLock};

use grate_rs::constants::{
    SYS_FCNTL, SYS_FTRUNCATE, SYS_FXSTAT, SYS_LSEEK, SYS_LSTAT, SYS_MMAP, SYS_NEWFSTATAT, SYS_OPEN,
    SYS_OPENAT, SYS_PREAD, SYS_PREADV, SYS_PWRITE, SYS_PWRITEV, SYS_READ, SYS_READV, SYS_TRUNCATE,
    SYS_WRITE, SYS_WRITEV, SYS_XSTAT,
};

use crypt_grate::cipher::ContentCipher;
use crypt_grate::cryptfile::{CHUNK_BYTES, CryptFile, checked_offset};
use crypt_grate::format::logical_size;

use crate::sys::{
    Args, CageFd, F_GETFL, F_SETFL, S_IFMT, S_IFREG, SEEK_CUR, SEEK_SET, call, copy_from_cage,
    copy_to_cage, fill_random, is_regular,
};

pub static CIPHER: OnceLock<ContentCipher> = OnceLock::new();
static IO_LOCK: Mutex<()> = Mutex::new(());

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_NONBLOCK: u64 = 0o4000;
const O_APPEND: u64 = 0o2000;
const O_CLOEXEC: u64 = 0o2000000;
const MAP_ANONYMOUS: u64 = 0x20;

const ENXIO: i64 = 6;
const EACCES: i64 = 13;
const ENODEV: i64 = 19;
const EINVAL: i64 = 22;

const IOV_MAX: u64 = 1024;
const IOVEC_SIZE: usize = 16; // grate_rs::ffi::iovec: { iov_base: u64, iov_len: u64 }
const STAT_MODE_OFFSET: usize = 16;
const STAT_SIZE_OFFSET: usize = 40;

macro_rules! handler {
    ($name:ident, $imp:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
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
            let args = Args {
                val: [a1, a2, a3, a4, a5, a6],
                cage: [c1, c2, c3, c4, c5, c6],
            };
            $imp(args)
        }
    };
}

handler!(open_handler, |a| open_impl(SYS_OPEN, a, 1));
handler!(openat_handler, |a| open_impl(SYS_OPENAT, a, 2));
handler!(read_handler, |a| io_impl(SYS_READ, a, false, false, false));
handler!(write_handler, |a| io_impl(SYS_WRITE, a, true, false, false));
handler!(pread_handler, |a| io_impl(SYS_PREAD, a, false, true, false));
handler!(pwrite_handler, |a| io_impl(
    SYS_PWRITE, a, true, true, false
));
handler!(readv_handler, |a| io_impl(SYS_READV, a, false, false, true));
handler!(writev_handler, |a| io_impl(
    SYS_WRITEV, a, true, false, true
));
handler!(preadv_handler, |a| io_impl(
    SYS_PREADV, a, false, true, true
));
handler!(pwritev_handler, |a| io_impl(
    SYS_PWRITEV,
    a,
    true,
    true,
    true
));
handler!(lseek_handler, lseek_impl);
handler!(fstat_handler, |a| stat_impl(SYS_FXSTAT, a, 1));
handler!(stat_handler, |a| stat_impl(SYS_XSTAT, a, 1));
handler!(lstat_handler, |a| stat_impl(SYS_LSTAT, a, 1));
handler!(fstatat_handler, |a| stat_impl(SYS_NEWFSTATAT, a, 2));
handler!(ftruncate_handler, ftruncate_impl);
handler!(truncate_handler, truncate_impl);
handler!(fcntl_handler, fcntl_impl);
handler!(mmap_handler, mmap_impl);

fn lock() -> MutexGuard<'static, ()> {
    IO_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn forward(nr: u64, a: &Args) -> i64 {
    call(nr, a.cage[0], a)
}

fn with_file<R>(
    io: &mut CageFd,
    f: impl FnOnce(&mut CryptFile<'_, CageFd>) -> Result<R, i32>,
) -> Result<R, i64> {
    let cipher = CIPHER.get().expect("key is loaded before any cage runs");
    let mut random = |b: &mut [u8]| fill_random(b);
    let mut file = CryptFile::new(io, cipher, &mut random);
    f(&mut file).map_err(|e| -(e as i64))
}

/// The fd in argument 1 if it is a regular file (encrypted), `None` if the
/// call should be forwarded as is, or the fstat error.
fn encrypted_fd(a: &Args) -> Result<Option<CageFd>, i64> {
    let io = CageFd::new(a.val[0], a.cage[0]);
    let st = io.fstat()?;
    Ok(if is_regular(&st) { Some(io) } else { None })
}

/// Whether this descriptor was opened (or set) with O_APPEND; see module docs.
fn is_append(io: &CageFd) -> Result<bool, i64> {
    let fl = io.fcntl(F_GETFL, 0);
    if fl < 0 {
        Err(fl)
    } else {
        Ok(fl as u64 & O_NONBLOCK != 0)
    }
}

fn finish(r: Result<u64, i64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// open / openat. Regular files are opened read-write (partial-block writes
/// must read the block first) and without O_APPEND (see module docs).
fn open_impl(nr: u64, a: Args, flag_idx: usize) -> i64 {
    let flags = a.val[flag_idx];
    let want_append = flags & O_APPEND != 0;
    let base = flags & !O_APPEND;
    let upgraded = if flags & O_ACCMODE == O_WRONLY {
        (base & !O_ACCMODE) | O_RDWR
    } else {
        base
    };

    let mut first = a;
    first.val[flag_idx] = upgraded;
    let mut fd = call(nr, a.cage[0], &first);
    if fd == -EACCES && upgraded != base {
        // Write-only permission: open write-only. Whole-block writes still
        // work; writes that must merge into an existing block will fail.
        first.val[flag_idx] = base;
        fd = call(nr, a.cage[0], &first);
    }
    if fd < 0 {
        return fd;
    }

    let io = CageFd::new(fd as u64, a.cage[0]);
    let st = match io.fstat() {
        Ok(st) => st,
        Err(e) => {
            io.close();
            return e;
        }
    };
    if !is_regular(&st) {
        if first.val[flag_idx] == flags {
            return fd;
        }

        io.close();
        return forward(nr, &a);
    }

    if want_append || flags & O_NONBLOCK != 0 {
        let fl = io.fcntl(F_GETFL, 0);
        let r = if fl < 0 {
            fl
        } else {
            let marker = if want_append { O_NONBLOCK } else { 0 };
            io.fcntl(F_SETFL, (fl as u64 & !O_NONBLOCK) | marker)
        };
        if r < 0 {
            io.close();
            return r;
        }
    }
    fd
}

/// read, write, pread, pwrite, readv, writev, preadv, pwritev.
///
/// `positioned`: the offset is argument 4 and the file offset is not moved.
/// `vectored`: argument 2 is an iovec array of argument 3 entries.
fn io_impl(nr: u64, a: Args, write: bool, positioned: bool, vectored: bool) -> i64 {
    let mut io = match encrypted_fd(&a) {
        Err(e) => return e,
        Ok(None) => return forward(nr, &a),
        Ok(Some(io)) => io,
    };

    // (address, length) segments in the cage's memory.
    let mem_cage = a.cage[1];
    let segments: Vec<(u64, u64)> = if vectored {
        let count = a.val[2];
        if count > IOV_MAX {
            return -EINVAL;
        }
        let raw = match copy_from_cage(a.val[1], mem_cage, count as usize * IOVEC_SIZE) {
            Ok(raw) => raw,
            Err(e) => return e,
        };
        raw.chunks_exact(IOVEC_SIZE)
            .map(|c| {
                (
                    u64::from_le_bytes(c[0..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..16].try_into().unwrap()),
                )
            })
            .collect()
    } else {
        vec![(a.val[1], a.val[2])]
    };

    let _guard = lock();
    let start = if positioned {
        match checked_offset(a.val[3] as i64) {
            Ok(off) => off,
            Err(e) => return -(e as i64),
        }
    } else {
        let at_end = write
            && match is_append(&io) {
                Ok(v) => v,
                Err(e) => return e,
            };
        let r = if at_end {
            with_file(&mut io, |f| f.len())
        } else {
            io.lseek(0, SEEK_CUR)
        };
        match r {
            Ok(off) => off,
            Err(e) => return e,
        }
    };

    let mut total = 0u64;
    let mut failure = None;
    for (addr, len) in segments {
        let r = if write {
            write_from_cage(&mut io, start + total, addr, mem_cage, len)
        } else {
            read_to_cage(&mut io, start + total, addr, mem_cage, len)
        };
        match r {
            Ok(n) => {
                total += n;
                if n < len {
                    break; // short read at end of file
                }
            }
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }

    if !positioned
        && total > 0
        && let Err(e) = io.lseek(start + total, SEEK_SET)
    {
        return e;
    }
    match failure {
        Some(e) if total == 0 => e,
        _ => total as i64,
    }
}

/// Decrypts up to `count` bytes at plaintext offset `off` into the cage.
fn read_to_cage(
    io: &mut CageFd,
    off: u64,
    dst: u64,
    dst_cage: u64,
    count: u64,
) -> Result<u64, i64> {
    let mut done = 0u64;
    while done < count {
        let want = (count - done).min(CHUNK_BYTES);
        let mut buf = vec![0u8; want as usize];
        let step = with_file(io, |f| f.read_at(off + done, &mut buf))
            .and_then(|got| copy_to_cage(&buf[..got], dst + done, dst_cage).map(|_| got as u64));
        match step {
            Ok(got) => {
                done += got;
                if got < want {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// Encrypts `count` bytes from the cage to plaintext offset `off`.
fn write_from_cage(
    io: &mut CageFd,
    off: u64,
    src: u64,
    src_cage: u64,
    count: u64,
) -> Result<u64, i64> {
    let mut done = 0u64;
    while done < count {
        let n = (count - done).min(CHUNK_BYTES);
        let step = copy_from_cage(src + done, src_cage, n as usize)
            .and_then(|buf| with_file(io, |f| f.write_at(off + done, &buf)));
        match step {
            Ok(_) => done += n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}


fn lseek_impl(a: Args) -> i64 {
    let mut io = match encrypted_fd(&a) {
        Err(e) => return e,
        Ok(None) => return forward(SYS_LSEEK, &a),
        Ok(Some(io)) => io,
    };
    let offset = a.val[1] as i64 as i128;
    let _guard = lock();
    let target: Result<i128, i64> = (|| {
        let size = with_file(&mut io, |f| f.len())? as i128;
        Ok(match a.val[2] {
            0 => offset,                                  // SEEK_SET
            1 => io.lseek(0, SEEK_CUR)? as i128 + offset, // SEEK_CUR
            2 => size + offset,                           // SEEK_END
            3 if offset >= 0 && offset < size => offset,  // SEEK_DATA: no holes
            4 if offset >= 0 && offset < size => size,    // SEEK_HOLE: only at EOF
            3 | 4 => return Err(-ENXIO),
            _ => return Err(-EINVAL),
        })
    })();
    match target {
        Ok(t) if (0..=i64::MAX as i128).contains(&t) => finish(io.lseek(t as u64, SEEK_SET)),
        Ok(_) => -EINVAL,
        Err(e) => e,
    }
}

/// fstat, stat, lstat, newfstatat: forward, then report the plaintext size of
/// regular files. `buf_idx` is the index of the struct stat pointer.
fn stat_impl(nr: u64, a: Args, buf_idx: usize) -> i64 {
    let r = forward(nr, &a);
    if r < 0 {
        return r;
    }
    let (ptr, cage) = (a.val[buf_idx], a.cage[buf_idx]);
    let head = match copy_from_cage(ptr, cage, STAT_SIZE_OFFSET + 8) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let mode = u32::from_le_bytes(
        head[STAT_MODE_OFFSET..STAT_MODE_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if mode & S_IFMT != S_IFREG {
        return r;
    }
    let physical = u64::from_le_bytes(
        head[STAT_SIZE_OFFSET..STAT_SIZE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    match copy_to_cage(
        &logical_size(physical).to_le_bytes(),
        ptr + STAT_SIZE_OFFSET as u64,
        cage,
    ) {
        Ok(()) => r,
        Err(e) => e,
    }
}

fn ftruncate_impl(a: Args) -> i64 {
    let mut io = match encrypted_fd(&a) {
        Err(e) => return e,
        Ok(None) => return forward(SYS_FTRUNCATE, &a),
        Ok(Some(io)) => io,
    };
    let len = match checked_offset(a.val[1] as i64) {
        Ok(l) => l,
        Err(e) => return -(e as i64),
    };
    let _guard = lock();
    finish(with_file(&mut io, |f| f.set_len(len)).map(|_| 0))
}

/// truncate(path, len): opens the file in the cage to resize it through the
/// same block logic as ftruncate.
fn truncate_impl(a: Args) -> i64 {
    let len = match checked_offset(a.val[1] as i64) {
        Ok(l) => l,
        Err(e) => return -(e as i64),
    };
    let cage = a.cage[0];
    let open = Args {
        val: [a.val[0], O_RDWR | O_CLOEXEC, 0, 0, 0, 0],
        cage: [cage, 0, 0, 0, 0, 0],
    };
    let fd = call(SYS_OPEN, cage, &open);
    if fd < 0 {
        return fd;
    }
    let mut io = CageFd::new(fd as u64, cage);
    let r = match io.fstat() {
        Err(e) => e,
        Ok(st) if !is_regular(&st) => {
            io.close();
            return forward(SYS_TRUNCATE, &a);
        }
        Ok(_) => {
            let _guard = lock();
            finish(with_file(&mut io, |f| f.set_len(len)).map(|_| 0))
        }
    };
    io.close();
    r
}

/// Translates O_APPEND <-> O_NONBLOCK in F_GETFL / F_SETFL (see module docs).
fn fcntl_impl(a: Args) -> i64 {
    let cmd = a.val[1];
    if cmd != F_GETFL && cmd != F_SETFL {
        return forward(SYS_FCNTL, &a);
    }
    match encrypted_fd(&a) {
        Err(e) => return e,
        Ok(None) => return forward(SYS_FCNTL, &a),
        Ok(Some(_)) => {}
    }
    if cmd == F_GETFL {
        let fl = forward(SYS_FCNTL, &a);
        if fl < 0 {
            return fl;
        }
        let fl = fl as u64;
        let append = if fl & O_NONBLOCK != 0 { O_APPEND } else { 0 };
        return ((fl & !O_NONBLOCK) | append) as i64;
    }
    let requested = a.val[2];
    let marker = if requested & O_APPEND != 0 {
        O_NONBLOCK
    } else {
        0
    };
    let mut b = a;
    b.val[2] = (requested & !(O_APPEND | O_NONBLOCK)) | marker;
    forward(SYS_FCNTL, &b)
}

/// File-backed mappings would expose ciphertext (and writes through them would
/// bypass encryption), so they are refused for encrypted files.
fn mmap_impl(a: Args) -> i64 {
    let fd = a.val[4] as i64 as i32;
    if a.val[3] & MAP_ANONYMOUS != 0 || fd < 0 {
        return forward(SYS_MMAP, &a);
    }
    match CageFd::new(a.val[4], a.cage[4]).fstat() {
        Ok(st) if is_regular(&st) => -ENODEV,
        _ => forward(SYS_MMAP, &a),
    }
}
