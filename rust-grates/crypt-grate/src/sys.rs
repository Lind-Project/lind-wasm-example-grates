//! 3i plumbing: issuing syscalls on the cage's behalf, moving bytes between
//! the cage and the grate, and a [`BlockIo`] over a cage file descriptor.

use grate_rs::constants::lind::GRATE_MEMORY_FLAG;
use grate_rs::constants::{
    SYS_CLOSE, SYS_FCNTL, SYS_FTRUNCATE, SYS_FXSTAT, SYS_LSEEK, SYS_PREAD, SYS_PWRITE,
};
use grate_rs::ffi::stat;
use grate_rs::{GrateError, copy_data_between_cages, getcageid, make_threei_call};

use crypt_grate::cryptfile::BlockIo;
use crypt_grate::errno::EIO;

pub const EFAULT: i64 = 14;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;

pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;

pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;

/// The six (value, cageid) argument pairs of a syscall.
#[derive(Clone, Copy)]
pub struct Args {
    pub val: [u64; 6],
    pub cage: [u64; 6],
}

impl Args {
    /// Arguments for a call the grate makes itself on `cage`'s fd.
    pub fn fd_call(fd: u64, cage: u64, rest: [(u64, u64); 5]) -> Self {
        let mut a = Args {
            val: [0; 6],
            cage: [0; 6],
        };
        a.val[0] = fd;
        a.cage[0] = cage;
        for (i, (v, c)) in rest.into_iter().enumerate() {
            a.val[i + 1] = v;
            a.cage[i + 1] = c;
        }
        a
    }
}

/// Issues syscall `nr` through 3i, acting on `target` (the cage whose fd table
/// and memory the call uses). Returns the raw result: >= 0 or -errno.
pub fn call(nr: u64, target: u64, a: &Args) -> i64 {
    match make_threei_call(
        nr as u32,
        0,
        getcageid(),
        target,
        a.val[0],
        a.cage[0],
        a.val[1],
        a.cage[1],
        a.val[2],
        a.cage[2],
        a.val[3],
        a.cage[3],
        a.val[4],
        a.cage[4],
        a.val[5],
        a.cage[5],
        0, // TRANSLATE_ERRNO_OFF: results go back to the cage's libc
    ) {
        Ok(r) => r,
        Err(GrateError::MakeSyscallError(r)) => r,
        Err(_) => -(EIO as i64),
    }
}

/// A pointer into the grate's own memory, as a syscall argument cage id.
pub fn grate_mem() -> u64 {
    getcageid() | GRATE_MEMORY_FLAG
}

/// Copies `len` bytes from the cage at `src` into a new grate buffer.
pub fn copy_from_cage(src: u64, src_cage: u64, len: usize) -> Result<Vec<u8>, i64> {
    let me = getcageid();
    let mut buf = vec![0u8; len];
    if len > 0 {
        copy_data_between_cages(
            me,
            src_cage,
            src,
            src_cage,
            buf.as_mut_ptr() as u64,
            me,
            len as u64,
            0,
        )
        .map_err(|_| -EFAULT)?;
    }
    Ok(buf)
}

/// Copies `data` into the cage at `dst`. Binary copy (copytype 0): a string
/// copy would stop at the first zero byte.
pub fn copy_to_cage(data: &[u8], dst: u64, dst_cage: u64) -> Result<(), i64> {
    if data.is_empty() {
        return Ok(());
    }
    let me = getcageid();
    copy_data_between_cages(
        me,
        dst_cage,
        data.as_ptr() as u64,
        me,
        dst,
        dst_cage,
        data.len() as u64,
        0,
    )
    .map_err(|_| -EFAULT)
}

/// A file descriptor in a cage's fd table, used from the grate.
pub struct CageFd {
    pub fd: u64,
    pub cage: u64,
}

impl CageFd {
    pub fn new(fd: u64, cage: u64) -> Self {
        Self { fd, cage }
    }

    fn fd_call(&self, nr: u64, rest: [(u64, u64); 5]) -> i64 {
        call(nr, self.cage, &Args::fd_call(self.fd, self.cage, rest))
    }

    pub fn fstat(&self) -> Result<stat, i64> {
        let mut st = stat::default();
        let r = self.fd_call(
            SYS_FXSTAT,
            [
                (&mut st as *mut stat as u64, grate_mem()),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
            ],
        );
        if r < 0 { Err(r) } else { Ok(st) }
    }

    pub fn lseek(&self, offset: u64, whence: u64) -> Result<u64, i64> {
        let r = self.fd_call(
            SYS_LSEEK,
            [(offset, 0), (whence, 0), (0, 0), (0, 0), (0, 0)],
        );
        if r < 0 { Err(r) } else { Ok(r as u64) }
    }

    pub fn fcntl(&self, cmd: u64, arg: u64) -> i64 {
        self.fd_call(SYS_FCNTL, [(cmd, 0), (arg, 0), (0, 0), (0, 0), (0, 0)])
    }

    pub fn close(&self) {
        let _ = self.fd_call(SYS_CLOSE, [(0, 0); 5]);
    }
}

pub fn is_regular(st: &stat) -> bool {
    st.st_mode & S_IFMT == S_IFREG
}

impl BlockIo for CageFd {
    fn pread(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
        let r = self.fd_call(
            SYS_PREAD,
            [
                (buf.as_mut_ptr() as u64, grate_mem()),
                (buf.len() as u64, 0),
                (offset, 0),
                (0, 0),
                (0, 0),
            ],
        );
        if r < 0 {
            Err(-r as i32)
        } else {
            Ok(r as usize)
        }
    }

    fn pwrite(&mut self, buf: &[u8], offset: u64) -> Result<usize, i32> {
        let r = self.fd_call(
            SYS_PWRITE,
            [
                (buf.as_ptr() as u64, grate_mem()),
                (buf.len() as u64, 0),
                (offset, 0),
                (0, 0),
                (0, 0),
            ],
        );
        if r < 0 {
            Err(-r as i32)
        } else {
            Ok(r as usize)
        }
    }

    fn size(&mut self) -> Result<u64, i32> {
        self.fstat().map(|st| st.st_size).map_err(|e| -e as i32)
    }

    fn set_size(&mut self, size: u64) -> Result<(), i32> {
        let r = self.fd_call(SYS_FTRUNCATE, [(size, 0), (0, 0), (0, 0), (0, 0), (0, 0)]);
        if r < 0 { Err(-r as i32) } else { Ok(()) }
    }
}

/// Fills `buf` with secure random bytes from the Lind libc.
pub fn fill_random(buf: &mut [u8]) {
    unsafe extern "C" {
        fn getrandom(buf: *mut core::ffi::c_void, buflen: usize, flags: u32) -> isize;
    }
    let mut done = 0;
    while done < buf.len() {
        let rest = &mut buf[done..];
        let n = unsafe { getrandom(rest.as_mut_ptr() as *mut core::ffi::c_void, rest.len(), 0) };
        if n <= 0 {
            // Never fall back to weak randomness: a repeated GCM nonce breaks
            // confidentiality and authenticity of the affected blocks.
            eprintln!("[crypt-grate] getrandom failed ({n}); aborting");
            std::process::abort();
        }
        done += n as usize;
    }
}
