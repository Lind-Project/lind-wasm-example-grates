//! Syscall handler functions for the IMFS grate.
//!
//! Each handler is an extern "C" function with the standard grate signature.
//! Handlers that deal with path arguments copy the path from cage memory
//! using copy_data_between_cages. Handlers that deal with buffers (read/write)
//! copy data to/from the cage similarly.

use grate_rs::constants::*;
use grate_rs::ffi::{iovec, stat};
use grate_rs::{copy_data_between_cages, getcageid, is_thread_clone, make_threei_call};

use crate::imfs;

const MAX_PATH_LEN: usize = 256;
const IOV_MAX: usize = 1024;

/// Copy a null-terminated path string from a cage's address space into a local buffer.
fn copy_path_from_cage(path_ptr: u64, path_cage: u64) -> Option<String> {
    let this_cage = getcageid();
    let mut buf = vec![0u8; MAX_PATH_LEN];

    // copytype=1 means strncpy (stops at null terminator).
    match copy_data_between_cages(
        this_cage,
        path_cage,
        path_ptr,
        path_cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        MAX_PATH_LEN as u64,
        1,
    ) {
        Ok(_) => {}
        Err(_) => return None,
    }

    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH_LEN);
    String::from_utf8(buf[..len].to_vec()).ok()
}

fn copy_iovecs_from_cage(iov_ptr: u64, iov_cage: u64, iovcnt: usize) -> Result<Vec<iovec>, i32> {
    if iovcnt > IOV_MAX {
        return Err(-22); // EINVAL
    }

    let this_cage = getcageid();
    let mut iovecs = vec![iovec::default(); iovcnt];
    let bytes = iovcnt
        .checked_mul(std::mem::size_of::<iovec>())
        .ok_or(-22)?;

    match copy_data_between_cages(
        this_cage,
        iov_cage,
        iov_ptr,
        iov_cage,
        iovecs.as_mut_ptr() as u64,
        this_cage,
        bytes as u64,
        0,
    ) {
        Ok(_) => Ok(iovecs),
        Err(_) => Err(-14), // EFAULT
    }
}

fn total_iovec_len(iovecs: &[iovec]) -> Result<usize, i32> {
    iovecs.iter().try_fold(0usize, |acc, iov| {
        let len = usize::try_from(iov.iov_len).map_err(|_| -22)?;
        acc.checked_add(len).ok_or(-22)
    })
}

pub extern "C" fn enosys_handler(
    _cageid: u64,
    _arg1: u64,
    _arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    -38 // ENOSYS
}

// =====================================================================
//  open (syscall 2)
//
//  arg1 = pathname ptr, arg1cage = cage that owns the path
//  arg2 = flags, arg3 = mode
// =====================================================================

pub extern "C" fn open_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    // This represents the calling cage, i.e. the cage that initially called open. Since arg1,
    // arg1cage represents a path pointer, it might represent the cageid of a transient grate
    // that modified this pointer.
    //
    // We therefore use arg2cage since that represents the `flag` which is an integer and won't be
    // translated.
    let cage_id = arg2cage;

    // Copy the pathname from the cage's memory.
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    let flags = arg2 as i32;
    let mode = arg3 as u32;

    imfs::with_imfs(|state| state.open(cage_id, &pathname, flags, mode))
}

pub extern "C" fn openat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg3cage;
    let dirfd = arg1 as i32;

    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    let flags = arg3 as i32;
    let mode = arg4 as u32;

    imfs::with_imfs(|state| state.openat(cage_id, dirfd, &pathname, flags, mode))
}

pub extern "C" fn getcwd_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg1 == 0 {
        return -14; // EFAULT
    }

    let cwd = match imfs::with_imfs(|state| state.getcwd(arg2cage)) {
        Ok(cwd) => cwd,
        Err(e) => return e,
    };

    let mut buf = cwd.into_bytes();
    buf.push(0);

    if buf.len() > arg2 as usize {
        return -34; // ERANGE
    }

    let this_cage = getcageid();
    match copy_data_between_cages(
        this_cage,
        arg1cage,
        buf.as_ptr() as u64,
        this_cage,
        arg1,
        arg1cage,
        buf.len() as u64,
        0,
    ) {
        Ok(_) => buf.len() as i32,
        Err(_) => -14,
    }
}

pub extern "C" fn access_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.access(arg2cage, &pathname, arg2 as i32))
}

// =====================================================================
//  close (syscall 3)
//
//  arg1 = fd, arg1cage = cage_id
// =====================================================================

pub extern "C" fn close_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    imfs::with_imfs(|state| state.close(arg1cage, arg1))
}

// =====================================================================
//  read (syscall 0)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = buf ptr, arg2cage = cage that owns the buffer
//  arg3 = count
// =====================================================================

pub extern "C" fn read_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    eprintln!(
        "[imfs|read] >> cage={} fd={} buf={:#x} bufcage={:#x} count={}",
        cage_id, fd, arg2, arg2cage, count
    );
    let _ = std::io::stderr().flush();

    // Allocate a local buffer, read into it, then copy to cage.
    let mut buf = vec![0u8; count];

    let ret = imfs::with_imfs(|state| state.read(cage_id, fd, &mut buf));
    eprintln!("[imfs|read]    state.read ret={}", ret);
    let _ = std::io::stderr().flush();

    // Copy result to the cage's buffer (if buf ptr is non-null and read succeeded).
    if ret > 0 && arg2 != 0 {
        let _ = copy_data_between_cages(
            this_cage,
            arg2cage,
            buf.as_ptr() as u64,
            this_cage,
            arg2,
            arg2cage,
            count as u64,
            0, // copytype=0 means raw memcpy
        );
        eprintln!("[imfs|read]    copy_data_between_cages done");
        let _ = std::io::stderr().flush();
    }

    eprintln!("[imfs|read] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  write (syscall 1)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = buf ptr, arg2cage = cage that owns the buffer
//  arg3 = count
// =====================================================================

pub extern "C" fn write_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    eprintln!(
        "[imfs|write] >> cage={} fd={} buf={:#x} bufcage={:#x} count={}",
        cage_id, fd, arg2, arg2cage, count
    );
    let _ = std::io::stderr().flush();

    // Copy the write data from the cage's buffer into a local buffer.
    let mut buf = vec![0u8; count];

    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        arg2,
        arg2cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        count as u64,
        0,
    );
    eprintln!("[imfs|write]    copy_data_between_cages done");
    let _ = std::io::stderr().flush();

    // Special case: fd 0/1/2 (stdin/stdout/stderr) pass through to real write.
    if fd < 3 {
        eprintln!("[imfs|write]    stdio passthrough fd={} count={}", fd, count);
        let _ = std::io::stderr().flush();
        // Write directly to the real fd.
        let ret = unsafe { libc::write(fd as i32, buf.as_ptr() as *const _, count) };
        eprintln!("[imfs|write] << stdio ret={}", ret);
        let _ = std::io::stderr().flush();
        return ret as i32;
    }

    let ret = imfs::with_imfs(|state| state.write(cage_id, fd, &buf));
    eprintln!("[imfs|write] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  lseek (syscall 8)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = offset, arg3 = whence
// =====================================================================

pub extern "C" fn lseek_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    _arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let offset = arg2 as i64;
    let whence = arg3 as i32;
    eprintln!(
        "[imfs|lseek] >> cage={} fd={} offset={} whence={}",
        arg1cage, arg1, offset, whence
    );
    let _ = std::io::stderr().flush();

    let ret = imfs::with_imfs(|state| state.lseek(arg1cage, arg1, offset, whence));
    eprintln!("[imfs|lseek] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  fcntl (syscall 72)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = op, arg3 = arg
// =====================================================================

pub extern "C" fn fcntl_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    _arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let op = arg2 as i32;
    let arg = arg3 as i32;

    imfs::with_imfs(|state| state.fcntl(arg1cage, arg1, op, arg))
}

// =====================================================================
//  getdents (syscall 78)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = dirent buffer ptr, arg2cage = cage that owns the buffer
//  arg3 = count
// =====================================================================

pub extern "C" fn getdents_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();
    let mut buf = vec![0u8; count];

    let ret = imfs::with_imfs(|state| state.getdents(cage_id, fd, &mut buf));

    if ret > 0 && arg2 != 0 {
        let _ = copy_data_between_cages(
            this_cage,
            arg2cage,
            buf.as_ptr() as u64,
            this_cage,
            arg2,
            arg2cage,
            ret as u64,
            0,
        );
    }

    ret
}

// =====================================================================
//  fstat / fxstat (syscall 5)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = stat buffer ptr, arg2cage = cage that owns the buffer
// =====================================================================

pub extern "C" fn chmod_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    let mode = arg2 as u32;

    imfs::with_imfs(|state| state.chmod(arg2cage, &pathname, mode))
}

pub extern "C" fn truncate_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    imfs::with_imfs(|state| state.truncate(arg2cage, &pathname, arg2 as i64))
}

pub extern "C" fn ftruncate_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    imfs::with_imfs(|state| state.ftruncate(arg1cage, arg1, arg2 as i64))
}

pub extern "C" fn stat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg2 == 0 {
        return -14;
    }

    let mut statbuf = stat::default();

    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let ret = imfs::with_imfs(|state| state.stat(arg2cage, &pathname, &mut statbuf));

    if ret < 0 {
        return ret;
    }

    let this_cage = getcageid();
    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        &statbuf as *const stat as u64,
        this_cage,
        arg2,
        arg2cage,
        std::mem::size_of::<stat>() as u64,
        0,
    );

    ret
}

pub extern "C" fn fstat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg2 == 0 {
        return -14; // EFAULT
    }

    let mut statbuf = stat::default();
    let ret = imfs::with_imfs(|state| state.fstat(arg1cage, arg1, &mut statbuf));

    if ret < 0 {
        return ret;
    }

    let this_cage = getcageid();
    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        &statbuf as *const stat as u64,
        this_cage,
        arg2,
        arg2cage,
        std::mem::size_of::<stat>() as u64,
        0,
    );

    ret
}

// =====================================================================
//  unlink (syscall 87)
//
//  arg1 = pathname ptr, arg1cage = cage_id
// =====================================================================

pub extern "C" fn unlink_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.unlink(arg1cage, &pathname))
}

pub extern "C" fn link_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let oldpath = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.link(arg3cage, &oldpath, &newpath))
}

pub extern "C" fn rename_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let oldpath = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.rename(arg3cage, &oldpath, &newpath))
}

// =====================================================================
//  pread (syscall 17)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = buf ptr, arg2cage = buf cage
//  arg3 = count, arg4 = offset
// =====================================================================

pub extern "C" fn pread_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let offset = arg4 as i64;
    let this_cage = getcageid();

    let mut buf = vec![0u8; count];

    let ret = imfs::with_imfs(|state| state.pread(cage_id, fd, &mut buf, offset));

    if ret > 0 && arg2 != 0 {
        let _ = copy_data_between_cages(
            this_cage,
            arg2cage,
            buf.as_ptr() as u64,
            this_cage,
            arg2,
            arg2cage,
            count as u64,
            0,
        );
    }

    ret
}

// =====================================================================
//  pwrite (syscall 18)
//
//  arg1 = fd, arg1cage = cage_id
//  arg2 = buf ptr, arg2cage = buf cage
//  arg3 = count, arg4 = offset
// =====================================================================

pub extern "C" fn pwrite_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let offset = arg4 as i64;
    let this_cage = getcageid();

    let mut buf = vec![0u8; count];

    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        arg2,
        arg2cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        count as u64,
        0,
    );

    // fd < 3 passthrough.
    if fd < 3 {
        unsafe {
            let ret = libc::write(fd as i32, buf.as_ptr() as *const _, count);
            return ret as i32;
        }
    }

    imfs::with_imfs(|state| state.pwrite(cage_id, fd, &buf, offset))
}

pub extern "C" fn readv_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let iovecs = match copy_iovecs_from_cage(arg2, arg2cage, arg3 as usize) {
        Ok(iovecs) => iovecs,
        Err(e) => return e,
    };

    let total_len = match total_iovec_len(&iovecs) {
        Ok(len) => len,
        Err(e) => return e,
    };

    let this_cage = getcageid();
    let mut buf = vec![0u8; total_len];
    let ret = if fd < 3 {
        unsafe { libc::read(fd as i32, buf.as_mut_ptr() as *mut _, total_len) as i32 }
    } else {
        imfs::with_imfs(|state| state.read(cage_id, fd, &mut buf))
    };

    if ret <= 0 {
        return ret;
    }

    let mut copied = 0usize;
    let total_read = ret as usize;
    for iov in &iovecs {
        if copied >= total_read {
            break;
        }
        let len = match usize::try_from(iov.iov_len) {
            Ok(len) => len,
            Err(_) => return -22,
        };
        let chunk_len = (total_read - copied).min(len);
        if chunk_len == 0 {
            continue;
        }
        if copy_data_between_cages(
            this_cage,
            arg2cage,
            buf[copied..copied + chunk_len].as_ptr() as u64,
            this_cage,
            iov.iov_base,
            arg2cage,
            chunk_len as u64,
            0,
        )
        .is_err()
        {
            return -14;
        }
        copied += chunk_len;
    }

    ret
}

pub extern "C" fn writev_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let iovecs = match copy_iovecs_from_cage(arg2, arg2cage, arg3 as usize) {
        Ok(iovecs) => iovecs,
        Err(e) => return e,
    };

    let total_len = match total_iovec_len(&iovecs) {
        Ok(len) => len,
        Err(e) => return e,
    };

    let this_cage = getcageid();
    let mut buf = Vec::with_capacity(total_len);
    for iov in &iovecs {
        let len = match usize::try_from(iov.iov_len) {
            Ok(len) => len,
            Err(_) => return -22,
        };
        if len == 0 {
            continue;
        }

        let start = buf.len();
        buf.resize(start + len, 0);
        if copy_data_between_cages(
            this_cage,
            arg2cage,
            iov.iov_base,
            arg2cage,
            buf[start..start + len].as_mut_ptr() as u64,
            this_cage,
            len as u64,
            0,
        )
        .is_err()
        {
            return -14;
        }
    }

    if fd < 3 {
        unsafe { libc::write(fd as i32, buf.as_ptr() as *const _, buf.len()) as i32 }
    } else {
        imfs::with_imfs(|state| state.write(cage_id, fd, &buf))
    }
}

pub extern "C" fn preadv_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let offset = arg4 as i64;
    let iovecs = match copy_iovecs_from_cage(arg2, arg2cage, arg3 as usize) {
        Ok(iovecs) => iovecs,
        Err(e) => return e,
    };

    let total_len = match total_iovec_len(&iovecs) {
        Ok(len) => len,
        Err(e) => return e,
    };

    let this_cage = getcageid();
    let mut buf = vec![0u8; total_len];
    let ret = if fd < 3 {
        unsafe { libc::pread(fd as i32, buf.as_mut_ptr() as *mut _, total_len, offset) as i32 }
    } else {
        imfs::with_imfs(|state| state.pread(cage_id, fd, &mut buf, offset))
    };

    if ret <= 0 {
        return ret;
    }

    let mut copied = 0usize;
    let total_read = ret as usize;
    for iov in &iovecs {
        if copied >= total_read {
            break;
        }
        let len = match usize::try_from(iov.iov_len) {
            Ok(len) => len,
            Err(_) => return -22,
        };
        let chunk_len = (total_read - copied).min(len);
        if chunk_len == 0 {
            continue;
        }
        if copy_data_between_cages(
            this_cage,
            arg2cage,
            buf[copied..copied + chunk_len].as_ptr() as u64,
            this_cage,
            iov.iov_base,
            arg2cage,
            chunk_len as u64,
            0,
        )
        .is_err()
        {
            return -14;
        }
        copied += chunk_len;
    }

    ret
}

pub extern "C" fn pwritev_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let offset = arg4 as i64;
    let iovecs = match copy_iovecs_from_cage(arg2, arg2cage, arg3 as usize) {
        Ok(iovecs) => iovecs,
        Err(e) => return e,
    };

    let total_len = match total_iovec_len(&iovecs) {
        Ok(len) => len,
        Err(e) => return e,
    };

    let this_cage = getcageid();
    let mut buf = Vec::with_capacity(total_len);
    for iov in &iovecs {
        let len = match usize::try_from(iov.iov_len) {
            Ok(len) => len,
            Err(_) => return -22,
        };
        if len == 0 {
            continue;
        }

        let start = buf.len();
        buf.resize(start + len, 0);
        if copy_data_between_cages(
            this_cage,
            arg2cage,
            iov.iov_base,
            arg2cage,
            buf[start..start + len].as_mut_ptr() as u64,
            this_cage,
            len as u64,
            0,
        )
        .is_err()
        {
            return -14;
        }
    }

    if fd < 3 {
        unsafe { libc::pwrite(fd as i32, buf.as_ptr() as *const _, buf.len(), offset) as i32 }
    } else {
        imfs::with_imfs(|state| state.pwrite(cage_id, fd, &buf, offset))
    }
}

pub extern "C" fn chdir_handler(
    _cageid: u64,
    path: u64,
    path_cage: u64,
    _arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(path, path_cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|s| s.chdir(arg2cage, &pathname))
}

// =====================================================================
//  mkdir (syscall 83)
// =====================================================================

pub extern "C" fn rmdir_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.rmdir(_arg2cage, &pathname))
}

pub extern "C" fn mkdir_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    // Copy the pathname from the cage's memory.
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    let mode = arg2 as u32;

    imfs::with_imfs(|state| state.mkdir(arg2cage, &pathname, mode))
}

pub extern "C" fn mknod_handler(
    _cageid: u64,
    _arg1: u64,
    _arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    -38 // ENOSYS
}

pub extern "C" fn fsync_handler(
    _cageid: u64,
    _arg1: u64,
    _arg1cage: u64,
    _arg2: u64,
    _arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    0
}

// =====================================================================
//  mmap (syscall 9)
//
//  arg1 = addr, arg2 = len, arg3 = prot, arg4 = flags,
//  arg5 = fd, arg6 = offset.
//
//  Only RegMapped imfs files are handled here.  Anonymous mappings
//  (fd == -1 or MAP_ANONYMOUS in flags) and mappings of non-RegMapped
//  fds are forwarded straight to RawPOSIX — imfs has nothing useful
//  to add for those.
// =====================================================================

pub extern "C" fn mmap_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // addr (pointer — cage tag may be a transient grate)
    arg2: u64, arg2cage: u64,    // len
    arg3: u64, arg3cage: u64,    // prot
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,    // fd (integer — reliable for cage_id)
    arg6: u64, arg6cage: u64,    // offset
) -> i32 {
    use std::io::Write;
    // Use an integer-arg's cage tag, not arg1's: arg1 is a pointer
    // (addr hint), so its cage tag may have been rewritten by a
    // transient grate.  arg5 (fd) is an integer; its cage tag is
    // the original caller.  See open_handler's note on this.
    let cage_id = arg5cage;
    eprintln!(
        "[imfs|mmap] >> cage={} addr={:#x} (acage={:#x}) len={:#x} prot={:#x} flags={:#x} fd={} off={:#x}",
        cage_id, arg1, arg1cage, arg2, arg3, arg4, arg5 as i32, arg6
    );
    let _ = std::io::stderr().flush();

    let ret = imfs::with_imfs(|state| {
        state.mmap(
            cage_id,
            arg1,
            arg2 as usize,
            arg3 as i32,
            arg4 as i32,
            arg5,
            arg6,
        )
    });
    eprintln!("[imfs|mmap]    state.mmap ret={:#x}", ret as u32);
    let _ = std::io::stderr().flush();

    // imfs::mmap returns -ENOSYS when the request isn't ours to
    // handle (anonymous, or a non-RegMapped fd) — forward to
    // RawPOSIX in that case so the cage sees normal mmap semantics.
    if ret == -(grate_rs::constants::error::ENOSYS as i32) {
        let thiscage = getcageid();
        eprintln!("[imfs|mmap]    forwarding to RawPOSIX target={}", cage_id);
        let _ = std::io::stderr().flush();
        let fwd = match make_threei_call(
            SYS_MMAP as u32,
            0,
            thiscage,
            cage_id,
            arg1, arg1cage,
            arg2, arg2cage,
            arg3, arg3cage,
            arg4, arg4cage,
            arg5, arg5cage,
            arg6, arg6cage,
            0,
        ) {
            Ok(v) => v,
            Err(grate_rs::GrateError::MakeSyscallError(n)) => n,
            Err(_) => -(grate_rs::constants::error::ENOMEM as i32),
        };
        eprintln!("[imfs|mmap] << forward ret={:#x}", fwd as u32);
        let _ = std::io::stderr().flush();
        return fwd;
    }

    eprintln!("[imfs|mmap] << ret={:#x}", ret as u32);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  munmap (syscall 11)
//
//  arg1 = addr, arg2 = len.
//
//  Always forwards to RawPOSIX (so the cage's vmmap entry is torn
//  down properly).  If the address corresponds to a live imfs
//  RegMapped mapping, also decrements that node's mmap_refs counter
//  so the region can be grown / freed later.
// =====================================================================

pub extern "C" fn munmap_handler(
    _cageid: u64,
    arg1: u64, _arg1cage: u64,   // addr (pointer — cage tag unreliable)
    arg2: u64, arg2cage: u64,    // len (integer — reliable)
    _arg3: u64, _arg3cage: u64,
    _arg4: u64, _arg4cage: u64,
    _arg5: u64, _arg5cage: u64,
    _arg6: u64, _arg6cage: u64,
) -> i32 {
    use std::io::Write;
    eprintln!(
        "[imfs|munmap] >> cage={} addr={:#x} len={:#x}",
        arg2cage, arg1, arg2
    );
    let _ = std::io::stderr().flush();
    let ret = imfs::with_imfs(|state| state.munmap(arg2cage, arg1, arg2 as usize));
    eprintln!("[imfs|munmap] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  exit / exit_group (syscalls 60 / 231)
//
//  A cage exiting without explicit `munmap`s would otherwise leave
//  its RegMapped mappings tracked, pinning the underlying node's
//  mmap_refs counter and blocking future grows.  We hook the exit
//  path to drop those references before forwarding to RawPOSIX.
//
//  We also drop the cage from fdtables and clean up its cwd / fd
//  bookkeeping in imfs.
// =====================================================================

pub extern "C" fn exit_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let cage_id = arg1cage;
    eprintln!("[imfs|exit] >> cage={} status={}", cage_id, arg1 as i32);
    let _ = std::io::stderr().flush();
    imfs::with_imfs(|s| s.cage_exit(cage_id));
    let _ = fdtables::remove_cage_from_fdtable(cage_id);

    let thiscage = getcageid();
    let ret = match make_threei_call(
        SYS_EXIT as u32,
        0,
        thiscage,
        cage_id,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(v) => v,
        Err(grate_rs::GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    };
    eprintln!("[imfs|exit] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

pub extern "C" fn exit_group_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let cage_id = arg1cage;
    eprintln!("[imfs|exit_group] >> cage={} status={}", cage_id, arg1 as i32);
    let _ = std::io::stderr().flush();
    imfs::with_imfs(|s| s.cage_exit(cage_id));
    let _ = fdtables::remove_cage_from_fdtable(cage_id);

    let thiscage = getcageid();
    let ret = match make_threei_call(
        SYS_EXIT_GROUP as u32,
        0,
        thiscage,
        cage_id,
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(v) => v,
        Err(grate_rs::GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    };
    eprintln!("[imfs|exit_group] << ret={}", ret);
    let _ = std::io::stderr().flush();
    ret
}

// =====================================================================
//  fork (syscall 57)
//
//  Forward the fork, then clone the fdtables and offset state for the
//  new child cage so it inherits the parent's open fds.
// =====================================================================

pub extern "C" fn fork_handler(
    cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    use std::io::Write;
    let this_cage = getcageid();
    eprintln!(
        "[imfs|fork] >> caller={} cageid={} clone_args={:#x} (acage={:#x})",
        arg1cage, cageid, arg1, arg1cage
    );
    let _ = std::io::stderr().flush();

    // Forward the fork to the runtime.
    let ret = match make_threei_call(
        SYS_CLONE as u32, // Fork is SYS_CLONE in lind.
        0,
        this_cage,
        arg1cage,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("[imfs|fork] !! SYS_CLONE returned Err");
            let _ = std::io::stderr().flush();
            return -1;
        }
    };
    eprintln!("[imfs|fork]    SYS_CLONE child={}", ret);
    let _ = std::io::stderr().flush();

    let child_cage_id = ret as u64;

    if !is_thread_clone(arg1, arg1cage) {
        eprintln!("[imfs|fork]    copying fdtable+state to child={}", child_cage_id);
        let _ = std::io::stderr().flush();
        // Clone the fdtables for the child — inherits all open fds.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);

        imfs::with_imfs(|state| {
            state.fork(arg1cage, child_cage_id);
        });
    } else {
        eprintln!("[imfs|fork]    thread clone, skipping fdtable copy");
        let _ = std::io::stderr().flush();
    }

    eprintln!("[imfs|fork] << ret={}", child_cage_id);
    let _ = std::io::stderr().flush();
    child_cage_id as i32
}

// =====================================================================
//  exec (syscall 59)
//
//  Close all fds that have the cloexec flag set (via fdtables), then
//  forward the exec to the runtime.
// =====================================================================

pub extern "C" fn exec_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let this_cage = getcageid();

    // Interposing on exec also interposes on the very first exec that launches the first child cage.
    // Since cages are registered to fdtables only on fork, the first cageid won't be registered.
    // Do that here.
    match fdtables::check_cage_exists(cage_id) {
        false => fdtables::init_empty_cage(cage_id),
        true => {}
    };

    // Close all fds with O_CLOEXEC set. fdtables handles this —
    // it calls the registered close handlers for each closed fd.
    fdtables::empty_fds_for_exec(cage_id);

    // fdtables allocates virtual FDs, which start from 0 instead of 3.
    // Unlike regular lind, `underfd` does not point to an actual FD allocation mechanism,
    // so we need to manually open stdin/stdout/stderr file descriptors to reserve them.
    for _fd in 0..3 {
        let _ = fdtables::get_unused_virtual_fd(
            cage_id,
            crate::imfs::IMFS_FDKIND,
            0, // underfd: which node
            false,
            0,
        );
    }

    // Forward the exec to the runtime.
    match make_threei_call(
        SYS_EXEC as u32,
        0,
        this_cage,
        arg1cage,
        arg1,
        arg1cage,
        arg2,
        arg2cage,
        arg3,
        arg3cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}
