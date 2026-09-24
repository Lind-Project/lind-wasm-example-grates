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
use crate::pipe;

const MAX_PATH_LEN: usize = 256;
const IOV_MAX: usize = 1024;
const LIND_AT_EMPTY_PATH: i32 = 0x1000;
const LIND_AT_SYMLINK_NOFOLLOW: i32 = 0x100;

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
    _arg1cage: u64,
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

    imfs::with_imfs(|state| state.access(arg1cage, &pathname, arg2 as i32))
}

pub extern "C" fn faccessat_handler(
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
    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.accessat(arg1cage, arg1 as i32, &pathname, arg3 as i32))
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

pub extern "C" fn dup_handler(
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
    imfs::with_imfs(|state| state.dup(arg1cage, arg1))
}

pub extern "C" fn dup2_handler(
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
    imfs::with_imfs(|state| state.dup2(arg1cage, arg1, arg2, false))
}

pub extern "C" fn dup3_handler(
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
    if arg1 == arg2 {
        return -22;
    }

    let cloexec = (arg3 as i32 & grate_rs::constants::fs::O_CLOEXEC) != 0;
    imfs::with_imfs(|state| state.dup2(arg1cage, arg1, arg2, cloexec))
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
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();

    // Allocate a local buffer, read into it, then copy to cage.
    let mut buf = vec![0u8; count];

    // Host standard streams (and anything dup'd from them) read from the real fd.
    let ret = if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe { libc::read(hfd, buf.as_mut_ptr() as *mut _, count) as i32 }
    } else if let Some((pipe, pflags)) = pipe::pipe_for_fd(cage_id, fd) {
        pipe_read(&pipe, pflags, &mut buf)
    } else {
        imfs::with_imfs(|state| state.read(cage_id, fd, &mut buf))
    };

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
    }

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
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();

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

    // Host standard streams (and anything dup'd from them) pass through to the real fd.
    // A std fd that bash redirected to an IMFS file resolves to that file instead.
    if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe {
            let ret = libc::write(hfd, buf.as_ptr() as *const _, count);
            return ret as i32;
        }
    }

    if let Some((pipe, pflags)) = pipe::pipe_for_fd(cage_id, fd) {
        return pipe_write(&pipe, pflags, &buf);
    }

    imfs::with_imfs(|state| state.write(cage_id, fd, &buf))
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
    let offset = arg2 as i64;
    let whence = arg3 as i32;

    imfs::with_imfs(|state| state.lseek(arg1cage, arg1, offset, whence))
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
        None => return -14, // EFAULT
    };

    let mode = arg2 as u32;

    imfs::with_imfs(|state| state.chmod(arg1cage, &pathname, mode))
}

pub extern "C" fn fchmodat_handler(
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
    let supported_flags = LIND_AT_SYMLINK_NOFOLLOW | LIND_AT_EMPTY_PATH;
    if (arg4 as i32) & !supported_flags != 0 {
        return -22;
    }

    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.chmodat(arg1cage, arg1 as i32, &pathname, arg3 as u32))
}

pub extern "C" fn chown_handler(
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
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.chown(arg1cage, &pathname, arg2 as u32, arg3 as u32))
}

pub extern "C" fn lchown_handler(
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
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.lchown(arg1cage, &pathname, arg2 as u32, arg3 as u32))
}

pub extern "C" fn fchownat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let supported_flags = LIND_AT_SYMLINK_NOFOLLOW | LIND_AT_EMPTY_PATH;
    if (arg5 as i32) & !supported_flags != 0 {
        return -22;
    }

    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| {
        state.chownat(
            arg1cage,
            arg1 as i32,
            &pathname,
            arg3 as u32,
            arg4 as u32,
            arg5 as i32,
        )
    })
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

    let ret = imfs::with_imfs(|state| state.stat(arg1cage, &pathname, &mut statbuf));

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

pub extern "C" fn lstat_handler(
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

    let ret = imfs::with_imfs(|state| state.lstat(arg1cage, &pathname, &mut statbuf));

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

pub extern "C" fn fstatat_handler(
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
    if arg3 == 0 {
        return -14;
    }

    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    let mut statbuf = stat::default();
    let ret = imfs::with_imfs(|state| {
        state.statat(arg1cage, arg1 as i32, &pathname, &mut statbuf, arg4 as i32)
    });

    if ret < 0 {
        return ret;
    }

    let this_cage = getcageid();
    let _ = copy_data_between_cages(
        this_cage,
        arg3cage,
        &statbuf as *const stat as u64,
        this_cage,
        arg3,
        arg3cage,
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

pub extern "C" fn statfs_handler(
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

    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let mut statbuf = imfs::FsData::default();
    let ret = imfs::with_imfs(|state| state.statfs(arg1cage, &pathname, &mut statbuf));

    if ret < 0 {
        return ret;
    }

    let this_cage = getcageid();
    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        &statbuf as *const imfs::FsData as u64,
        this_cage,
        arg2,
        arg2cage,
        std::mem::size_of::<imfs::FsData>() as u64,
        0,
    );

    ret
}

pub extern "C" fn fstatfs_handler(
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

    let mut statbuf = imfs::FsData::default();
    let ret = imfs::with_imfs(|state| state.fstatfs(arg1cage, arg1, &mut statbuf));

    if ret < 0 {
        return ret;
    }

    let this_cage = getcageid();
    let _ = copy_data_between_cages(
        this_cage,
        arg2cage,
        &statbuf as *const imfs::FsData as u64,
        this_cage,
        arg2,
        arg2cage,
        std::mem::size_of::<imfs::FsData>() as u64,
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

pub extern "C" fn unlinkat_handler(
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
    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.unlinkat(arg1cage, arg1 as i32, &pathname, arg3 as i32))
}

pub extern "C" fn link_handler(
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
    let oldpath = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.link(arg1cage, &oldpath, &newpath))
}

pub extern "C" fn linkat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let oldpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(arg4, arg4cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| {
        state.linkat(
            arg1cage,
            arg1 as i32,
            &oldpath,
            arg3 as i32,
            &newpath,
            arg5 as i32,
        )
    })
}

pub extern "C" fn symlink_handler(
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
    let target = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let linkpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.symlink(arg2cage, &target, &linkpath))
}

pub extern "C" fn symlinkat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let target = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let linkpath = match copy_path_from_cage(arg3, arg3cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.symlinkat(arg2cage, &target, arg2 as i32, &linkpath))
}

fn copy_readlink_target_to_cage(target: String, buf: u64, buf_cage: u64, bufsiz: u64) -> i32 {
    if buf == 0 {
        return -14;
    }

    let copy_len = std::cmp::min(target.len(), bufsiz as usize);
    if copy_len == 0 {
        return 0;
    }

    let this_cage = getcageid();
    match copy_data_between_cages(
        this_cage,
        buf_cage,
        target.as_ptr() as u64,
        this_cage,
        buf,
        buf_cage,
        copy_len as u64,
        0,
    ) {
        Ok(_) => copy_len as i32,
        Err(_) => -14,
    }
}

pub extern "C" fn readlink_handler(
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
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let target = match imfs::with_imfs(|state| state.readlink(arg1cage, &pathname)) {
        Ok(target) => target,
        Err(e) => return e,
    };

    copy_readlink_target_to_cage(target, arg2, arg2cage, arg3)
}

pub extern "C" fn readlinkat_handler(
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
    let pathname = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    let target = match imfs::with_imfs(|state| state.readlinkat(arg1cage, arg1 as i32, &pathname)) {
        Ok(target) => target,
        Err(e) => return e,
    };

    copy_readlink_target_to_cage(target, arg3, arg3cage, arg4)
}

pub extern "C" fn rename_handler(
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
    let oldpath = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(arg2, arg2cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.rename(arg1cage, &oldpath, &newpath))
}

fn renameat_impl(
    olddirfd: u64,
    oldpath_ptr: u64,
    oldpath_cage: u64,
    newdirfd: u64,
    newpath_ptr: u64,
    newpath_cage: u64,
    cage_id: u64,
) -> i32 {
    let oldpath = match copy_path_from_cage(oldpath_ptr, oldpath_cage) {
        Some(p) => p,
        None => return -14,
    };

    let newpath = match copy_path_from_cage(newpath_ptr, newpath_cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| {
        state.renameat(
            cage_id,
            olddirfd as i32,
            &oldpath,
            newdirfd as i32,
            &newpath,
        )
    })
}

pub extern "C" fn renameat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    renameat_impl(arg1, arg2, arg2cage, arg3, arg4, arg4cage, arg1cage)
}

pub extern "C" fn renameat2_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg5 != 0 {
        return -22;
    }

    renameat_impl(arg1, arg2, arg2cage, arg3, arg4, arg4cage, arg1cage)
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

    if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe {
            let ret = libc::pwrite(hfd, buf.as_ptr() as *const _, count, offset);
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
    let ret = if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe { libc::read(hfd, buf.as_mut_ptr() as *mut _, total_len) as i32 }
    } else if let Some((pipe, pflags)) = pipe::pipe_for_fd(cage_id, fd) {
        pipe_read(&pipe, pflags, &mut buf)
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

    if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe { libc::write(hfd, buf.as_ptr() as *const _, buf.len()) as i32 }
    } else if let Some((pipe, pflags)) = pipe::pipe_for_fd(cage_id, fd) {
        pipe_write(&pipe, pflags, &buf)
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
    let ret = if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe { libc::pread(hfd, buf.as_mut_ptr() as *mut _, total_len, offset) as i32 }
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

    if let Some(hfd) = imfs::with_imfs(|state| state.host_std_fd(cage_id, fd)) {
        unsafe { libc::pwrite(hfd, buf.as_ptr() as *const _, buf.len(), offset) as i32 }
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

pub extern "C" fn fchdir_handler(
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
    let fd = arg1;
    let cage_id = arg1cage;

    imfs::with_imfs(|state| state.fchdir(cage_id, fd))
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

    imfs::with_imfs(|state| state.rmdir(arg1cage, &pathname))
}

pub extern "C" fn mkdir_handler(
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
    // Copy the pathname from the cage's memory.
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14, // EFAULT
    };

    let mode = arg2 as u32;

    imfs::with_imfs(|state| state.mkdir(arg1cage, &pathname, mode))
}

pub extern "C" fn mknod_handler(
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
    let pathname = match copy_path_from_cage(arg1, arg1cage) {
        Some(p) => p,
        None => return -14,
    };

    imfs::with_imfs(|state| state.mknod(arg1cage, &pathname, arg2 as u32))
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

pub extern "C" fn sync_file_range_handler(
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

pub extern "C" fn fchmod_handler(
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
    imfs::with_imfs(|state| state.fchmod(arg1cage, arg1, arg2 as u32))
}

pub extern "C" fn utimensat_handler(
    _cageid: u64,
    arg1: u64,
    arg1cage: u64,
    arg2: u64,
    arg2cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    if arg4 != 0 {
        return -22;
    }

    let pathname = if arg2 == 0 {
        None
    } else {
        match copy_path_from_cage(arg2, arg2cage) {
            Some(p) => Some(p),
            None => return -14,
        }
    };

    imfs::with_imfs(|state| state.utimensat(arg1cage, arg1 as i32, pathname.as_deref()))
}

// =====================================================================
//  fork (syscall 57)
//
//  Forward the fork, then clone the fdtables and offset state for the
//  new child cage so it inherits the parent's open fds.
// =====================================================================

pub extern "C" fn fork_handler(
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
    let this_cage = getcageid();

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
        Err(_) => return -1,
    };

    let child_cage_id = ret as u64;

    if !is_thread_clone(arg1, arg1cage) {
        // The child may already be running; keep any fds it created itself.
        let parent_fds = fdtables::return_fdtable_copy(arg1cage);
        let existed = fdtables::check_cage_exists(child_cage_id);
        if !existed {
            fdtables::init_empty_cage(child_cage_id);
        }
        let mut inherited = 0usize;
        for (fd, entry) in &parent_fds {
            if fdtables::translate_virtual_fd(child_cage_id, *fd).is_ok() {
                continue;
            }
            if fdtables::get_specific_virtual_fd(
                child_cage_id,
                *fd,
                entry.fdkind,
                entry.underfd,
                entry.should_cloexec,
                entry.perfdinfo,
            )
            .is_ok()
            {
                inherited += 1;
                pipe::add_ref_for_entry(entry);
            }
        }

        imfs::with_imfs(|state| {
            state.fork(arg1cage, child_cage_id);
        });

        crate::log!(
            "fork: {} -> {} table-existed={} inherited={}",
            arg1cage,
            child_cage_id,
            existed,
            inherited
        );

        if pipe::take_early_exit(child_cage_id) {
            crate::log!("fork: child {} already exited, releasing its fds", child_cage_id);
            fdtables::remove_cage_from_fdtable(child_cage_id);
            imfs::with_imfs(|state| state.forget_cage(child_cage_id));
        }
    }

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

    // Make sure fds 0..3 exist after exec. `empty_fds_for_exec` keeps non-cloexec
    // entries, so an inherited (possibly redirected) std fd survives as-is; only a
    // missing one is re-pointed at the host stream.
    for fd in 0..3 {
        if fdtables::translate_virtual_fd(cage_id, fd).is_err() {
            imfs::with_imfs(|s| s.register_host_std(cage_id, fd));
        }
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

// =====================================================================
//  pipes (syscalls 22 / 293) and cage exit (60 / 231)
// =====================================================================

fn pipe_read(pipe: &pipe::PipeBuffer, pflags: i32, buf: &mut [u8]) -> i32 {
    if pipe::is_write_end(pflags) {
        return -9; // EBADF: read on the write end
    }
    let ret = pipe.read(buf, (pflags & pipe::O_NONBLOCK) != 0);
    crate::log!("pipe read: want {} -> {}", buf.len(), ret);
    ret
}

fn pipe_write(pipe: &pipe::PipeBuffer, pflags: i32, buf: &[u8]) -> i32 {
    if !pipe::is_write_end(pflags) {
        return -9; // EBADF: write on the read end
    }
    let ret = pipe.write(buf, (pflags & pipe::O_NONBLOCK) != 0);
    crate::log!("pipe write: {} -> {}", buf.len(), ret);
    ret
}

fn pipe_impl(cage_id: u64, pipefd_ptr: u64, pipefd_cage: u64, flags: i32) -> i32 {
    if pipefd_ptr == 0 {
        return -14; // EFAULT
    }

    let (rfd, wfd) = match imfs::with_imfs(|state| state.create_pipe(cage_id, flags)) {
        Ok(fds) => fds,
        Err(e) => return e,
    };

    let this_cage = getcageid();
    let fds: [i32; 2] = [rfd, wfd];
    let _ = copy_data_between_cages(
        this_cage,
        pipefd_cage,
        fds.as_ptr() as u64,
        this_cage,
        pipefd_ptr,
        pipefd_cage,
        8,
        0,
    );

    crate::log!("pipe: cage {} -> ({}, {})", cage_id, rfd, wfd);
    0
}

pub extern "C" fn pipe_handler(
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
    pipe_impl(arg1cage, arg1, arg1cage, 0)
}

pub extern "C" fn pipe2_handler(
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
    pipe_impl(arg1cage, arg1, arg1cage, arg2 as i32)
}

/// Release the cage's fds in this grate's own fdtables, so a pipe write end
/// held by an exiting cage is dropped and readers see EOF. Then forward.
fn exit_impl(syscall: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let cage_id = arg_cages[0];
    let this_cage = getcageid();

    let existed = fdtables::check_cage_exists(cage_id);
    if existed {
        fdtables::remove_cage_from_fdtable(cage_id);
    } else {
        pipe::note_early_exit(cage_id);
    }
    imfs::with_imfs(|state| state.forget_cage(cage_id));
    crate::log!("exit: cage {} table-existed={}", cage_id, existed);

    match make_threei_call(
        syscall as u32,
        0,
        this_cage,
        cage_id,
        args[0],
        arg_cages[0],
        args[1],
        arg_cages[1],
        args[2],
        arg_cages[2],
        args[3],
        arg_cages[3],
        args[4],
        arg_cages[4],
        args[5],
        arg_cages[5],
        0,
    ) {
        Ok(r) => r,
        Err(_) => -1,
    }
}

pub extern "C" fn exit_handler(
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
    exit_impl(
        SYS_EXIT,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}

pub extern "C" fn exit_group_handler(
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
    exit_impl(
        SYS_EXIT_GROUP,
        [arg1, arg2, arg3, arg4, arg5, arg6],
        [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage],
    )
}
