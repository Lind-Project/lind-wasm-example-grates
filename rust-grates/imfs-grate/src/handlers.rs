//! Syscall handler functions for the IMFS grate.
//!
//! Each handler is an extern "C" function with the standard grate signature.
//! Handlers that deal with path arguments copy the path from cage memory
//! using copy_data_between_cages. Handlers that deal with buffers (read/write)
//! copy data to/from the cage similarly.

use grate_rs::constants::*;
use grate_rs::{copy_data_between_cages, getcageid, is_thread_clone, make_threei_call};

use crate::imfs;

const MAX_PATH_LEN: usize = 256;

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
    let cage_id = arg1cage;
    let fd = arg1;
    let count = arg3 as usize;
    let this_cage = getcageid();

    // Allocate a local buffer, read into it, then copy to cage.
    let mut buf = vec![0u8; count];

    let ret = imfs::with_imfs(|state| state.read(cage_id, fd, &mut buf));

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

    // Special case: fd 0/1/2 (stdin/stdout/stderr) pass through to real write.
    if fd < 3 {
        // Write directly to the real fd.
        unsafe {
            let ret = libc::write(fd as i32, buf.as_ptr() as *const _, count);
            return ret as i32;
        }
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

    imfs::with_imfs(|state| state.unlink(&pathname))
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

    imfs::with_imfs(|state| state.link(&oldpath, &newpath))
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

// =====================================================================
//  mkdir (syscall 83)
// =====================================================================

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

    imfs::with_imfs(|state| state.mkdir(&pathname, mode))
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
        // Clone the fdtables for the child — inherits all open fds.
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, child_cage_id);

        imfs::with_imfs(|state| {
            state.fork(arg1cage, child_cage_id);
        });
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
