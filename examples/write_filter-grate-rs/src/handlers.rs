use grate_rs::{
    constants::{
        SYS_CLONE, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_OPEN, SYS_PWRITE, SYS_WRITE, SYS_WRITEV,
        error::EPERM,
    },
    copy_data_between_cages, getcageid, make_threei_call,
};
use std::path::Path;

const MAX_PATH: usize = 256;

fn is_fd_blocked(cageid: u64, fd: u64) -> bool {
    match fdtables::translate_virtual_fd(cageid, fd) {
        Ok(entry) => entry.perfdinfo == 1,
        Err(_) => false,
    }
}

// open() syscall handler
pub extern "C" fn open_handler(
    _cageid: u64,
    filename: u64,
    filename_cage: u64,
    flags: u64,
    flags_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();
    let cage_id = filename_cage;

    let mut buf = vec![0u8; MAX_PATH];

    // copy filname passed to open()
    let _ = copy_data_between_cages(
        this_cage,
        filename_cage,
        filename,
        filename_cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        MAX_PATH as u64,
        1,
    );

    let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_PATH);
    let path_str = String::from_utf8_lossy(&buf[..len]).to_string();

    let is_log = Path::new(&path_str).extension().and_then(|s| s.to_str()) == Some("log");

    // forward open() syscall
    let ret = match make_threei_call(
        SYS_OPEN as u32,
        0,
        this_cage,
        filename_cage,
        filename,
        filename_cage,
        flags,
        flags_cage,
        mode,
        mode_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    };

    let _ = fdtables::get_specific_virtual_fd(cage_id, ret as u64, 0, ret as u64, false, 0);

    if !is_log {
        let _ = fdtables::set_perfdinfo(cage_id, ret as u64, 1);
    }

    ret
}

// write() syscall handler
pub extern "C" fn write_handler(
    _cageid: u64,
    fd: u64,
    fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    count_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    if is_fd_blocked(fd_cage, fd) {
        return -EPERM;
    }

    match make_threei_call(
        SYS_WRITE as u32,
        0,
        this_cage,
        fd_cage,
        fd,
        fd_cage,
        buf,
        buf_cage,
        count,
        count_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

pub extern "C" fn writev_handler(
    _cageid: u64,
    fd: u64,
    fd_cage: u64,
    iovec: u64,
    iovec_cage: u64,
    vlen: u64,
    vlen_cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    if is_fd_blocked(fd_cage, fd) {
        return -EPERM;
    }

    match make_threei_call(
        SYS_WRITEV as u32,
        0,
        this_cage,
        fd_cage,
        fd,
        fd_cage,
        iovec,
        iovec_cage,
        vlen,
        vlen_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

pub extern "C" fn pwrite_handler(
    _cageid: u64,
    fd: u64,
    fd_cage: u64,
    buf: u64,
    buf_cage: u64,
    count: u64,
    count_cage: u64,
    pos: u64,
    pos_cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let this_cage = getcageid();

    if is_fd_blocked(fd_cage, fd) {
        return -EPERM; // Return positive EPERM
    }

    match make_threei_call(
        SYS_PWRITE as u32,
        0,
        this_cage,
        fd_cage,
        fd,
        fd_cage,
        buf,
        buf_cage,
        count,
        count_cage,
        pos,
        pos_cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

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
    let cage_id = arg1cage;

    let ret = match make_threei_call(
        SYS_CLONE as u32,
        0,
        this_cage,
        cage_id,
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
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret <= 0 {
        return ret;
    }

    let child_cageid = ret as u64;
    let _ = fdtables::copy_fdtable_for_cage(cage_id, child_cageid as u64);

    child_cageid as i32
}

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
    let this_cage = getcageid();
    let cage_id = arg1cage;

    fdtables::empty_fds_for_exec(cage_id);

    for fd in 0..3u64 {
        let _ = fdtables::get_specific_virtual_fd(cage_id, fd, 0, fd, false, 0);
    }

    match make_threei_call(
        SYS_EXECVE as u32,
        0,
        this_cage,
        cage_id,
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
        Ok(ret) => ret,
        Err(_) => -1,
    }
}

pub extern "C" fn dup_handler(
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
    let cage_id = arg1cage;
    let fd = arg1;

    let ret = match make_threei_call(
        SYS_DUP as u32,
        0,
        this_cage,
        cage_id,
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
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, fd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id,
                ret as u64,
                entry.fdkind,
                entry.underfd,
                entry.should_cloexec,
                entry.perfdinfo,
            );
        }
    }

    ret
}

pub extern "C" fn dup2_handler(
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
    let cage_id = arg1cage;
    let oldfd = arg1;
    let newfd = arg2;

    let ret = match make_threei_call(
        SYS_DUP2 as u32,
        0,
        this_cage,
        cage_id,
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
        Ok(ret) => ret,
        Err(_) => -1,
    };

    if ret >= 0 {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, oldfd) {
            let _ = fdtables::get_specific_virtual_fd(
                cage_id,
                newfd,
                entry.fdkind,
                entry.underfd,
                entry.should_cloexec,
                entry.perfdinfo,
            );
        }
    }
    ret
}
