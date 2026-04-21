use grate_rs::constants::*;
use grate_rs::constants::error::{EACCES, EAGAIN, EMFILE};
use grate_rs::constants::fs::*;
use grate_rs::constants::net::AF_INET;
use grate_rs::constants::process::CLONE_VM;
use grate_rs::{copy_data_between_cages, getcageid, make_threei_call, GrateError};

use crate::NANNY;

// =====================================================================
//  fdtables fdkind constants
// =====================================================================

/// FD opened via open/openat — charges fileread/filewrite.
pub const FD_FILE: u32 = 1;
/// FD opened via socket/accept/connect — charges netsend/netrecv.
pub const FD_SOCKET: u32 = 2;

// perfdinfo bit flags for sockets
const SOCK_LOOPBACK: u64 = 1 << 0;
const SOCK_LISTENING: u64 = 1 << 1;

// =====================================================================
//  Helpers
// =====================================================================


/// Forward a syscall to the cage via make_threei_call.
fn forward(
    syscall_nr: u64,
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    match make_threei_call(
        syscall_nr as u32,
        0,
        grate_cageid,
        arg1cage, // target = the calling cage
        arg1, arg1cage,
        arg2, arg2cage,
        arg3, arg3cage,
        arg4, arg4cage,
        arg5, arg5cage,
        arg6, arg6cage,
        0,
    ) {
        Ok(ret) => ret,
        Err(GrateError::MakeSyscallError(e)) => e,
        Err(_) => -1,
    }
}

/// Round bytes up to 4096-byte disk blocks (repy convention).
fn block_charge(bytes: i32) -> f64 {
    ((bytes as f64) / 4096.0).ceil() * 4096.0
}

/// Copy a sockaddr_in (16 bytes) from cage memory and extract the port.
/// No lock needed: operates entirely on a stack-local buffer.
fn extract_port(addr_ptr: u64, addr_cage: u64) -> Option<u16> {
    let mut buf = [0u8; 16];
    let gid = getcageid();
    if copy_data_between_cages(
        gid, gid,
        addr_ptr, addr_cage,
        buf.as_mut_ptr() as u64, gid,
        16, 0,
    ).is_err() {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    if family == AF_INET {
        Some(u16::from_be_bytes([buf[2], buf[3]]))
    } else {
        None
    }
}

/// Check whether a sockaddr_in points to 127.x.x.x.
/// No lock needed: operates entirely on a stack-local buffer.
fn is_loopback_addr(addr_ptr: u64, addr_cage: u64) -> bool {
    let mut buf = [0u8; 16];
    let gid = getcageid();
    if copy_data_between_cages(
        gid, gid,
        addr_ptr, addr_cage,
        buf.as_mut_ptr() as u64, gid,
        16, 0,
    ).is_err() {
        return false;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    // sin_addr starts at offset 4; first byte is 127 for loopback.
    family == AF_INET && buf[4] == 127
}

/// Look up the fdkind for an fd.  Returns 0 if unknown.
fn fd_kind(cage_id: u64, fd: u64) -> u32 {
    match fdtables::translate_virtual_fd(cage_id, fd) {
        Ok(entry) => entry.fdkind,
        Err(_) => 0,
    }
}

/// Look up the perfdinfo for a socket fd.
fn socket_flags(cage_id: u64, fd: u64) -> u64 {
    match fdtables::translate_virtual_fd(cage_id, fd) {
        Ok(entry) if entry.fdkind == FD_SOCKET => entry.perfdinfo,
        _ => 0,
    }
}

// =====================================================================
//  Charge helpers
// =====================================================================

/// Pre-check + post-charge for a read-like operation.
fn charge_read_pre(cage_id: u64, fd: u64) {
    let nanny = NANNY.get().unwrap();
    if fd_kind(cage_id, fd) == FD_SOCKET {
        let flags = socket_flags(cage_id, fd);
        if flags & SOCK_LOOPBACK != 0 {
            nanny.tattle_quantity("looprecv", 0.0);
        } else {
            nanny.tattle_quantity("netrecv", 0.0);
        }
    } else {
        nanny.tattle_quantity("fileread", 0.0);
    }
}

fn charge_read_post(cage_id: u64, fd: u64, bytes: i32) {
    if bytes <= 0 { return; }
    let nanny = NANNY.get().unwrap();
    if fd_kind(cage_id, fd) == FD_SOCKET {
        let flags = socket_flags(cage_id, fd);
        if flags & SOCK_LOOPBACK != 0 {
            nanny.tattle_quantity("looprecv", bytes as f64 + 64.0);
        } else {
            nanny.tattle_quantity("netrecv", bytes as f64 + 64.0);
        }
    } else {
        nanny.tattle_quantity("fileread", block_charge(bytes));
    }
}

/// Pre-check + post-charge for a write-like operation.
fn charge_write_pre(cage_id: u64, fd: u64) {
    let nanny = NANNY.get().unwrap();
    let fd_i32 = fd as i32;

    if fd_i32 == 1 || fd_i32 == 2 {
        nanny.tattle_quantity("lograte", 0.0);
    } else if fd_kind(cage_id, fd) == FD_SOCKET {
        let flags = socket_flags(cage_id, fd);
        if flags & SOCK_LOOPBACK != 0 {
            nanny.tattle_quantity("loopsend", 0.0);
        } else {
            nanny.tattle_quantity("netsend", 0.0);
        }
    } else {
        nanny.tattle_quantity("filewrite", 0.0);
    }
}

fn charge_write_post(cage_id: u64, fd: u64, bytes: i32) {
    if bytes <= 0 { return; }
    let nanny = NANNY.get().unwrap();
    let fd_i32 = fd as i32;

    if fd_i32 == 1 || fd_i32 == 2 {
        nanny.tattle_quantity("lograte", bytes as f64);
    } else if fd_kind(cage_id, fd) == FD_SOCKET {
        let flags = socket_flags(cage_id, fd);
        if flags & SOCK_LOOPBACK != 0 {
            nanny.tattle_quantity("loopsend", bytes as f64 + 64.0);
        } else {
            nanny.tattle_quantity("netsend", bytes as f64 + 64.0);
        }
    } else {
        nanny.tattle_quantity("filewrite", block_charge(bytes));
    }
}

// =====================================================================
//  File I/O handlers
// =====================================================================

/// open(pathname, flags, mode)
pub extern "C" fn handle_open(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let flags = arg2 as u32;
    let nanny = NANNY.get().unwrap();

    eprintln!("[resource] open: cage={} exists={}", cage_id, fdtables::check_cage_exists(cage_id));

    // Check filesopened cap before the syscall.
    if nanny.tattle_add_item("filesopened").is_err() {
        return -EMFILE;
    }

    // Pre-check fileread capacity.
    nanny.tattle_quantity("fileread", 0.0);

    let ret = forward(
        SYS_OPEN, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        // Track the fd in fdtables as a file.
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, ret as u64, FD_FILE, 0, false, flags as u64,
        );

        // Charge metadata read (4096 bytes per repy convention).
        nanny.tattle_quantity("fileread", 4096.0);

        // If opened for writing, also charge a filewrite block.
        let acc = flags & O_ACCMODE as u32;
        if acc == O_WRONLY as u32 || acc == O_RDWR as u32 {
            nanny.tattle_quantity("filewrite", 4096.0);
        }
    } else {
        // Open failed — roll back the filesopened slot.
        nanny.tattle_remove_item("filesopened");
    }

    ret
}

/// close(fd)
pub extern "C" fn handle_close(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let fd = arg1;
    let nanny = NANNY.get().unwrap();

    // Look up fd type before forwarding (close destroys the fd).
    let kind = fd_kind(cage_id, fd);
    let sflags = if kind == FD_SOCKET { socket_flags(cage_id, fd) } else { 0 };

    let ret = forward(
        SYS_CLOSE, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        // Decrement the appropriate fungible counter.
        match kind {
            FD_FILE => nanny.tattle_remove_item("filesopened"),
            FD_SOCKET => {
                if sflags & SOCK_LISTENING != 0 {
                    nanny.tattle_remove_item("insockets");
                } else {
                    nanny.tattle_remove_item("outsockets");
                }
            }
            _ => {}
        }
        let _ = fdtables::close_virtualfd(cage_id, fd);
    }

    ret
}

/// read(fd, buf, count)
pub extern "C" fn handle_read(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_read_pre(cage_id, arg1);

    let ret = forward(
        SYS_READ, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_read_post(cage_id, arg1, ret);
    ret
}

/// write(fd, buf, count)
pub extern "C" fn handle_write(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_write_pre(cage_id, arg1);

    let ret = forward(
        SYS_WRITE, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_write_post(cage_id, arg1, ret);
    ret
}

/// pread64(fd, buf, count, offset)
pub extern "C" fn handle_pread64(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_read_pre(cage_id, arg1);

    let ret = forward(
        SYS_PREAD, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_read_post(cage_id, arg1, ret);
    ret
}

/// pwrite64(fd, buf, count, offset)
pub extern "C" fn handle_pwrite64(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_write_pre(cage_id, arg1);

    let ret = forward(
        SYS_PWRITE, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_write_post(cage_id, arg1, ret);
    ret
}

/// readv(fd, iov, iovcnt)
pub extern "C" fn handle_readv(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_read_pre(cage_id, arg1);

    let ret = forward(
        SYS_READV, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_read_post(cage_id, arg1, ret);
    ret
}

/// writev(fd, iov, iovcnt)
pub extern "C" fn handle_writev(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_write_pre(cage_id, arg1);

    let ret = forward(
        SYS_WRITEV, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_write_post(cage_id, arg1, ret);
    ret
}

// =====================================================================
//  Network handlers
// =====================================================================

/// socket(domain, type, protocol) — track fd as socket, no resource charge.
pub extern "C" fn handle_socket(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;


    let ret = forward(
        SYS_SOCKET, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, ret as u64, FD_SOCKET, 0, false, 0,
        );
    }

    ret
}

/// bind(sockfd, addr, addrlen) — check messport/connport allowlist.
pub extern "C" fn handle_bind(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let nanny = NANNY.get().unwrap();

    // Check port against both allowlists.
    if let Some(port) = extract_port(arg2, arg2cage) {
        if !nanny.is_item_allowed("messport", port) && !nanny.is_item_allowed("connport", port) {
            return -EACCES;
        }
    }

    // Detect loopback and update socket metadata.
    let cage_id = arg1cage;
    let loopback = is_loopback_addr(arg2, arg2cage);
    if loopback {
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, arg1) {
            let _ = fdtables::close_virtualfd(cage_id, arg1);
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, arg1, FD_SOCKET, entry.underfd,
                entry.should_cloexec, entry.perfdinfo | SOCK_LOOPBACK,
            );
        }
    }

    forward(
        SYS_BIND, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    )
}

/// listen(sockfd, backlog) — insockets += 1.
pub extern "C" fn handle_listen(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nanny = NANNY.get().unwrap();

    if nanny.tattle_add_item("insockets").is_err() {
        return -EMFILE;
    }

    let ret = forward(
        SYS_LISTEN, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        // Mark socket as listening in fdtables.
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, arg1) {
            let _ = fdtables::close_virtualfd(cage_id, arg1);
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, arg1, FD_SOCKET, entry.underfd,
                entry.should_cloexec, entry.perfdinfo | SOCK_LISTENING,
            );
        }
    } else {
        nanny.tattle_remove_item("insockets");
    }

    ret
}

/// accept(sockfd, addr, addrlen) — outsockets += 1, charge overhead.
pub extern "C" fn handle_accept(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nanny = NANNY.get().unwrap();

    if nanny.tattle_add_item("outsockets").is_err() {
        return -EMFILE;
    }

    let ret = forward(
        SYS_ACCEPT, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        // Inherit loopback flag from the listening socket.
        let parent_flags = socket_flags(cage_id, arg1);
        let loopback = parent_flags & SOCK_LOOPBACK != 0;

    
        let _ = fdtables::get_specific_virtual_fd(
            cage_id, ret as u64, FD_SOCKET, 0, false,
            if loopback { SOCK_LOOPBACK } else { 0 },
        );

        // Connection overhead charges (repy: 128 recv + 64 send).
        if loopback {
            nanny.tattle_quantity("looprecv", 128.0);
            nanny.tattle_quantity("loopsend", 64.0);
        } else {
            nanny.tattle_quantity("netrecv", 128.0);
            nanny.tattle_quantity("netsend", 64.0);
        }
    } else {
        nanny.tattle_remove_item("outsockets");
    }

    ret
}

/// connect(sockfd, addr, addrlen) — outsockets += 1, charge overhead.
pub extern "C" fn handle_connect(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    let nanny = NANNY.get().unwrap();

    if nanny.tattle_add_item("outsockets").is_err() {
        return -EMFILE;
    }

    // Pre-check network capacity.
    nanny.tattle_quantity("netsend", 0.0);
    nanny.tattle_quantity("netrecv", 0.0);

    let ret = forward(
        SYS_CONNECT, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret >= 0 {
        let loopback = is_loopback_addr(arg2, arg2cage);

        // Update socket's loopback flag.
        if let Ok(entry) = fdtables::translate_virtual_fd(cage_id, arg1) {
            let _ = fdtables::close_virtualfd(cage_id, arg1);
            let flags = if loopback {
                entry.perfdinfo | SOCK_LOOPBACK
            } else {
                entry.perfdinfo & !SOCK_LOOPBACK
            };
            let _ = fdtables::get_specific_virtual_fd(
                cage_id, arg1, FD_SOCKET, entry.underfd,
                entry.should_cloexec, flags,
            );
        }

        // Connection overhead (repy: 128 send + 64 recv).
        if loopback {
            nanny.tattle_quantity("loopsend", 128.0);
            nanny.tattle_quantity("looprecv", 64.0);
        } else {
            nanny.tattle_quantity("netsend", 128.0);
            nanny.tattle_quantity("netrecv", 64.0);
        }
    } else {
        nanny.tattle_remove_item("outsockets");
    }

    ret
}

/// sendto(sockfd, buf, len, flags, dest_addr, addrlen)
pub extern "C" fn handle_sendto(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_write_pre(cage_id, arg1);

    let ret = forward(
        SYS_SENDTO, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_write_post(cage_id, arg1, ret);
    ret
}

/// recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
pub extern "C" fn handle_recvfrom(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_read_pre(cage_id, arg1);

    let ret = forward(
        SYS_RECVFROM, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_read_post(cage_id, arg1, ret);
    ret
}

/// sendmsg(sockfd, msg, flags)
pub extern "C" fn handle_sendmsg(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_write_pre(cage_id, arg1);

    let ret = forward(
        SYS_SENDMSG, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_write_post(cage_id, arg1, ret);
    ret
}

/// recvmsg(sockfd, msg, flags)
pub extern "C" fn handle_recvmsg(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let cage_id = arg1cage;
    charge_read_pre(cage_id, arg1);

    let ret = forward(
        SYS_RECVMSG, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    charge_read_post(cage_id, arg1, ret);
    ret
}

// =====================================================================
//  Threading handlers
// =====================================================================

/// clone(flags, stack, parent_tid, child_tid, tls)
/// Only counts as a new event/thread if CLONE_VM is set.
pub extern "C" fn handle_clone(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let nanny = NANNY.get().unwrap();
    let is_thread = (arg1 & CLONE_VM) != 0;

    if is_thread {
        if nanny.tattle_add_item("events").is_err() {
            return -EAGAIN;
        }
    }

    let ret = forward(
        SYS_CLONE, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret < 0 && is_thread {
        nanny.tattle_remove_item("events");
    }

    if ret > 0 && !is_thread {
        eprintln!("[resource] clone: parent={} child={} parent_exists={}", arg1cage, ret, fdtables::check_cage_exists(arg1cage));
        let _ = fdtables::copy_fdtable_for_cage(arg1cage, ret as u64);
        eprintln!("[resource] clone: child_exists={}", fdtables::check_cage_exists(ret as u64));
    }

    ret
}

/// exit(status) — decrement events counter for thread exit.
pub extern "C" fn handle_exit(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let nanny = NANNY.get().unwrap();
    nanny.tattle_remove_item("events");

    forward(
        SYS_EXIT, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    )
}

// =====================================================================
//  Random handler
// =====================================================================

/// getrandom(buf, count, flags) — charge 1024 bytes per call (repy convention).
pub extern "C" fn handle_getrandom(
    grate_cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let nanny = NANNY.get().unwrap();

    nanny.tattle_quantity("random", 0.0);

    let ret = forward(
        SYS_GETRANDOM, grate_cageid,
        arg1, arg1cage, arg2, arg2cage, arg3, arg3cage,
        arg4, arg4cage, arg5, arg5cage, arg6, arg6cage,
    );

    if ret > 0 {
        nanny.tattle_quantity("random", 1024.0);
    }

    ret
}
