//! Network namespace syscall handlers.
//!
//! Routes network syscalls based on port number. Sockets that bind or connect
//! to a port in the clamped range get marked in fdtables (perfdinfo=1).
//! Subsequent I/O on those fds is routed to the clamped child grate.

use crate::helpers;
use grate_rs::{SyscallHandler, constants::*};

// =====================================================================
//  FD-BASED ROUTING (generic)
//
//  For syscalls where arg1 is an fd. Routes to alt if fd is clamped.
// =====================================================================

macro_rules! fd_route_handler {
    ($name:ident, $sysno:expr) => {
        pub extern "C" fn $name(
            _cageid: u64,
            arg1: u64, arg1cage: u64,
            arg2: u64, arg2cage: u64,
            arg3: u64, arg3cage: u64,
            arg4: u64, arg4cage: u64,
            arg5: u64, arg5cage: u64,
            arg6: u64, arg6cage: u64,
        ) -> i32 {
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            let nr = match helpers::get_route(arg1cage, $sysno) {
                Some(alt)
                    if fdtables::check_cage_exists(arg1cage)
                        && fdtables::translate_virtual_fd(arg1cage, arg1)
                            .map(|e| e.perfdinfo != 0)
                            .unwrap_or(false) =>
                {
                    alt
                }
                _ => $sysno,
            };

            helpers::do_syscall(arg1cage, nr, &args, &arg_cages)
        }
    };
}

// I/O on clamped sockets
fd_route_handler!(ns_read_handler, SYS_READ);
fd_route_handler!(ns_write_handler, SYS_WRITE);
fd_route_handler!(ns_readv_handler, SYS_READV);
fd_route_handler!(ns_writev_handler, SYS_WRITEV);
fd_route_handler!(ns_sendmsg_handler, SYS_SENDMSG);
fd_route_handler!(ns_recvmsg_handler, SYS_RECVMSG);
fd_route_handler!(ns_listen_handler, SYS_LISTEN);
fd_route_handler!(ns_shutdown_handler, SYS_SHUTDOWN);

// =====================================================================
//  SOCKET — passthrough, just track the fd
// =====================================================================

/// socket(): always forward, register fd in fdtables as unclamped (perfdinfo=0).
/// We can't know the port yet — clamping happens at bind/connect.
pub extern "C" fn ns_socket_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Route through alt if child grate registered for SYS_SOCKET.
    let nr = helpers::get_route(arg1cage, SYS_SOCKET).unwrap_or(SYS_SOCKET);
    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret >= 0 && fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, 0,
        );
    }
    ret
}

// =====================================================================
//  BIND — addr-based routing + fd clamping
// =====================================================================

/// bind(fd, addr, addrlen): read sockaddr, extract port.
/// If port is in clamped range, mark fd as clamped and route to alt.
pub extern "C" fn ns_bind_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // addr
    arg3: u64, arg3cage: u64,    // addrlen
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let in_range = helpers::read_port_from_cage(arg2, arg2cage, arg3)
        .map(|port| helpers::port_in_range(port))
        .unwrap_or(false);

    let nr = match helpers::get_route(arg1cage, SYS_BIND) {
        Some(alt) if in_range => alt,
        _ => SYS_BIND,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    // On successful bind to a clamped port, mark the fd.
    if ret >= 0 && in_range && fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::set_perfdinfo(arg1cage, arg1, 1);
    }
    ret
}

// =====================================================================
//  CONNECT — addr-based routing + fd clamping
// =====================================================================

/// connect(fd, addr, addrlen): same pattern as bind.
pub extern "C" fn ns_connect_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let in_range = helpers::read_port_from_cage(arg2, arg2cage, arg3)
        .map(|port| helpers::port_in_range(port))
        .unwrap_or(false);

    let nr = match helpers::get_route(arg1cage, SYS_CONNECT) {
        Some(alt) if in_range => alt,
        _ => SYS_CONNECT,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret >= 0 && in_range && fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::set_perfdinfo(arg1cage, arg1, 1);
    }
    ret
}

// =====================================================================
//  ACCEPT — fd-based routing + new fd inherits clamped status
// =====================================================================

/// accept(fd, addr, addrlen): if the listening socket is clamped,
/// the accepted connection fd inherits that status.
pub extern "C" fn ns_accept_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let is_clamped = if fdtables::check_cage_exists(arg1cage) {
        fdtables::translate_virtual_fd(arg1cage, arg1)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false)
    } else {
        false
    };

    let nr = match helpers::get_route(arg1cage, SYS_ACCEPT) {
        Some(alt) if is_clamped => alt,
        _ => SYS_ACCEPT,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);

    if ret >= 0 && fdtables::check_cage_exists(arg1cage) {
        let clamped = if is_clamped { 1u64 } else { 0 };
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, clamped,
        );
    }
    ret
}

// =====================================================================
//  SENDTO — addr-based routing (for UDP)
// =====================================================================

/// sendto(fd, buf, len, flags, addr, addrlen): if addr is provided
/// and port is in range, route to alt. Also check if fd is already clamped.
pub extern "C" fn ns_sendto_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,    // fd
    arg2: u64, arg2cage: u64,    // buf
    arg3: u64, arg3cage: u64,    // len
    arg4: u64, arg4cage: u64,    // flags
    arg5: u64, arg5cage: u64,    // addr
    arg6: u64, arg6cage: u64,    // addrlen
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    // Check fd first.
    let fd_clamped = if fdtables::check_cage_exists(arg1cage) {
        fdtables::translate_virtual_fd(arg1cage, arg1)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false)
    } else {
        false
    };

    // If addr is provided, also check the port.
    let addr_clamped = if arg5 != 0 {
        helpers::read_port_from_cage(arg5, arg5cage, arg6)
            .map(|port| helpers::port_in_range(port))
            .unwrap_or(false)
    } else {
        false
    };

    let clamped = fd_clamped || addr_clamped;

    let nr = match helpers::get_route(arg1cage, SYS_SENDTO) {
        Some(alt) if clamped => alt,
        _ => SYS_SENDTO,
    };

    helpers::do_syscall(arg1cage, nr, &args, &arg_cages)
}

// =====================================================================
//  RECVFROM — fd-based routing
// =====================================================================

// recvfrom: route based on fd.
fd_route_handler!(ns_recvfrom_handler, SYS_RECVFROM);

// =====================================================================
//  CLOSE — fd-based routing + cleanup
// =====================================================================

pub extern "C" fn ns_close_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let is_clamped = if fdtables::check_cage_exists(arg1cage) {
        fdtables::translate_virtual_fd(arg1cage, arg1)
            .map(|e| e.perfdinfo != 0)
            .unwrap_or(false)
    } else {
        false
    };

    let nr = match helpers::get_route(arg1cage, SYS_CLOSE) {
        Some(alt) if is_clamped => alt,
        _ => SYS_CLOSE,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);
    if fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::close_virtualfd(arg1cage, arg1);
    }
    ret
}

// =====================================================================
//  DUP / DUP2 / DUP3 — inherit clamped status
// =====================================================================

pub extern "C" fn ns_dup_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let perfdinfo = if fdtables::check_cage_exists(arg1cage) {
        fdtables::translate_virtual_fd(arg1cage, arg1)
            .map(|e| e.perfdinfo)
            .unwrap_or(0)
    } else {
        0
    };

    let nr = match helpers::get_route(arg1cage, SYS_DUP) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);
    if ret >= 0 && fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, ret as u64, 0, ret as u64, false, perfdinfo,
        );
    }
    ret
}

pub extern "C" fn ns_dup2_handler(
    _cageid: u64,
    arg1: u64, arg1cage: u64,
    arg2: u64, arg2cage: u64,
    arg3: u64, arg3cage: u64,
    arg4: u64, arg4cage: u64,
    arg5: u64, arg5cage: u64,
    arg6: u64, arg6cage: u64,
) -> i32 {
    let args = [arg1, arg2, arg3, arg4, arg5, arg6];
    let arg_cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

    let perfdinfo = if fdtables::check_cage_exists(arg1cage) {
        fdtables::translate_virtual_fd(arg1cage, arg1)
            .map(|e| e.perfdinfo)
            .unwrap_or(0)
    } else {
        0
    };

    let nr = match helpers::get_route(arg1cage, SYS_DUP2) {
        Some(alt) if perfdinfo != 0 => alt,
        _ => SYS_DUP2,
    };

    let ret = helpers::do_syscall(arg1cage, nr, &args, &arg_cages);
    if ret >= 0 && fdtables::check_cage_exists(arg1cage) {
        let _ = fdtables::get_specific_virtual_fd(
            arg1cage, arg2, 0, arg2, false, perfdinfo,
        );
    }
    ret
}

// =====================================================================
//  HANDLER LOOKUP
// =====================================================================

pub fn get_ns_handler(syscall_nr: u64) -> Option<SyscallHandler> {
    match syscall_nr {
        // Socket lifecycle
        SYS_SOCKET => Some(ns_socket_handler),
        SYS_BIND => Some(ns_bind_handler),
        SYS_CONNECT => Some(ns_connect_handler),
        SYS_LISTEN => Some(ns_listen_handler),
        SYS_ACCEPT => Some(ns_accept_handler),
        SYS_SHUTDOWN => Some(ns_shutdown_handler),

        // I/O
        SYS_READ => Some(ns_read_handler),
        SYS_WRITE => Some(ns_write_handler),
        SYS_READV => Some(ns_readv_handler),
        SYS_WRITEV => Some(ns_writev_handler),
        SYS_SENDTO => Some(ns_sendto_handler),
        SYS_RECVFROM => Some(ns_recvfrom_handler),
        SYS_SENDMSG => Some(ns_sendmsg_handler),
        SYS_RECVMSG => Some(ns_recvmsg_handler),

        // FD management
        SYS_CLOSE => Some(ns_close_handler),
        SYS_DUP => Some(ns_dup_handler),
        SYS_DUP2 => Some(ns_dup2_handler),

        _ => None,
    }
}
