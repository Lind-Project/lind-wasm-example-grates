//! AF_UNIX sockaddr translation helpers and socket syscall handler macros.
//!
//! Linux AF_UNIX (aka Unix domain) sockets embed filesystem paths inside
//! `sockaddr_un.sun_path`. When a cage is chrooted, those paths need to be
//! translated similarly to regular filesystem syscalls:
//! - **Input** (e.g. `bind`, `connect`, `sendto`): chroot the `sun_path`.
//! - **Output** (e.g. `accept`, `getsockname`, `getpeername`, `recvfrom`): strip
//!   the chroot prefix from returned `sun_path` so the cage sees a virtual path.
//!
//! This module intentionally focuses on pathname sockets. Abstract-namespace
//! AF_UNIX addresses (leading `\\0`) are treated as opaque bytes and are passed
//! through unchanged.

use crate::paths::*;
use grate_rs::{copy_data_between_cages, getcageid};

/// Generate a syscall handler that rewrites a `sockaddr` argument before calling
/// the real syscall.
///
/// Used for syscalls that **take** a sockaddr containing a path (AF_UNIX):
/// `bind`, `connect`, and the destination address in `sendto`.
///
/// # Parameters
/// - `$idx`: index of the `sockaddr*` argument in the 6-arg syscall ABI.
/// - `$idx_len`: index of the corresponding `socklen_t` argument.
#[macro_export]
macro_rules! socket_translate_handler {
    ($name: ident, $syscall_const:expr, $idx:expr, $idx_len:expr) => {
        extern "C" fn $name(
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
            let thiscage = getcageid();

            let mut args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            if args[$idx] != 0 {
                // Translate the sockaddr (chroot AF_UNIX paths).
                // Use `arg1cage` as the cage identity for path resolution; in
                // practice this is the cage associated with the syscall's
                // memory arguments (and therefore the cwd tracking entry).
                let (sockaddr_buf, new_len) =
                    match translate_sockaddr(arg1cage, args[$idx], cages[$idx], args[$idx_len]) {
                        Some(v) => v,
                        None => return -14, // EFAULT
                    };

                let rewrites = &[($idx as usize, sockaddr_buf.as_ptr() as u64)];
                args[$idx_len] = new_len;

                call_with_rewrites(
                    $syscall_const as u32,
                    thiscage,
                    arg1cage,
                    args,
                    cages,
                    rewrites,
                )
            } else {
                match make_threei_call(
                    $syscall_const as u32,
                    0,
                    thiscage, // self cage (grate)
                    arg1cage, // execute as-if from cageid
                    args[0],
                    cages[0],
                    args[1],
                    cages[1],
                    args[2],
                    cages[2],
                    args[3],
                    cages[3],
                    args[4],
                    cages[4],
                    args[5],
                    cages[5],
                    0,
                ) {
                    Ok(ret) => ret,
                    Err(_) => -1,
                }
            }
        }
    };
}

/// Generate a syscall handler that post-processes a returned `sockaddr` buffer.
///
/// Used for syscalls that **return** a peer/local address (AF_UNIX):
/// `accept`, `getsockname`, `getpeername`, and `recvfrom`.
///
/// On success, the generated handler reads the returned sockaddr from the cage's
/// memory, strips the chroot prefix from `sun_path`, and writes it back.
#[macro_export]
macro_rules! socket_untranslate_handler {
    ($name:ident, $syscall_const:expr, $idx:expr, $idx_len:expr) => {
        extern "C" fn $name(
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
            let args = [arg1, arg2, arg3, arg4, arg5, arg6];
            let cages = [arg1cage, arg2cage, arg3cage, arg4cage, arg5cage, arg6cage];

            // Call the real syscall.
            let ret = match make_threei_call(
                $syscall_const as u32,
                0,
                cageid,
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

            // On success, untranslate the returned peer sockaddr (strip chroot from AF_UNIX).
            if ret >= 0 {
                untranslate_sockaddr_in_cage(
                    args[$idx],
                    cages[$idx],
                    args[$idx_len],
                    cages[$idx_len],
                );
            }

            ret
        }
    };
}

/// Address family for Unix domain sockets (`sockaddr_un`).
const AF_UNIX: u16 = 1;

/// Translate a `sockaddr` buffer if it is AF_UNIX.
///
/// Returns a freshly-allocated buffer containing the rewritten sockaddr bytes
/// and the new length.
pub fn translate_sockaddr(
    cageid: u64,
    addr: u64,
    addr_cage: u64,
    addrlen: u64,
) -> Option<(Vec<u8>, u64)> {
    let thiscage = getcageid();

    if addrlen < 2 {
        return None;
    }

    let mut sockaddr_buf = vec![0u8; addrlen as usize];
    if copy_data_between_cages(
        thiscage,
        addr_cage,
        addr,
        addr_cage,
        sockaddr_buf.as_mut_ptr() as u64,
        thiscage,
        addrlen,
        0,
    )
    .is_err()
    {
        return None;
    }

    // Check `sa_family` (first 2 bytes).
    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);

    if sa_family == AF_UNIX && addrlen > 2 {
        // Extract and chroot the path (starts at offset 2).
        let path_bytes = &sockaddr_buf[2..];
        let path_len = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        let path = String::from_utf8_lossy(&path_bytes[..path_len]).to_string();

        let chrooted = chroot_path(&path, cageid);

        // Build a new sockaddr payload (sa_family + sun_path + trailing NUL).
        let mut new_sockaddr = vec![0u8; 2 + chrooted.len() + 1];
        new_sockaddr[0] = sockaddr_buf[0];
        new_sockaddr[1] = sockaddr_buf[1];
        new_sockaddr[2..2 + chrooted.len()].copy_from_slice(chrooted.as_bytes());

        Some((new_sockaddr.clone(), new_sockaddr.len() as u64))
    } else {
        // Not AF_UNIX, return original
        Some((sockaddr_buf, addrlen))
    }
}

/// Untranslate a sockaddr buffer in place (strip chroot prefix from AF_UNIX path)
pub fn untranslate_sockaddr(sockaddr_buf: &mut [u8]) {
    let chroot_dir = crate::CHROOT_DIR.lock().unwrap().clone();

    // Need at least 2 bytes for sa_family
    if sockaddr_buf.len() < 2 {
        return;
    }

    // Check if this is an AF_UNIX socket.
    let sa_family = u16::from_ne_bytes([sockaddr_buf[0], sockaddr_buf[1]]);
    if sa_family != AF_UNIX || sockaddr_buf.len() <= 2 {
        return;
    }

    // Extract the path (starts at offset 2, NUL-terminated).
    let path_bytes = &sockaddr_buf[2..];
    let path_len = path_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_bytes.len());
    let path = String::from_utf8_lossy(&path_bytes[..path_len]).to_string();

    // Strip chroot prefix if present to get the virtual path.
    let virtual_path = if path.starts_with(&chroot_dir) {
        let stripped = &path[chroot_dir.len()..];
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    } else {
        path
    };

    // Write the virtual path back to the buffer.
    let dest = &mut sockaddr_buf[2..];
    let copy_len = std::cmp::min(virtual_path.len(), dest.len() - 1);
    dest[..copy_len].copy_from_slice(&virtual_path.as_bytes()[..copy_len]);
    if copy_len < dest.len() {
        dest[copy_len] = 0; // null-terminate
    }
}

/// Read a returned sockaddr from cage memory, untranslate it, and write it back.
/// Used after syscalls that return a sockaddr (accept, getsockname, getpeername, recvfrom).
pub fn untranslate_sockaddr_in_cage(
    addr: u64,
    addr_cage: u64,
    addrlen_ptr: u64,
    addrlen_cage: u64,
) {
    // Skip if no address buffer provided
    if addr == 0 || addrlen_ptr == 0 {
        return;
    }

    let thiscage = getcageid();

    // Step 1: Read the addrlen value from cage memory to know buffer size
    let mut addrlen_buf = [0u8; 4];
    if copy_data_between_cages(
        thiscage,
        addrlen_cage,
        addrlen_ptr,
        addrlen_cage,
        addrlen_buf.as_mut_ptr() as u64,
        thiscage,
        4,
        0,
    )
    .is_err()
    {
        return;
    }
    let addrlen = u32::from_ne_bytes(addrlen_buf) as usize;
    if addrlen == 0 {
        return;
    }

    // Step 2: Read the sockaddr from cage memory
    let mut sockaddr_buf = vec![0u8; addrlen];
    if copy_data_between_cages(
        thiscage,
        addr_cage,
        addr,
        addr_cage,
        sockaddr_buf.as_mut_ptr() as u64,
        thiscage,
        addrlen as u64,
        0,
    )
    .is_err()
    {
        return;
    }

    // Step 3: Untranslate the sockaddr (strip chroot prefix if AF_UNIX)
    untranslate_sockaddr(&mut sockaddr_buf);

    // Step 4: Write the untranslated sockaddr back to cage memory
    let _ = copy_data_between_cages(
        thiscage,
        addr_cage,
        sockaddr_buf.as_ptr() as u64,
        thiscage,
        addr,
        addr_cage,
        addrlen as u64,
        0,
    );
}
