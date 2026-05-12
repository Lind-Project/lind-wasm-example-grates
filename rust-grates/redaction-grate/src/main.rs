//! Redacts configured literal byte strings from write-like syscalls.

use grate_rs::{
    GrateBuilder, GrateError,
    constants::{SYS_PWRITE, SYS_WRITE, SYS_WRITEV},
    copy_data_between_cages, getcageid, make_threei_call,
};
use std::sync::Mutex;

const MAX_REDACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_IOVEC: u64 = 4096;

static REDACTION: Mutex<RedactionConfig> = Mutex::new(RedactionConfig {
    patterns: Vec::new(),
    mask: b'*',
});

#[derive(Clone)]
struct RedactionConfig {
    patterns: Vec<Vec<u8>>,
    mask: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GuestIovec {
    iov_base: u64,
    iov_len: u64,
}

fn config() -> RedactionConfig {
    REDACTION.lock().unwrap().clone()
}

fn redact(buf: &mut [u8], config: &RedactionConfig) {
    for pattern in &config.patterns {
        if pattern.is_empty() || pattern.len() > buf.len() {
            continue;
        }

        let mut i = 0;
        while i + pattern.len() <= buf.len() {
            if &buf[i..i + pattern.len()] == pattern {
                for byte in &mut buf[i..i + pattern.len()] {
                    *byte = config.mask;
                }
                i += pattern.len();
            } else {
                i += 1;
            }
        }
    }
}

fn copy_from_cage(src_ptr: u64, src_cage: u64, len: u64) -> Result<Vec<u8>, i32> {
    let len = usize::try_from(len).map_err(|_| -(libc::EINVAL as i32))?;
    if len > MAX_REDACT_BYTES {
        return Err(-(libc::E2BIG as i32));
    }

    let this_cage = getcageid();
    let mut buf = vec![0u8; len];
    copy_data_between_cages(
        this_cage,
        src_cage,
        src_ptr,
        src_cage,
        buf.as_mut_ptr() as u64,
        this_cage,
        len as u64,
        0,
    )
    .map_err(|_| -(libc::EFAULT as i32))?;

    Ok(buf)
}

fn forward(syscall: u64, target_cage: u64, args: [u64; 6], arg_cages: [u64; 6]) -> i32 {
    let this_cage = getcageid();
    match make_threei_call(
        syscall as u32,
        0,
        this_cage,
        target_cage,
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
        Ok(ret) => ret,
        Err(GrateError::MakeSyscallError(n)) => n,
        Err(_) => -1,
    }
}

fn forward_with_redacted_buffer(
    syscall: u64,
    target_cage: u64,
    mut args: [u64; 6],
    mut arg_cages: [u64; 6],
    buf_idx: usize,
    count_idx: usize,
) -> i32 {
    let redaction = config();
    if redaction.patterns.is_empty() {
        return forward(syscall, target_cage, args, arg_cages);
    }

    let mut data = match copy_from_cage(args[buf_idx], arg_cages[buf_idx], args[count_idx]) {
        Ok(data) => data,
        Err(err) if err == -(libc::E2BIG as i32) => {
            return forward(syscall, target_cage, args, arg_cages);
        }
        Err(err) => return err,
    };

    redact(&mut data, &redaction);

    let this_cage = getcageid();
    args[buf_idx] = data.as_ptr() as u64;
    arg_cages[buf_idx] = this_cage | grate_rs::constants::lind::GRATE_MEMORY_FLAG;
    args[count_idx] = data.len() as u64;

    forward(syscall, target_cage, args, arg_cages)
}

extern "C" fn write_handler(
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
    forward_with_redacted_buffer(
        SYS_WRITE,
        fd_cage,
        [fd, buf, count, arg4, arg5, arg6],
        [fd_cage, buf_cage, count_cage, arg4cage, arg5cage, arg6cage],
        1,
        2,
    )
}

extern "C" fn pwrite_handler(
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
    forward_with_redacted_buffer(
        SYS_PWRITE,
        fd_cage,
        [fd, buf, count, pos, arg5, arg6],
        [fd_cage, buf_cage, count_cage, pos_cage, arg5cage, arg6cage],
        1,
        2,
    )
}

extern "C" fn writev_handler(
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
    let redaction = config();
    if redaction.patterns.is_empty() || vlen > MAX_IOVEC {
        return forward(
            SYS_WRITEV,
            fd_cage,
            [fd, iovec, vlen, arg4, arg5, arg6],
            [fd_cage, iovec_cage, vlen_cage, arg4cage, arg5cage, arg6cage],
        );
    }

    let iovec_bytes = match vlen.checked_mul(std::mem::size_of::<GuestIovec>() as u64) {
        Some(n) => n,
        None => return -(libc::EINVAL as i32),
    };
    let raw_iovecs = match copy_from_cage(iovec, iovec_cage, iovec_bytes) {
        Ok(data) => data,
        Err(_) => return -(libc::EFAULT as i32),
    };

    let mut data = Vec::new();
    for chunk in raw_iovecs.chunks_exact(std::mem::size_of::<GuestIovec>()) {
        let iov = unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const GuestIovec) };
        let next_len = match data.len().checked_add(iov.iov_len as usize) {
            Some(n) => n,
            None => return -(libc::EINVAL as i32),
        };
        if next_len > MAX_REDACT_BYTES {
            return forward(
                SYS_WRITEV,
                fd_cage,
                [fd, iovec, vlen, arg4, arg5, arg6],
                [fd_cage, iovec_cage, vlen_cage, arg4cage, arg5cage, arg6cage],
            );
        }

        let part = match copy_from_cage(iov.iov_base, iovec_cage, iov.iov_len) {
            Ok(part) => part,
            Err(_) => return -(libc::EFAULT as i32),
        };
        data.extend_from_slice(&part);
    }

    redact(&mut data, &redaction);

    let this_cage = getcageid();
    forward(
        SYS_WRITE,
        fd_cage,
        [
            fd,
            data.as_ptr() as u64,
            data.len() as u64,
            arg4,
            arg5,
            arg6,
        ],
        [
            fd_cage,
            this_cage | grate_rs::constants::lind::GRATE_MEMORY_FLAG,
            this_cage,
            arg4cage,
            arg5cage,
            arg6cage,
        ],
    )
}

fn parse_args() -> Result<Vec<String>, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut patterns = Vec::new();
    let mut mask = b'*';
    let mut remaining = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                remaining.extend_from_slice(&args[i + 1..]);
                break;
            }
            "--redact" => {
                i += 1;
                let pattern = args
                    .get(i)
                    .ok_or_else(|| "--redact requires a literal string".to_string())?;
                patterns.push(pattern.as_bytes().to_vec());
            }
            "--mask" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| "--mask requires one byte".to_string())?;
                let bytes = value.as_bytes();
                if bytes.len() != 1 {
                    return Err("--mask requires exactly one byte".to_string());
                }
                mask = bytes[0];
            }
            _ => {
                remaining.extend_from_slice(&args[i..]);
                break;
            }
        }
        i += 1;
    }

    *REDACTION.lock().unwrap() = RedactionConfig { patterns, mask };
    Ok(remaining)
}

fn main() {
    let argv = match parse_args() {
        Ok(argv) => argv,
        Err(err) => {
            eprintln!("redaction-grate: {}", err);
            eprintln!(
                "usage: redaction-grate [--redact TEXT]... [--mask X] -- <program> [args...]"
            );
            std::process::exit(1);
        }
    };

    GrateBuilder::new()
        .register(SYS_WRITE, write_handler)
        .register(SYS_PWRITE, pwrite_handler)
        .register(SYS_WRITEV, writev_handler)
        .teardown(|result: Result<i32, GrateError>| println!("Result: {:#?}", result))
        .run(argv);
}
