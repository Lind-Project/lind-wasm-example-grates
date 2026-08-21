use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::{
    constants::{SYS_OPEN, SYS_UMASK},
    make_threei_call, GrateBuilder, GrateError,
};

/// Bits forced into every umask the cage sets.
/// Default 0o000 adds no restriction to the requested mask.
static FORCE_BITS: AtomicU64 = AtomicU64::new(0o000);
static CURRENT_MASK: AtomicU64 = AtomicU64::new(0o022);

fn masked_mode(mode: u64) -> u64 {
    mode & !CURRENT_MASK.load(Ordering::Relaxed)
}

fn syscall_result(result: Result<i32, GrateError>) -> i32 {
    match result {
        Ok(value) => value,
        Err(GrateError::MakeSyscallError(errno)) => errno,
        Err(_) => -1,
    }
}

extern "C" fn umask_handler(
    _cageid: u64,
    mask: u64,
    _mask_cage: u64,
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
    // Force any required bits into the cage's requested umask.
    // With --force-bits 022, the cage can never set a umask that
    // would allow group-write or other-write.
    let next_mask = ((mask & 0o777) | FORCE_BITS.load(Ordering::Relaxed)) & 0o777;
    CURRENT_MASK.swap(next_mask, Ordering::Relaxed) as i32
}

extern "C" fn open_handler(
    cageid: u64,
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
    syscall_result(make_threei_call(
        SYS_OPEN as u32,
        0,
        cageid,
        filename_cage,
        filename,
        filename_cage,
        flags,
        flags_cage,
        masked_mode(mode),
        mode_cage,
        arg4,
        arg4cage,
        arg5,
        arg5cage,
        arg6,
        arg6cage,
        0,
    ))
}

struct Config {
    force_bits: u64,
    remaining_args: Vec<String>,
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut force_bits = 0o000u64;
    let mut remaining_args = Vec::new();
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--force-bits" {
            if i + 1 >= args.len() {
                return Err("--force-bits requires an argument".to_string());
            }
            force_bits = u64::from_str_radix(&args[i + 1], 8).map_err(|_| {
                format!("--force-bits: '{}' is not a valid octal value", args[i + 1])
            })?;
            i += 2;
        } else {
            remaining_args.push(args[i].clone());
            i += 1;
        }
    }

    Ok(Config {
        force_bits,
        remaining_args,
    })
}

fn main() {
    let config = match parse_args() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("argument error: {}", err);
            eprintln!("Usage: umask-grate [--force-bits <octal>] <program> [args...]");
            std::process::exit(1);
        }
    };

    let force_bits = config.force_bits & 0o777;
    FORCE_BITS.store(force_bits, Ordering::Relaxed);
    CURRENT_MASK.store(0o022 | force_bits, Ordering::Relaxed);

    GrateBuilder::new()
        .register(SYS_UMASK, umask_handler)
        .register(SYS_OPEN, open_handler)
        .teardown(|result| match result {
            Ok(status) => println!("[umask-grate] child exited with status: {status}"),
            Err(e) => {
                eprintln!("[umask-grate] error: {:#?}", e);
                std::process::exit(-1);
            }
        })
        .run(config.remaining_args);
}
