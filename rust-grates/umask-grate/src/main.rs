use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::{
    constants::SYS_UMASK,
    getcageid, make_threei_call, GrateBuilder, GrateError,
};

/// Bits forced into every umask the cage sets.
/// Default 0o000 adds no restriction to the requested mask.
static FORCE_BITS: AtomicU64 = AtomicU64::new(0o000);

extern "C" fn umask_handler(
    cageid: u64,
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
    let enforced_mask = (mask | FORCE_BITS.load(Ordering::Relaxed)) & 0o777;
    // 3i dispatches by self_cageid. Forward as this grate so the call uses
    // the grate's RawPOSIX entry instead of re-entering this handler.
    let grate_cageid = getcageid();

    match make_threei_call(
        SYS_UMASK as u32,
        0,
        grate_cageid,
        cageid,
        enforced_mask,
        cageid,
        0,
        cageid,
        0,
        cageid,
        0,
        cageid,
        0,
        cageid,
        0,
        cageid,
        0,
    ) {
        Ok(result) => result,
        Err(GrateError::MakeSyscallError(errno)) => errno,
        Err(_) => -1,
    }
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

    GrateBuilder::new()
        .register(SYS_UMASK, umask_handler)
        .teardown(|result| match result {
            Ok(status) => println!("[umask-grate] child exited with status: {status}"),
            Err(e) => {
                eprintln!("[umask-grate] error: {:#?}", e);
                std::process::exit(-1);
            }
        })
        .run(config.remaining_args);
}
