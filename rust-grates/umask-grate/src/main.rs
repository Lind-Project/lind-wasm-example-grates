use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::{
    GrateBuilder, GrateError,
    constants::SYS_UMASK,
    make_threei_call,
};

/// The "ceiling" mask: any bits NOT in this mask will be forced into
/// every umask the cage sets. Default 0o000 = no restriction (pass through).
static FORCE_BITS: AtomicU64 = AtomicU64::new(0o000);

extern "C" fn umask_handler(
    cageid: u64,
    mask: u64,
    mask_cage: u64,
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
) -> i64 {
    // Force any required bits into the cage's requested umask.
    // e.g. with --force-bits 022, the cage can never set a umask
    // that would allow group-write or other-write.
    let enforced_mask = mask | FORCE_BITS.load(Ordering::Relaxed);

    match make_threei_call(
        SYS_UMASK as u32,
        0,
        cageid,
        mask_cage,
        enforced_mask,
        mask_cage,
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
        Err(GrateError::MakeSyscallError(n)) => n,
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
            force_bits = u64::from_str_radix(&args[i + 1], 8)
                .map_err(|_| format!("--force-bits: '{}' is not a valid octal value", args[i + 1]))?;
            i += 2;
        } else {
            remaining_args.push(args[i].clone());
            i += 1;
        }
    }

    Ok(Config { force_bits, remaining_args })
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

    FORCE_BITS.store(config.force_bits, Ordering::Relaxed);

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
