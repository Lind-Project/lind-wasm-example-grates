use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::{
    GrateBuilder, GrateError,
    constants::SYS_FCHMOD,
    make_threei_call,
};

static MASK: AtomicU64 = AtomicU64::new(0o7777);

extern "C" fn fchmod_handler(
    cageid: u64,
    fd: u64,
    fd_cage: u64,
    mode: u64,
    mode_cage: u64,
    arg3: u64,
    arg3cage: u64,
    arg4: u64,
    arg4cage: u64,
    arg5: u64,
    arg5cage: u64,
    arg6: u64,
    arg6cage: u64,
) -> i32 {
    let masked_mode = mode & MASK.load(Ordering::Relaxed);

    match make_threei_call(
        SYS_FCHMOD as u32,
        0,
        cageid,
        fd_cage,
        fd,
        fd_cage,
        masked_mode,
        mode_cage,
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
    mask: u64,
    remaining_args: Vec<String>,
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mask = 0o7777u64;
    let mut remaining_args = Vec::new();
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--mask" {
            if i + 1 >= args.len() {
                return Err("--mask requires an argument".to_string());
            }
            mask = u64::from_str_radix(&args[i + 1], 8)
                .map_err(|_| format!("--mask: '{}' is not a valid octal value", args[i + 1]))?;
            i += 2;
        } else {
            remaining_args.push(args[i].clone());
            i += 1;
        }
    }

    Ok(Config { mask, remaining_args })
}

fn main() {
    let config = match parse_args() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("argument error: {}", err);
            eprintln!("Usage: fchmod-grate [--mask <octal>] <program> [args...]");
            std::process::exit(1);
        }
    };

    MASK.store(config.mask, Ordering::Relaxed);

    GrateBuilder::new()
        .register(SYS_FCHMOD, fchmod_handler)
        .teardown(|result| match result {
            Ok(status) => println!("[fchmod-grate] child exited with status: {status}"),
            Err(e) => {
                eprintln!("[fchmod-grate] error: {:#?}", e);
                std::process::exit(-1);
            }
        })
        .run(config.remaining_args);
}
