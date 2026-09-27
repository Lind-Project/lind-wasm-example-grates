use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use grate_rs::{GrateBuilder, constants::SYS_UMASK};

/// Bits forced into every umask the cage sets.
/// Default 0o000 adds no restriction to the requested mask.
static FORCE_BITS: AtomicU64 = AtomicU64::new(0o000);

/// The default effective umask for a newly observed cage.
const INITIAL_UMASK: u64 = 0o022;

/// Effective umasks keyed by the cage currently making the syscall.
///
/// The grate handler receives the destination grate ID as its first argument.
/// The `mask_cage` metadata identifies the cage that owns the syscall argument,
/// which is the calling cage for `umask`. Keep the state keyed by that ID so
/// calls from different cages cannot overwrite one another's umask. The mutex
/// also makes the read-and-replace operation equivalent to the old atomic swap
/// when grate calls execute concurrently.
static CAGE_UMASKS: LazyLock<Mutex<HashMap<u64, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

extern "C" fn umask_handler(
    _grate_id: u64,
    mask: u64,
    mask_cage: u64,
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
    let cage_id = mask_cage;

    let mut cage_umasks = CAGE_UMASKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous_mask = cage_umasks
        .insert(cage_id, enforced_mask)
        .unwrap_or(INITIAL_UMASK);

    previous_mask as i32
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
