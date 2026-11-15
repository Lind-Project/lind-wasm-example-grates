//! seeded-random-grate
//!
//! Answers every `getrandom` of its child cages from a declared seed, so the bytes a program
//! reads depend only on the seed, on the cage that asks and on how much that cage has read
//! before, never on the hardware or the host.
//! The seed comes from `RANDOM_GRATE_SEED` (an unsigned 64-bit number), default 0.

mod stream;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use grate_rs::{GrateBuilder, constants::SYS_GETRANDOM, copy_data_between_cages, getcageid};

const GRND_NONBLOCK: u32 = 1;
const GRND_RANDOM: u32 = 2;
const GRND_INSECURE: u32 = 4;

const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

// The most one call returns, as in Linux. A caller that asks for more gets a short count.
const MAX_READ: u64 = 0x1ff_ffff;

static SEED: OnceLock<u64> = OnceLock::new();
// How far each cage has read into its stream. A BTreeMap, because a HashMap would seed itself
// with the randomness this grate replaces.
static POSITIONS: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());
static CALLS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

pub extern "C" fn getrandom_handler(
    _cageid: u64,
    buf: u64,
    buf_cage: u64,
    buflen: u64,
    _buflen_cage: u64,
    flags: u64,
    _flags_cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i64 {
    getrandom(buf, buf_cage, buflen, flags as u32) as _
}

fn getrandom(buf: u64, cage: u64, buflen: u64, flags: u32) -> i64 {
    // Every flag gets the same stream; the flag combinations Linux refuses are refused here too.
    let insecure_random = GRND_INSECURE | GRND_RANDOM;
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & insecure_random == insecure_random
    {
        return -EINVAL;
    }

    let len = buflen.min(MAX_READ);
    // The range is taken before the copy, so two threads of one cage never get the same bytes.
    let start = {
        let mut positions = POSITIONS.lock().unwrap_or_else(|e| e.into_inner());
        let position = positions.entry(cage).or_insert(0);
        let start = *position;
        *position += len;
        start
    };

    let seed = SEED.get().copied().unwrap_or(0);
    let grate = getcageid();
    let mut chunk = [0u8; 4096];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(chunk.len() as u64);
        stream::fill(seed, cage, start + done, &mut chunk[..n as usize]);
        if copy_data_between_cages(
            grate,
            cage,
            chunk.as_ptr() as u64,
            grate,
            buf + done,
            cage,
            n,
            0,
        )
        .is_err()
        {
            return -EFAULT;
        }
        done += n;
    }

    CALLS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(len, Ordering::Relaxed);
    len as i64
}

fn main() {
    // A seed that does not parse stops the grate: falling back to 0 would run the build under a
    // seed nobody declared.
    let seed = match std::env::var("RANDOM_GRATE_SEED") {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            eprintln!(
                "[seeded-random-grate] RANDOM_GRATE_SEED is not an unsigned 64-bit number: {v}"
            );
            std::process::exit(2);
        }),
        Err(_) => 0,
    };
    SEED.set(seed).unwrap();

    let grate = GrateBuilder::new()
        .register(SYS_GETRANDOM, getrandom_handler)
        .teardown(|result| match result {
            Ok(status) => eprintln!(
                "[seeded-random-grate] child exited with status: {status}; served {} calls, {} bytes",
                CALLS.load(Ordering::Relaxed),
                BYTES.load(Ordering::Relaxed)
            ),
            Err(e) => {
                eprintln!(
                    "[seeded-random-grate] unable to launch child cages: {:#?}",
                    e
                );
                std::process::exit(-1);
            }
        });

    let argv = std::env::args().skip(1).collect();
    grate.run(argv);
}
