//! logical-clock-grate
//!
//! Answers every `clock_gettime` with a declared epoch plus a logical tick, so `time(NULL)` and
//! `gettimeofday` in the child cages depend only on the order of calls, never on the host clock.
//! The epoch comes from `LOGICAL_CLOCK_EPOCH` (seconds), default 0, as in the IMFS grate.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use grate_rs::{GrateBuilder, constants::SYS_CLOCK_GETTIME, copy_data_between_cages, getcageid};

// Each call advances the clock by one millisecond, so loops that wait for time to pass still end.
const TICK_NS: u64 = 1_000_000;

static EPOCH: OnceLock<u64> = OnceLock::new();
static CALLS: AtomicU64 = AtomicU64::new(0);

pub extern "C" fn clock_gettime_handler(
    _cageid: u64,
    _clockid: u64,
    _clockid_cage: u64,
    tp: u64,
    tp_cage: u64,
    _arg3: u64,
    _arg3cage: u64,
    _arg4: u64,
    _arg4cage: u64,
    _arg5: u64,
    _arg5cage: u64,
    _arg6: u64,
    _arg6cage: u64,
) -> i32 {
    let ns = CALLS.fetch_add(1, Ordering::SeqCst) * TICK_NS;
    let sec = EPOCH.get().copied().unwrap_or(0) + ns / 1_000_000_000;
    let mut ts = [0u8; 16];
    ts[..8].copy_from_slice(&sec.to_le_bytes());
    ts[8..].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());

    let grate = getcageid();
    match copy_data_between_cages(
        grate,
        tp_cage,
        ts.as_ptr() as u64,
        grate,
        tp,
        tp_cage,
        16,
        0,
    ) {
        Ok(()) => 0,
        Err(_) => -14, // EFAULT
    }
}

fn main() {
    let epoch = std::env::var("LOGICAL_CLOCK_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    EPOCH.set(epoch).unwrap();

    let grate = GrateBuilder::new()
        .register(SYS_CLOCK_GETTIME, clock_gettime_handler)
        .teardown(|result| match result {
            Ok(status) => eprintln!("[logical-clock-grate] child exited with status: {status}"),
            Err(e) => {
                eprintln!(
                    "[logical-clock-grate] unable to launch child cages: {:#?}",
                    e
                );
                std::process::exit(-1);
            }
        });

    let argv = std::env::args().skip(1).collect();
    grate.run(argv);
}
