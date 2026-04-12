use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::resources::ResourceConfig;

/// Busy-wait for the given duration using yield.
/// Lind's WASM sysroot doesn't provide clock_nanosleep (which both
/// std::thread::sleep and libc::nanosleep require on WASI), so we
/// spin with sched_yield like the IPC grate does.
fn lind_sleep(dur: Duration) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        std::thread::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Renewable resource: token-bucket rate limiter
//
// Rate-limited resources (e.g. filewrite, netrecv, random) that refill over
// time.  Each resource tracks a token bucket: consumption accumulates and
// drains at `allowed_per_sec`.  When consumption exceeds the per-second
// budget the caller is blocked until it drains back below the threshold.
// ---------------------------------------------------------------------------

struct RenewableInner {
    /// Accumulated consumption that hasn't yet drained.
    consumed: f64,
    /// Timestamp of the last drain calculation.
    last_update: Instant,
}

struct RenewableResource {
    /// Maximum tokens per second (refill rate and burst cap).
    allowed_per_sec: f64,
    /// Mutable accounting state, protected by a mutex so concurrent
    /// callers on the same resource are serialized (matches repy behaviour).
    inner: Mutex<RenewableInner>,
}

// ---------------------------------------------------------------------------
// Fungible resource: counted cap
//
// Resources with a fixed concurrent limit (e.g. filesopened, events).
// Acquiring increments the count; releasing decrements it.  Requests
// that would exceed the limit are denied immediately.
// ---------------------------------------------------------------------------

struct FungibleResource {
    /// Maximum number of concurrent slots.
    limit: usize,
    /// Current number of acquired slots.
    count: Mutex<usize>,
}

// ---------------------------------------------------------------------------
// NannyState: all resource accounting for the cage
//
// Central accounting struct that holds every configured resource.
// Handlers call `tattle_quantity` (renewable), `tattle_add_item` /
// `tattle_remove_item` (fungible), or `is_item_allowed` (individual)
// to enforce limits before forwarding syscalls.
// ---------------------------------------------------------------------------

pub struct NannyState {
    /// Token-bucket rate limiters keyed by resource name
    /// (e.g. "filewrite", "netrecv", "random").
    renewable: HashMap<String, RenewableResource>,
    /// Counted caps keyed by resource name (e.g. "filesopened", "events").
    fungible: HashMap<String, FungibleResource>,
    /// Per-item allowlists keyed by resource name (e.g. "messport",
    /// "connport").  The `HashSet<u16>` contains the permitted port numbers.
    individual: HashMap<String, HashSet<u16>>,
    /// Hard byte caps (currently unused, reserved for future enforcement).
    #[allow(dead_code)]
    hard_caps: HashMap<String, u64>,
}

impl NannyState {
    pub fn from_config(config: ResourceConfig) -> Self {
        let now = Instant::now();

        let renewable = config
            .renewable
            .into_iter()
            .map(|(name, rate)| {
                (
                    name,
                    RenewableResource {
                        allowed_per_sec: rate,
                        inner: Mutex::new(RenewableInner {
                            consumed: 0.0,
                            last_update: now,
                        }),
                    },
                )
            })
            .collect();

        let fungible = config
            .fungible
            .into_iter()
            .map(|(name, limit)| {
                (
                    name,
                    FungibleResource {
                        limit,
                        count: Mutex::new(0),
                    },
                )
            })
            .collect();

        NannyState {
            renewable,
            fungible,
            individual: config.individual,
            hard_caps: config.hard_caps,
        }
    }

    /// Charge a renewable resource.  Blocks the caller if the resource is
    /// over-subscribed.  Passing `quantity = 0.0` is a pre-check that blocks
    /// until capacity is available without adding new consumption.
    ///
    /// Algorithm (from repy nanny.py):
    ///   1. Lock the resource
    ///   2. Drain: consumed -= elapsed * allowed_per_sec
    ///   3. Clamp consumed >= 0
    ///   4. consumed += quantity
    ///   5. If consumed > allowed_per_sec:
    ///        sleep_time = (consumed - allowed_per_sec) / allowed_per_sec
    ///        sleep(sleep_time)
    ///        Re-drain after waking
    ///   6. Update last_update = now
    ///   7. Unlock
    pub fn tattle_quantity(&self, resource: &str, quantity: f64) {
        let res = match self.renewable.get(resource) {
            Some(r) => r,
            None => return, // not configured → unlimited
        };

        let mut inner = res.inner.lock().unwrap();

        // Drain based on elapsed time.
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last_update).as_secs_f64();
        inner.consumed -= elapsed * res.allowed_per_sec;
        if inner.consumed < 0.0 {
            inner.consumed = 0.0;
        }
        inner.last_update = now;

        // Add new consumption.
        inner.consumed += quantity;

        // If over budget, sleep until it drains.  The lock is held during
        // sleep so concurrent users of the same resource block as well —
        // this is intentional and matches repy's behaviour.
        if inner.consumed > res.allowed_per_sec {
            let sleep_secs = (inner.consumed - res.allowed_per_sec) / res.allowed_per_sec;
            lind_sleep(Duration::from_secs_f64(sleep_secs));

            // Re-drain after waking.
            let now = Instant::now();
            let elapsed = now.duration_since(inner.last_update).as_secs_f64();
            inner.consumed -= elapsed * res.allowed_per_sec;
            if inner.consumed < 0.0 {
                inner.consumed = 0.0;
            }
            inner.last_update = now;
        }
    }

    /// Try to acquire one slot of a fungible resource.
    /// Returns `Ok(())` if under the limit, `Err(())` if at capacity.
    pub fn tattle_add_item(&self, resource: &str) -> Result<(), ()> {
        let res = match self.fungible.get(resource) {
            Some(r) => r,
            None => return Ok(()), // not configured → unlimited
        };

        let mut count = res.count.lock().unwrap();
        if *count >= res.limit {
            Err(())
        } else {
            *count += 1;
            Ok(())
        }
    }

    /// Release one slot of a fungible resource.
    pub fn tattle_remove_item(&self, resource: &str) {
        let res = match self.fungible.get(resource) {
            Some(r) => r,
            None => return,
        };

        let mut count = res.count.lock().unwrap();
        *count = count.saturating_sub(1);
    }

    /// Check whether an individual item (port number) is allowed.
    /// Returns `true` if the resource is not configured (no restriction).
    pub fn is_item_allowed(&self, resource: &str, item: u16) -> bool {
        match self.individual.get(resource) {
            Some(set) => set.contains(&item),
            None => true, // not configured → all allowed
        }
    }
}
