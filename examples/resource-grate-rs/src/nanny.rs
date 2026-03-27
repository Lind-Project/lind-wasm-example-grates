use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::resources::ResourceConfig;

// ---------------------------------------------------------------------------
// Renewable resource: token-bucket rate limiter
// ---------------------------------------------------------------------------

struct RenewableInner {
    consumed: f64,
    last_update: Instant,
}

struct RenewableResource {
    allowed_per_sec: f64,
    inner: Mutex<RenewableInner>,
}

// ---------------------------------------------------------------------------
// Fungible resource: counted cap
// ---------------------------------------------------------------------------

struct FungibleResource {
    limit: usize,
    count: Mutex<usize>,
}

// ---------------------------------------------------------------------------
// NannyState: all resource accounting for the cage
// ---------------------------------------------------------------------------

pub struct NannyState {
    renewable: HashMap<String, RenewableResource>,
    fungible: HashMap<String, FungibleResource>,
    individual: HashMap<String, HashSet<u16>>,
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
            std::thread::sleep(Duration::from_secs_f64(sleep_secs));

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
