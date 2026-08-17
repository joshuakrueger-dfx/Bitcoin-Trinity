//! Injected clocks for the spend window (TESTING.md §2.4, Spec O18).
//!
//! [`MonotonicClock`] is boot-relative. [`BlockHeightSource`] is the
//! local stand-in for `trinity-chain::ChainBackend::tip_height` — this
//! crate must not depend on `trinity-chain`.

#[cfg(any(test, feature = "test-util"))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(test, feature = "test-util"))]
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Boot-relative clock. Tests set it explicitly.
pub trait MonotonicClock: Send + Sync {
    /// Duration since an arbitrary, platform-owned origin.
    fn now(&self) -> Duration;

    /// Optional boot generation. A change (or a `now` that is *behind*
    /// the persisted anchor) means the monotonic reading is not
    /// trustworthy across the reboot.
    fn boot_id(&self) -> Option<u64> {
        None
    }
}

/// Chain tip. `None` = unreachable / offline — no block progress.
///
/// A reported height is a **brake** on the spend window (`min` with a
/// trusted monotonic delta), never a standalone source of elapsed time:
/// a freely configured Electrum/RPC server can claim any tip. Branch
/// `(None, Some(h))` of the combiner therefore yields zero. That branch
/// may return only once `tip_height` is backed by a PoW-validated
/// header chain with cumulative work — not by this trait as it stands.
pub trait BlockHeightSource: Send + Sync {
    /// Best known tip, or `None` when the attachment cannot be read.
    fn tip_height(&self) -> Option<u32>;
}

/// Test clock whose time and boot id are set by the caller.
#[cfg(any(test, feature = "test-util"))]
pub struct FakeClock {
    now_ns: AtomicU64,
    boot_id: AtomicU64,
}

#[cfg(any(test, feature = "test-util"))]
impl FakeClock {
    /// Boot 1, time zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now_ns: AtomicU64::new(0),
            boot_id: AtomicU64::new(1),
        }
    }

    /// Set the monotonic reading.
    pub fn set(&self, now: Duration) {
        let ns = u64::try_from(now.as_nanos()).unwrap_or(u64::MAX);
        self.now_ns.store(ns, Ordering::SeqCst);
    }

    /// Advance by `delta` (saturating).
    ///
    /// Concurrent calls cannot wrap the clock backwards: a
    /// `compare_exchange_weak` loop stores `now.saturating_add(delta)`
    /// or retries from the value another caller just wrote.
    pub fn advance(&self, delta: Duration) {
        let extra = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        let mut now = self.now_ns.load(Ordering::SeqCst);
        loop {
            let next = now.saturating_add(extra);
            match self
                .now_ns
                .compare_exchange_weak(now, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(actual) => now = actual,
            }
        }
    }

    /// New boot session: time restarts at zero, boot id increments.
    pub fn reboot(&self) {
        self.now_ns.store(0, Ordering::SeqCst);
        self.boot_id.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl MonotonicClock for FakeClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.now_ns.load(Ordering::SeqCst))
    }

    fn boot_id(&self) -> Option<u64> {
        Some(self.boot_id.load(Ordering::SeqCst))
    }
}

/// Test tip. `None` models an offline / stalled attachment.
#[cfg(any(test, feature = "test-util"))]
pub struct FakeBlockHeightSource {
    tip: Mutex<Option<u32>>,
}

#[cfg(any(test, feature = "test-util"))]
fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(test, feature = "test-util"))]
impl FakeBlockHeightSource {
    /// Start at `tip` (`None` = offline).
    #[must_use]
    pub fn new(tip: Option<u32>) -> Self {
        Self {
            tip: Mutex::new(tip),
        }
    }

    /// Replace the tip.
    pub fn set(&self, tip: Option<u32>) {
        *locked(&self.tip) = tip;
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for FakeBlockHeightSource {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl BlockHeightSource for FakeBlockHeightSource {
    fn tip_height(&self) -> Option<u32> {
        *locked(&self.tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoBoot(Duration);
    impl MonotonicClock for NoBoot {
        fn now(&self) -> Duration {
            self.0
        }
    }

    #[test]
    fn fake_clock_set_advance_reboot() {
        let c = FakeClock::new();
        assert_eq!(c.now(), Duration::ZERO);
        assert_eq!(c.boot_id(), Some(1));
        c.set(Duration::from_secs(10));
        assert_eq!(c.now(), Duration::from_secs(10));
        c.advance(Duration::from_secs(2));
        assert_eq!(c.now(), Duration::from_secs(12));
        c.reboot();
        assert_eq!(c.now(), Duration::ZERO);
        assert_eq!(c.boot_id(), Some(2));
        let d = FakeClock::default();
        assert_eq!(d.boot_id(), Some(1));
    }

    #[test]
    fn fake_clock_advance_saturates() {
        let c = FakeClock::new();
        c.set(Duration::from_nanos(u64::MAX));
        c.advance(Duration::from_nanos(10));
        assert_eq!(c.now(), Duration::from_nanos(u64::MAX));
    }

    #[test]
    fn fake_clock_concurrent_advances_do_not_wrap() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(FakeClock::new());
        c.set(Duration::from_nanos(u64::MAX - 5));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let clock = Arc::clone(&c);
                thread::spawn(move || clock.advance(Duration::from_nanos(10)))
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.now(), Duration::from_nanos(u64::MAX));
    }

    #[test]
    fn fake_clock_concurrent_advances_sum() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(FakeClock::new());
        const THREADS: u64 = 8;
        const EACH: u64 = 5_000;
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let clock = Arc::clone(&c);
                thread::spawn(move || {
                    for _ in 0..EACH {
                        clock.advance(Duration::from_nanos(1));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.now(), Duration::from_nanos(THREADS * EACH));
    }

    #[test]
    fn default_boot_id_is_none() {
        let c = NoBoot(Duration::from_millis(3));
        assert_eq!(c.now(), Duration::from_millis(3));
        assert_eq!(c.boot_id(), None);
    }

    #[test]
    fn fake_blocks_offline_and_set() {
        let b = FakeBlockHeightSource::default();
        assert_eq!(b.tip_height(), None);
        b.set(Some(800_000));
        assert_eq!(b.tip_height(), Some(800_000));
        b.set(None);
        assert_eq!(b.tip_height(), None);
        let online = FakeBlockHeightSource::new(Some(1));
        assert_eq!(online.tip_height(), Some(1));
    }
}
