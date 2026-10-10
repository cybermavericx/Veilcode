//! Injected wall-clock time (D61 session expiry; GUI auto-lock).

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of unix seconds.
pub trait Clock {
    /// Seconds since the unix epoch.
    fn now_unix(&self) -> u64;
}

/// The system clock. A time before the epoch reads as 0 (never panics).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// A clock that only moves when told to. Test-only (D70).
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

#[cfg(test)]
impl ManualClock {
    /// A clock reading `now` unix seconds.
    pub fn new(now: u64) -> Self {
        ManualClock(AtomicU64::new(now))
    }

    /// Sets the time.
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    /// Moves the time forward by `secs` (saturating).
    pub fn advance(&self, secs: u64) {
        let now = self.now_unix().saturating_add(secs);
        self.set(now);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now_unix(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::new(100);
        assert_eq!(c.now_unix(), 100);
        c.advance(5);
        assert_eq!(c.now_unix(), 105);
        c.set(7);
        assert_eq!(c.now_unix(), 7);
        c.set(u64::MAX);
        c.advance(1);
        assert_eq!(c.now_unix(), u64::MAX);
        assert!(SystemClock.now_unix() > 1_700_000_000);
    }
}
