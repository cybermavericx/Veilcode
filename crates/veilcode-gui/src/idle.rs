//! Idle auto-lock timer (SPEC §7, D100), driven by the core `Clock` so it
//! also runs while the window is hidden and is testable without sleeping.

/// Lock after this many seconds without input.
pub const IDLE_LIMIT_SECS: u64 = 10 * 60;

/// Remembers the time of the last input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleTimer {
    last_input: u64,
}

impl IdleTimer {
    /// A timer whose last input was at `now` (unix seconds).
    pub fn new(now: u64) -> Self {
        IdleTimer { last_input: now }
    }

    /// Records input at `now`.
    pub fn reset(&mut self, now: u64) {
        self.last_input = now;
    }

    /// True once more than `IDLE_LIMIT_SECS` have passed without input.
    /// A clock that went backwards counts as no time passed.
    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_input) > IDLE_LIMIT_SECS
    }
}
