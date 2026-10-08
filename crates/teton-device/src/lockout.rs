//! Device-wide rate limits (SPEC.md §7.1, §7.3). Both live in memory only.

use std::time::Duration;

use tokio::time::Instant;

/// Paces Wi-Fi join attempts after consecutive failures that reached the
/// network's authentication: none for the first three, then 30 s, 60 s and
/// 120 s from then on. A successful join resets it. Reconnecting over BLE
/// does not, because this state belongs to the device, not the session.
#[derive(Debug, Default)]
pub struct JoinLockout {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

impl JoinLockout {
    pub const FREE_ATTEMPTS: u32 = 3;

    pub fn remaining(&self, now: Instant) -> Duration {
        self.locked_until
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures += 1;
        let secs = match self.consecutive_failures {
            n if n < Self::FREE_ATTEMPTS => return,
            n if n == Self::FREE_ATTEMPTS => 30,
            n if n == Self::FREE_ATTEMPTS + 1 => 60,
            _ => 120,
        };
        self.locked_until = Some(now + Duration::from_secs(secs));
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}

/// Refuses new sessions for a while after sessions that ended in decryption
/// failures (someone without the label, or a bug): 5 s, doubling to 300 s.
/// A session that verifies the device resets it.
#[derive(Debug, Default)]
pub struct ConnectionBackoff {
    level: u32,
    until: Option<Instant>,
}

impl ConnectionBackoff {
    const BASE: Duration = Duration::from_secs(5);
    const MAX: Duration = Duration::from_secs(300);

    pub fn remaining(&self, now: Instant) -> Duration {
        self.until
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    pub fn record_failure(&mut self, now: Instant) {
        let delay = Self::BASE
            .checked_mul(1 << self.level.min(16))
            .map_or(Self::MAX, |d| d.min(Self::MAX));
        self.level += 1;
        self.until = Some(now + delay);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Whole seconds, rounded up, for `retry_after` fields.
pub fn ceil_secs(d: Duration) -> u32 {
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    u32::try_from(secs).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn join_lockout_schedule() {
        let t0 = Instant::now();
        let mut l = JoinLockout::default();
        l.record_failure(t0);
        l.record_failure(t0);
        assert_eq!(l.remaining(t0), Duration::ZERO, "first attempts are free");
        l.record_failure(t0);
        assert_eq!(l.remaining(t0), S(30));
        assert_eq!(l.remaining(t0 + S(10)), S(20));
        assert_eq!(l.remaining(t0 + S(31)), Duration::ZERO);
        l.record_failure(t0 + S(31));
        assert_eq!(l.remaining(t0 + S(31)), S(60));
        l.record_failure(t0 + S(100));
        assert_eq!(l.remaining(t0 + S(100)), S(120));
        l.record_failure(t0 + S(300));
        assert_eq!(l.remaining(t0 + S(300)), S(120), "capped");
        l.record_success();
        l.record_failure(t0 + S(300));
        assert_eq!(l.remaining(t0 + S(300)), Duration::ZERO, "success resets");
    }

    #[test]
    fn connection_backoff_doubles_and_caps() {
        let t0 = Instant::now();
        let mut b = ConnectionBackoff::default();
        let mut seen = vec![];
        for _ in 0..8 {
            b.record_failure(t0);
            seen.push(b.remaining(t0).as_secs());
        }
        assert_eq!(seen, [5, 10, 20, 40, 80, 160, 300, 300]);
        b.reset();
        assert_eq!(b.remaining(t0), Duration::ZERO);
    }

    #[test]
    fn rounds_up() {
        assert_eq!(ceil_secs(Duration::from_millis(29_001)), 30);
        assert_eq!(ceil_secs(S(30)), 30);
        assert_eq!(ceil_secs(Duration::ZERO), 0);
    }
}
