//! Retry budgets and deterministic timers.

const UNLIMITED_RETRY_CODE: u8 = 7;
const MAX_RETRY_CODE: u8 = 7;

const RNR_TIMER_MICROSECONDS: [u64; 32] = [
    655_360, 10, 20, 30, 40, 60, 80, 120, 160, 240, 320, 480, 640, 960, 1_280, 1_920, 2_560, 3_840,
    5_120, 7_680, 10_240, 15_360, 20_480, 30_720, 40_960, 61_440, 81_920, 122_880, 163_840,
    245_760, 327_680, 491_520,
];

/// Cause consuming an RC retry budget.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetryReason {
    /// No valid ACK arrived before the local timeout.
    Timeout,
    /// The peer returned a receiver-not-ready NAK.
    ReceiverNotReady,
}

/// Result of charging a retry budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    /// Retry after the supplied caller-defined delay.
    Retry {
        /// Number of caller timer ticks to wait.
        delay_ticks: u64,
    },
    /// The applicable finite retry budget has been exhausted.
    Exhausted {
        /// Failure that exhausted the budget.
        reason: RetryReason,
    },
}

/// Immutable retry policy negotiated for a queue pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Number of timeout retries; `7` means unlimited.
    pub retry_count: u8,
    /// Number of receiver-not-ready retries; `7` means unlimited.
    pub rnr_retry_count: u8,
    /// Delay, in caller-defined ticks, before retransmission after timeout.
    pub timeout_ticks: u64,
}

impl RetryPolicy {
    /// Construct a policy when both three-bit retry fields are valid.
    #[must_use]
    pub const fn new(retry_count: u8, rnr_retry_count: u8, timeout_ticks: u64) -> Option<Self> {
        if retry_count <= MAX_RETRY_CODE && rnr_retry_count <= MAX_RETRY_CODE {
            Some(Self {
                retry_count,
                rnr_retry_count,
                timeout_ticks,
            })
        } else {
            None
        }
    }
}

/// Mutable remaining retry counts for one queue pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBudget {
    policy: RetryPolicy,
    remaining_timeout: u8,
    remaining_rnr: u8,
}

impl RetryBudget {
    /// Create a full budget from a validated policy.
    #[must_use]
    pub const fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            remaining_timeout: policy.retry_count,
            remaining_rnr: policy.rnr_retry_count,
        }
    }

    /// Return the active immutable policy.
    #[must_use]
    pub const fn policy(self) -> RetryPolicy {
        self.policy
    }

    /// Return the remaining finite timeout retries.
    #[must_use]
    pub const fn remaining_timeout(self) -> u8 {
        self.remaining_timeout
    }

    /// Return the remaining finite RNR retries.
    #[must_use]
    pub const fn remaining_rnr(self) -> u8 {
        self.remaining_rnr
    }

    /// Reset both counters after forward progress or QP reset.
    pub const fn reset(&mut self) {
        self.remaining_timeout = self.policy.retry_count;
        self.remaining_rnr = self.policy.rnr_retry_count;
    }

    /// Charge one failure and decide whether the operation may be retried.
    ///
    /// `rnr_delay_ticks` is ignored for timeout failures.
    pub const fn on_failure(&mut self, reason: RetryReason, rnr_delay_ticks: u64) -> RetryDecision {
        match reason {
            RetryReason::Timeout => {
                if self.policy.retry_count == UNLIMITED_RETRY_CODE {
                    return RetryDecision::Retry {
                        delay_ticks: self.policy.timeout_ticks,
                    };
                }
                if self.remaining_timeout == 0 {
                    return RetryDecision::Exhausted { reason };
                }
                self.remaining_timeout -= 1;
                RetryDecision::Retry {
                    delay_ticks: self.policy.timeout_ticks,
                }
            }
            RetryReason::ReceiverNotReady => {
                if self.policy.rnr_retry_count == UNLIMITED_RETRY_CODE {
                    return RetryDecision::Retry {
                        delay_ticks: rnr_delay_ticks,
                    };
                }
                if self.remaining_rnr == 0 {
                    return RetryDecision::Exhausted { reason };
                }
                self.remaining_rnr -= 1;
                RetryDecision::Retry {
                    delay_ticks: rnr_delay_ticks,
                }
            }
        }
    }
}

/// A simple absolute-deadline timer driven by caller-provided monotonic ticks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timer {
    deadline: Option<u64>,
}

impl Timer {
    /// Create a disarmed timer.
    #[must_use]
    pub const fn new() -> Self {
        Self { deadline: None }
    }

    /// Arm the timer, saturating if `now + delay_ticks` overflows.
    pub const fn arm(&mut self, now: u64, delay_ticks: u64) {
        self.deadline = Some(now.saturating_add(delay_ticks));
    }

    /// Disarm the timer.
    pub const fn cancel(&mut self) {
        self.deadline = None;
    }

    /// Return the absolute deadline, if armed.
    #[must_use]
    pub const fn deadline(self) -> Option<u64> {
        self.deadline
    }

    /// Return whether the timer is armed.
    #[must_use]
    pub const fn is_armed(self) -> bool {
        self.deadline.is_some()
    }

    /// Return whether `now` has reached the deadline.
    #[must_use]
    pub const fn expired(self, now: u64) -> bool {
        match self.deadline {
            Some(deadline) => now >= deadline,
            None => false,
        }
    }

    /// Return ticks remaining, saturating at zero.
    #[must_use]
    pub const fn remaining(self, now: u64) -> Option<u64> {
        match self.deadline {
            Some(deadline) => Some(deadline.saturating_sub(now)),
            None => None,
        }
    }
}

/// Convert the five-bit RC local ACK timeout code to caller timer ticks.
///
/// `InfiniBand` defines the timeout as `4.096 microseconds * 2^code`. The
/// conversion rounds up so a configured timeout is never shortened.
#[must_use]
pub fn ack_timeout_ticks(code: u8, ticks_per_second: u64) -> Option<u64> {
    if code >= 32 || ticks_per_second == 0 {
        return None;
    }

    let nanoseconds = 4_096_u128.checked_shl(u32::from(code))?;
    let numerator = nanoseconds.checked_mul(u128::from(ticks_per_second))?;
    let ticks = numerator.div_ceil(1_000_000_000);
    u64::try_from(ticks).ok()
}

/// Convert a five-bit AETH RNR timer code to microseconds.
#[must_use]
pub fn rnr_timer_microseconds(code: u8) -> Option<u64> {
    if code < 32 {
        Some(RNR_TIMER_MICROSECONDS[usize::from(code)])
    } else {
        None
    }
}

/// Convert a five-bit AETH RNR timer code to caller timer ticks.
///
/// The conversion rounds up so a peer-requested delay is never shortened.
#[must_use]
pub fn rnr_timer_ticks(code: u8, ticks_per_second: u64) -> Option<u64> {
    if ticks_per_second == 0 {
        return None;
    }

    let microseconds = u128::from(rnr_timer_microseconds(code)?);
    let numerator = microseconds.checked_mul(u128::from(ticks_per_second))?;
    let ticks = numerator.div_ceil(1_000_000);
    u64::try_from(ticks).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_timeout_conversion_matches_wire_code() {
        assert_eq!(ack_timeout_ticks(0, 1_000_000), Some(5));
        assert_eq!(ack_timeout_ticks(14, 1_000_000), Some(67_109));
        assert_eq!(ack_timeout_ticks(32, 1_000_000), None);
        assert_eq!(ack_timeout_ticks(1, 0), None);
    }

    #[test]
    fn rnr_table_matches_edge_codes() {
        assert_eq!(rnr_timer_microseconds(0), Some(655_360));
        assert_eq!(rnr_timer_microseconds(1), Some(10));
        assert_eq!(rnr_timer_microseconds(31), Some(491_520));
        assert_eq!(rnr_timer_microseconds(32), None);
    }

    #[test]
    fn tick_conversion_rounds_up() {
        assert_eq!(rnr_timer_ticks(1, 1_000), Some(1));
        assert_eq!(rnr_timer_ticks(1, 1_000_000), Some(10));
        assert_eq!(rnr_timer_ticks(1, 0), None);
    }

    #[test]
    fn finite_budget_exhausts_after_configured_retries() {
        let policy = RetryPolicy::new(1, 2, 50).unwrap();
        let mut budget = RetryBudget::new(policy);

        assert_eq!(
            budget.on_failure(RetryReason::Timeout, 0),
            RetryDecision::Retry { delay_ticks: 50 }
        );
        assert_eq!(
            budget.on_failure(RetryReason::Timeout, 0),
            RetryDecision::Exhausted {
                reason: RetryReason::Timeout,
            }
        );

        assert_eq!(
            budget.on_failure(RetryReason::ReceiverNotReady, 7),
            RetryDecision::Retry { delay_ticks: 7 }
        );
        assert_eq!(
            budget.on_failure(RetryReason::ReceiverNotReady, 7),
            RetryDecision::Retry { delay_ticks: 7 }
        );
        assert_eq!(
            budget.on_failure(RetryReason::ReceiverNotReady, 7),
            RetryDecision::Exhausted {
                reason: RetryReason::ReceiverNotReady,
            }
        );
    }

    #[test]
    fn unlimited_retry_code_never_decrements() {
        let policy = RetryPolicy::new(7, 7, 5).unwrap();
        let mut budget = RetryBudget::new(policy);
        for _ in 0..100 {
            assert!(matches!(
                budget.on_failure(RetryReason::Timeout, 0),
                RetryDecision::Retry { .. }
            ));
            assert!(matches!(
                budget.on_failure(RetryReason::ReceiverNotReady, 3),
                RetryDecision::Retry { .. }
            ));
        }
        assert_eq!(budget.remaining_timeout(), 7);
        assert_eq!(budget.remaining_rnr(), 7);
    }

    #[test]
    fn timer_is_deterministic() {
        let mut timer = Timer::new();
        assert!(!timer.expired(100));
        timer.arm(100, 20);
        assert_eq!(timer.remaining(110), Some(10));
        assert!(!timer.expired(119));
        assert!(timer.expired(120));
        timer.cancel();
        assert!(!timer.is_armed());
    }
}
