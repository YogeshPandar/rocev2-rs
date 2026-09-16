//! Queue-pair configuration and state transitions.

use crate::Psn;

const MAX_QPN: u32 = 0x00ff_ffff;
const MIN_APPLICATION_QPN: u32 = 2;
const MAX_RETRY_COUNT: u8 = 7;
const MAX_TIMEOUT_CODE: u8 = 31;

/// Supported Reliable Connected path MTUs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum PathMtu {
    /// 256-byte path MTU.
    Mtu256 = 256,
    /// 512-byte path MTU.
    Mtu512 = 512,
    /// 1024-byte path MTU.
    Mtu1024 = 1024,
    /// 2048-byte path MTU.
    Mtu2048 = 2048,
    /// 4096-byte path MTU.
    Mtu4096 = 4096,
}

impl PathMtu {
    /// Decode a supported path MTU in bytes.
    #[must_use]
    pub const fn from_bytes(bytes: usize) -> Option<Self> {
        match bytes {
            256 => Some(Self::Mtu256),
            512 => Some(Self::Mtu512),
            1024 => Some(Self::Mtu1024),
            2048 => Some(Self::Mtu2048),
            4096 => Some(Self::Mtu4096),
            _ => None,
        }
    }

    /// Return the MTU in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Mtu256 => 256,
            Self::Mtu512 => 512,
            Self::Mtu1024 => 1024,
            Self::Mtu2048 => 2048,
            Self::Mtu4096 => 4096,
        }
    }
}

/// Reliable Connected queue-pair state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QpState {
    /// Newly created or reset.
    Reset,
    /// Locally initialized.
    Init,
    /// Ready to receive.
    Rtr,
    /// Ready to send and receive.
    Rts,
    /// Send queue draining.
    Sqd,
    /// Send queue error.
    Sqe,
    /// Fatal queue-pair error.
    Error,
}

/// Configuration required by the deterministic RC state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpConfig {
    /// Local 24-bit queue-pair number.
    pub local_qpn: u32,
    /// Remote 24-bit queue-pair number.
    pub remote_qpn: u32,
    /// Initial requester PSN.
    pub send_psn: Psn,
    /// Initial responder PSN expected from the peer.
    pub receive_psn: Psn,
    /// Negotiated path MTU.
    pub path_mtu: PathMtu,
    /// Transport retry count; `7` means unlimited at the policy layer.
    pub retry_count: u8,
    /// Receiver-not-ready retry count; `7` means unlimited.
    pub rnr_retry_count: u8,
    /// Five-bit local ACK timeout code.
    pub timeout: u8,
}

impl QpConfig {
    /// Validate field widths and reserved queue-pair numbers.
    pub const fn validate(self) -> Result<(), StateTransitionError> {
        if self.local_qpn < MIN_APPLICATION_QPN || self.local_qpn > MAX_QPN {
            return Err(StateTransitionError::InvalidLocalQpn(self.local_qpn));
        }
        if self.remote_qpn < MIN_APPLICATION_QPN || self.remote_qpn > MAX_QPN {
            return Err(StateTransitionError::InvalidRemoteQpn(self.remote_qpn));
        }
        if self.retry_count > MAX_RETRY_COUNT {
            return Err(StateTransitionError::InvalidRetryCount(self.retry_count));
        }
        if self.rnr_retry_count > MAX_RETRY_COUNT {
            return Err(StateTransitionError::InvalidRnrRetryCount(
                self.rnr_retry_count,
            ));
        }
        if self.timeout > MAX_TIMEOUT_CODE {
            return Err(StateTransitionError::InvalidTimeout(self.timeout));
        }
        Ok(())
    }
}

/// Queue-pair validation or transition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateTransitionError {
    /// The local QPN is reserved or wider than 24 bits.
    InvalidLocalQpn(u32),
    /// The remote QPN is reserved or wider than 24 bits.
    InvalidRemoteQpn(u32),
    /// The retry count is wider than the three-bit field.
    InvalidRetryCount(u8),
    /// The RNR retry count is wider than the three-bit field.
    InvalidRnrRetryCount(u8),
    /// The timeout code is wider than five bits.
    InvalidTimeout(u8),
    /// The requested state transition is not valid.
    IllegalTransition {
        /// State before the attempted transition.
        from: QpState,
        /// Requested destination state.
        to: QpState,
    },
    /// Reconfiguration was attempted while the QP was active.
    ReconfigureWhileActive(QpState),
}

/// Deterministic Reliable Connected queue-pair state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpStateMachine {
    state: QpState,
    config: QpConfig,
}

impl QpStateMachine {
    /// Construct a validated queue pair in [`QpState::Reset`].
    pub const fn new(config: QpConfig) -> Result<Self, StateTransitionError> {
        match config.validate() {
            Ok(()) => Ok(Self {
                state: QpState::Reset,
                config,
            }),
            Err(error) => Err(error),
        }
    }

    /// Return the current QP state.
    #[must_use]
    pub const fn state(self) -> QpState {
        self.state
    }

    /// Return the active configuration.
    #[must_use]
    pub const fn config(self) -> QpConfig {
        self.config
    }

    /// Return whether requester work may be emitted.
    #[must_use]
    pub const fn can_send(self) -> bool {
        matches!(self.state, QpState::Rts)
    }

    /// Return whether responder traffic may be accepted.
    #[must_use]
    pub const fn can_receive(self) -> bool {
        matches!(
            self.state,
            QpState::Rtr | QpState::Rts | QpState::Sqd | QpState::Sqe
        )
    }

    /// Replace configuration while the queue pair is reset.
    pub const fn reconfigure(&mut self, config: QpConfig) -> Result<(), StateTransitionError> {
        if !matches!(self.state, QpState::Reset) {
            return Err(StateTransitionError::ReconfigureWhileActive(self.state));
        }
        match config.validate() {
            Ok(()) => {
                self.config = config;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Move the queue pair to another state after validating the transition.
    pub const fn transition(&mut self, destination: QpState) -> Result<(), StateTransitionError> {
        if is_legal_transition(self.state, destination) {
            self.state = destination;
            Ok(())
        } else {
            Err(StateTransitionError::IllegalTransition {
                from: self.state,
                to: destination,
            })
        }
    }
}

const fn is_legal_transition(from: QpState, to: QpState) -> bool {
    if matches!(
        (from, to),
        (QpState::Reset, QpState::Reset)
            | (QpState::Init, QpState::Init)
            | (QpState::Rtr, QpState::Rtr)
            | (QpState::Rts, QpState::Rts)
            | (QpState::Sqd, QpState::Sqd)
            | (QpState::Sqe, QpState::Sqe)
            | (QpState::Error, QpState::Error)
    ) {
        return true;
    }

    matches!(
        (from, to),
        (QpState::Reset, QpState::Init | QpState::Error)
            | (
                QpState::Init,
                QpState::Reset | QpState::Rtr | QpState::Error
            )
            | (
                QpState::Rtr | QpState::Sqd | QpState::Sqe,
                QpState::Reset | QpState::Rts | QpState::Error
            )
            | (
                QpState::Rts,
                QpState::Reset | QpState::Sqd | QpState::Sqe | QpState::Error
            )
            | (QpState::Error, QpState::Reset)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn config() -> QpConfig {
        QpConfig {
            local_qpn: 2,
            remote_qpn: 3,
            send_psn: Psn::new_truncated(7),
            receive_psn: Psn::new_truncated(11),
            path_mtu: PathMtu::Mtu1024,
            retry_count: 3,
            rnr_retry_count: 3,
            timeout: 14,
        }
    }

    #[test]
    fn validates_bit_widths_and_reserved_qpns() {
        let mut invalid = config();
        invalid.local_qpn = 1;
        assert_eq!(
            QpStateMachine::new(invalid),
            Err(StateTransitionError::InvalidLocalQpn(1))
        );

        invalid = config();
        invalid.retry_count = 8;
        assert_eq!(
            QpStateMachine::new(invalid),
            Err(StateTransitionError::InvalidRetryCount(8))
        );
    }

    #[test]
    fn follows_reset_init_rtr_rts_sequence() {
        let mut qp = QpStateMachine::new(config()).unwrap();
        assert!(!qp.can_send());
        assert!(!qp.can_receive());

        qp.transition(QpState::Init).unwrap();
        qp.transition(QpState::Rtr).unwrap();
        assert!(qp.can_receive());
        qp.transition(QpState::Rts).unwrap();
        assert!(qp.can_send());
        assert!(qp.can_receive());
    }

    #[test]
    fn rejects_skipped_transition() {
        let mut qp = QpStateMachine::new(config()).unwrap();
        assert_eq!(
            qp.transition(QpState::Rts),
            Err(StateTransitionError::IllegalTransition {
                from: QpState::Reset,
                to: QpState::Rts,
            })
        );
    }

    #[test]
    fn error_state_requires_reset_before_reuse() {
        let mut qp = QpStateMachine::new(config()).unwrap();
        qp.transition(QpState::Error).unwrap();
        assert!(qp.transition(QpState::Init).is_err());
        qp.transition(QpState::Reset).unwrap();
        qp.transition(QpState::Init).unwrap();
    }
}
