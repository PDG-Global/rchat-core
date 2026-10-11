//! Delivery and recovery events reported to the app (spec §18.9, D40).
//! No event carries secret material.

/// One delivery or recovery event. `peer` is the contact's identity
/// (lowercase hex) and `message_id` the message id (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum StatusEvent {
    DecryptFailed {
        peer: String,
        message_id: String,
        detail: u8,
    },
    PeerUndelivered {
        peer: String,
        message_id: String,
        reason: u8,
    },
    PeerSessionReset {
        peer: String,
    },
    SessionReplaced {
        peer: String,
    },
    SendNotAccepted {
        peer: String,
        message_id: String,
    },
    AckUnknown {
        peer: String,
        message_id: String,
        attempts: u8,
    },
    QueuedSendLost {
        peer: String,
        message_id: String,
    },
    StatePersistFailed {
        peer: Option<String>,
    },
    StateRestoreFailed {
        reason: u8,
    },
    ResendEligible {
        peer: String,
        message_id: String,
    },
}

impl StatusEvent {
    pub fn code(&self) -> i32 {
        self.parts().0
    }

    /// (kind, peer or "", message id or "", detail), as on the C callback.
    pub fn parts(&self) -> (i32, String, String, i32) {
        use StatusEvent::*;
        match self {
            DecryptFailed {
                peer,
                message_id,
                detail,
            } => (1, peer.clone(), message_id.clone(), i32::from(*detail)),
            PeerUndelivered {
                peer,
                message_id,
                reason,
            } => (2, peer.clone(), message_id.clone(), i32::from(*reason)),
            PeerSessionReset { peer } => (3, peer.clone(), String::new(), 0),
            SessionReplaced { peer } => (4, peer.clone(), String::new(), 0),
            SendNotAccepted { peer, message_id } => (5, peer.clone(), message_id.clone(), 0),
            AckUnknown {
                peer,
                message_id,
                attempts,
            } => (6, peer.clone(), message_id.clone(), i32::from(*attempts)),
            QueuedSendLost { peer, message_id } => (7, peer.clone(), message_id.clone(), 0),
            StatePersistFailed { peer } => (8, peer.clone().unwrap_or_default(), String::new(), 0),
            StateRestoreFailed { reason } => (9, String::new(), String::new(), i32::from(*reason)),
            ResendEligible { peer, message_id } => (10, peer.clone(), message_id.clone(), 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_spec_18_9() {
        let p = || "aa".repeat(32);
        assert_eq!(
            StatusEvent::DecryptFailed {
                peer: p(),
                message_id: "00".repeat(16),
                detail: 2
            }
            .parts()
            .3,
            2
        );
        assert_eq!(
            StatusEvent::StateRestoreFailed { reason: 4 }.parts(),
            (9, String::new(), String::new(), 4)
        );
        assert_eq!(StatusEvent::StatePersistFailed { peer: None }.code(), 8);
        assert_eq!(
            StatusEvent::QueuedSendLost {
                peer: p(),
                message_id: "11".repeat(16)
            }
            .code(),
            7
        );
        assert_eq!(
            StatusEvent::ResendEligible {
                peer: p(),
                message_id: "22".repeat(16)
            }
            .code(),
            10
        );
    }

    /// Events reach the app's callbacks as given.
    #[test]
    fn emit_status_reaches_the_app_callbacks() {
        let (mut inner, _rx) = crate::test_support::inner_with_identity(1);
        let log = crate::test_support::install_event_log(&mut inner);
        let ev = StatusEvent::SessionReplaced {
            peer: "bb".repeat(32),
        };
        inner.emit_status(ev.clone());
        assert_eq!(
            *log.lock().unwrap(),
            vec![crate::test_support::Ev::Status(ev)]
        );
    }
}
