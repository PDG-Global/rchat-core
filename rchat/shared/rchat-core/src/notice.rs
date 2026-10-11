//! Session notice, inner type 0x06 (spec §18.6 D37), with the D45 trailer.
//!
//! `0x06 || flags || reason || count || count × id(16) || sig_len(0 | 64) || sig`.
//! The signature is the sender's device key's over `tbs` (D45).

/// Inner ratchet plaintext type of a session notice.
pub const NOTICE_TYPE: u8 = 0x06;
/// Flag bit 0: the notice's sender held no session with the recipient
/// (current, retired or restored) when this session was made.
pub const FLAG_NO_PRIOR_SESSION: u8 = 0x01;
/// No ids (count 0).
pub const REASON_NONE: u8 = 0;
/// The ids decrypted under neither session.
pub const REASON_UNDECRYPTABLE: u8 = 1;
/// The ids were decrypted but lost before the app stored them (§18.7).
pub const REASON_LOST_BEFORE_STORED: u8 = 2;
/// Local only, never on the wire: unconfirmed when the peer's session was
/// reset (`PeerUndelivered` reason 3).
pub const REASON_UNCONFIRMED_AT_RESET: u8 = 3;
/// Ids per notice.
pub const MAX_IDS: usize = 32;
/// Signature length in the trailer when signed (raw ECDSA P-256 r||s).
const SIG_LEN: u8 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub flags: u8,
    pub reason: u8,
    pub ids: Vec<[u8; 16]>,
    pub sig: Option<[u8; 64]>,
}

/// The notice's plaintext, or None when it breaks a rule: a reserved flag
/// bit, an unknown or local-only reason, more than `MAX_IDS` ids, or ids
/// with reason 0 (and none with any other reason).
pub fn encode(n: &Notice) -> Option<Vec<u8>> {
    let valid_reason = matches!(
        n.reason,
        REASON_NONE | REASON_UNDECRYPTABLE | REASON_LOST_BEFORE_STORED
    );
    if n.flags & !FLAG_NO_PRIOR_SESSION != 0
        || !valid_reason
        || n.ids.len() > MAX_IDS
        || ((n.reason == REASON_NONE) != n.ids.is_empty())
    {
        return None;
    }
    let mut out = Vec::with_capacity(4 + 16 * n.ids.len() + 1 + 64);
    out.extend_from_slice(&[NOTICE_TYPE, n.flags, n.reason, n.ids.len() as u8]);
    for id in &n.ids {
        out.extend_from_slice(id);
    }
    match &n.sig {
        Some(sig) => {
            out.push(SIG_LEN);
            out.extend_from_slice(sig);
        }
        None => out.push(0),
    }
    Some(out)
}

/// What the device key signs (D45): `NOTICE_SIG_DOMAIN || sender_ik ||
/// recipient_ik || session_binding || flags || reason || count || ids`.
/// The trailer (`sig_len || sig`) is never part of it. None for more than
/// `MAX_IDS` ids (no such notice is ever encoded, signed or verified).
pub fn tbs(
    sender_ik: &[u8; 32],
    recipient_ik: &[u8; 32],
    binding: &[u8; 32],
    n: &Notice,
) -> Option<Vec<u8>> {
    let count = u8::try_from(n.ids.len())
        .ok()
        .filter(|c| usize::from(*c) <= MAX_IDS)?;
    let domain = crate::device_key::NOTICE_SIG_DOMAIN;
    let mut out = Vec::with_capacity(domain.len() + 96 + 3 + 16 * n.ids.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(sender_ik);
    out.extend_from_slice(recipient_ik);
    out.extend_from_slice(binding);
    out.extend_from_slice(&[n.flags, n.reason, count]);
    for id in &n.ids {
        out.extend_from_slice(id);
    }
    Some(out)
}

/// Parse a notice plaintext; None unless it is exactly what `encode` makes.
pub fn decode(pt: &[u8]) -> Option<Notice> {
    let [ty, flags, reason, count, rest @ ..] = pt else {
        return None;
    };
    let ids_len = 16 * usize::from(*count);
    if *ty != NOTICE_TYPE || rest.len() < ids_len + 1 {
        return None;
    }
    let (ids, trailer) = rest.split_at(ids_len);
    let sig = match trailer {
        [0] => None,
        [SIG_LEN, sig @ ..] if sig.len() == usize::from(SIG_LEN) => Some(sig.try_into().ok()?),
        _ => return None,
    };
    let n = Notice {
        flags: *flags,
        reason: *reason,
        ids: ids
            .chunks_exact(16)
            .map(|c| c.try_into().expect("chunks of 16"))
            .collect(),
        sig,
    };
    encode(&n).map(|_| n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(flags: u8, reason: u8, ids: Vec<[u8; 16]>) -> Notice {
        Notice {
            flags,
            reason,
            ids,
            sig: None,
        }
    }

    /// RV1: codec bounds and the trailer.
    #[test]
    fn rv1_notice_codec() {
        let x = n(
            FLAG_NO_PRIOR_SESSION,
            REASON_UNDECRYPTABLE,
            vec![[1; 16], [2; 16]],
        );
        let pt = encode(&x).unwrap();
        assert_eq!(&pt[..4], &[NOTICE_TYPE, 1, 1, 2]);
        assert_eq!(*pt.last().unwrap(), 0, "sig_len 0");
        assert_eq!(decode(&pt), Some(x.clone()));
        let signed = Notice {
            sig: Some([7; 64]),
            ..x
        };
        assert_eq!(decode(&encode(&signed).unwrap()), Some(signed));
        assert!(encode(&n(0, 1, vec![[0; 16]; 33])).is_none());
        assert!(encode(&n(0x02, 0, vec![])).is_none(), "reserved bit");
        assert!(
            encode(&n(0, 0, vec![[0; 16]])).is_none(),
            "reason 0 with ids"
        );
        assert!(
            encode(&n(0, REASON_UNCONFIRMED_AT_RESET, vec![[0; 16]])).is_none(),
            "local only"
        );
        assert!(decode(&pt[..pt.len() - 1]).is_none(), "trailer missing");
        let mut bad = pt.clone();
        *bad.last_mut().unwrap() = 63;
        assert!(decode(&bad).is_none(), "sig_len must be 0 or 64");
        assert!(
            encode(&n(0, 0, vec![])).is_some(),
            "the empty notice is legal"
        );
    }

    /// The signed bytes: exact layout, every field covered, trailer excluded.
    #[test]
    fn tbs_layout_covers_every_field_but_the_trailer() {
        let x = Notice {
            flags: FLAG_NO_PRIOR_SESSION,
            reason: REASON_UNDECRYPTABLE,
            ids: vec![[1; 16], [2; 16]],
            sig: None,
        };
        let t = tbs(&[0xA; 32], &[0xB; 32], &[0xC; 32], &x).unwrap();
        let mut expected = b"rchat/session-notice/v1\0".to_vec();
        expected.extend_from_slice(&[0xA; 32]);
        expected.extend_from_slice(&[0xB; 32]);
        expected.extend_from_slice(&[0xC; 32]);
        expected.extend_from_slice(&[1, 1, 2]);
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[2; 16]);
        assert_eq!(t, expected);
        assert_eq!(t.len(), 24 + 96 + 3 + 32);
        let signed = Notice {
            sig: Some([7; 64]),
            ..x.clone()
        };
        assert_eq!(
            tbs(&[0xA; 32], &[0xB; 32], &[0xC; 32], &signed),
            Some(t.clone())
        );
        // Swapping the identities (a reflected notice) or the binding changes it.
        assert_ne!(tbs(&[0xB; 32], &[0xA; 32], &[0xC; 32], &x), Some(t.clone()));
        assert_ne!(tbs(&[0xA; 32], &[0xB; 32], &[0xD; 32], &x), Some(t.clone()));
        for changed in [
            Notice {
                flags: 0,
                ..x.clone()
            },
            Notice {
                reason: REASON_LOST_BEFORE_STORED,
                ..x.clone()
            },
            Notice {
                ids: vec![[1; 16]],
                ..x.clone()
            },
            Notice {
                ids: vec![[2; 16], [1; 16]],
                ..x.clone()
            },
        ] {
            assert_ne!(
                tbs(&[0xA; 32], &[0xB; 32], &[0xC; 32], &changed),
                Some(t.clone())
            );
        }
        // More than MAX_IDS ids: refused, never clamped.
        let max = Notice {
            ids: vec![[3; 16]; MAX_IDS],
            ..x.clone()
        };
        assert!(tbs(&[0xA; 32], &[0xB; 32], &[0xC; 32], &max).is_some());
        for len in [MAX_IDS + 1, 256, 300] {
            let over = Notice {
                ids: vec![[3; 16]; len],
                ..x.clone()
            };
            assert_eq!(tbs(&[0xA; 32], &[0xB; 32], &[0xC; 32], &over), None);
        }
    }

    /// Hostile plaintexts: every one is refused.
    #[test]
    fn hostile_notices_are_refused() {
        let with = |count: u8, id_bytes: usize, trailer: &[u8]| {
            let mut pt = vec![NOTICE_TYPE, 0, REASON_UNDECRYPTABLE, count];
            pt.resize(pt.len() + id_bytes, 0xAB);
            pt.extend_from_slice(trailer);
            pt
        };
        assert!(decode(&with(33, 33 * 16, &[0])).is_none(), "count > 32");
        assert!(
            decode(&with(2, 16, &[0])).is_none(),
            "fewer ids than the count"
        );
        assert!(
            decode(&with(1, 32, &[0])).is_none(),
            "more ids than the count"
        );
        assert!(
            decode(&with(1, 16, &[0, 0])).is_none(),
            "a byte after sig_len 0"
        );
        let signed = encode(&Notice {
            flags: 0,
            reason: REASON_UNDECRYPTABLE,
            ids: vec![[1; 16]],
            sig: Some([9; 64]),
        })
        .unwrap();
        assert!(decode(&signed).is_some());
        let mut trailing = signed.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_none(), "a byte after the signature");
        assert!(
            decode(&signed[..signed.len() - 1]).is_none(),
            "short signature"
        );
        assert!(decode(&[NOTICE_TYPE, 0, 0]).is_none(), "truncated header");
        let mut wrong_type = with(1, 16, &[0]);
        wrong_type[0] = 0x03;
        assert!(decode(&wrong_type).is_none(), "not a notice");
    }
}
