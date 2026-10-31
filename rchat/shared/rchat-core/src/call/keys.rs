//! Media keys (spec §4): HKDF-SHA256 with ikm = caller_rand ‖ callee_rand
//! and salt = call_id. Both phones contribute randomness; the keys live
//! only for the call and are wiped when dropped.

use super::CallId;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const INFO_CALLER_TO_CALLEE: &[u8] = b"rchat-call-v1 key caller->callee";
pub const INFO_CALLEE_TO_CALLER: &[u8] = b"rchat-call-v1 key callee->caller";
pub const INFO_RELAY_TOKEN: &[u8] = b"rchat-call-v1 relay-token";
pub const INFO_VIDEO_CALLER_TO_CALLEE: &[u8] = b"rchat-call-v1 video caller->callee";
pub const INFO_VIDEO_CALLEE_TO_CALLER: &[u8] = b"rchat-call-v1 video callee->caller";
pub const INFO_VIDEO_CTL_CALLER_TO_CALLEE: &[u8] = b"rchat-call-v1 video-control caller->callee";
pub const INFO_VIDEO_CTL_CALLEE_TO_CALLER: &[u8] = b"rchat-call-v1 video-control callee->caller";

/// This phone's two directions and the relay token. Never logged.
pub struct CallKeys {
    pub send: Zeroizing<[u8; 32]>,
    pub recv: Zeroizing<[u8; 32]>,
    pub relay_token: Zeroizing<[u8; 32]>,
}

/// This phone's video keys: media and control, each way. Held by the
/// call until video starts; wiped when dropped. Never logged.
pub struct VideoKeys {
    pub send: Zeroizing<[u8; 32]>,
    pub recv: Zeroizing<[u8; 32]>,
    pub ctl_send: Zeroizing<[u8; 32]>,
    pub ctl_recv: Zeroizing<[u8; 32]>,
}

pub fn derive(
    call_id: &CallId,
    caller_rand: &[u8; 32],
    callee_rand: &[u8; 32],
    we_are_caller: bool,
) -> (CallKeys, VideoKeys) {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(caller_rand);
    ikm[32..].copy_from_slice(callee_rand);
    let hk = Hkdf::<Sha256>::new(Some(&call_id.0), &ikm[..]);
    let expand = |info: &[u8]| {
        let mut out = Zeroizing::new([0u8; 32]);
        // 32 bytes is always a valid HKDF-SHA256 output length.
        hk.expand(info, &mut out[..]).expect("32-byte HKDF output");
        out
    };
    let (c2e, e2c) = (expand(INFO_CALLER_TO_CALLEE), expand(INFO_CALLEE_TO_CALLER));
    let relay_token = expand(INFO_RELAY_TOKEN);
    let (send, recv) = if we_are_caller {
        (c2e, e2c)
    } else {
        (e2c, c2e)
    };
    let (v_c2e, v_e2c) = (
        expand(INFO_VIDEO_CALLER_TO_CALLEE),
        expand(INFO_VIDEO_CALLEE_TO_CALLER),
    );
    let (c_c2e, c_e2c) = (
        expand(INFO_VIDEO_CTL_CALLER_TO_CALLEE),
        expand(INFO_VIDEO_CTL_CALLEE_TO_CALLER),
    );
    let video = if we_are_caller {
        VideoKeys {
            send: v_c2e,
            recv: v_e2c,
            ctl_send: c_c2e,
            ctl_recv: c_e2c,
        }
    } else {
        VideoKeys {
            send: v_e2c,
            recv: v_c2e,
            ctl_send: c_e2c,
            ctl_recv: c_c2e,
        }
    };
    (
        CallKeys {
            send,
            recv,
            relay_token,
        },
        video,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::CallId;

    fn id() -> CallId {
        CallId(core::array::from_fn(|i| i as u8 + 1)) // 01..10
    }

    /// Spec §4 labels against fixed vectors (computed independently with
    /// Python's hmac/hashlib HKDF-SHA256 over the same inputs).
    #[test]
    fn keys_match_the_fixed_vectors() {
        let k = derive(&id(), &[0x11; 32], &[0x22; 32], true).0;
        assert_eq!(
            hex::encode(*k.send),
            "7d9644d01b45f7393adfa80ed25254d20dabb3e4ac544c6132efe15226f858ca"
        );
        assert_eq!(
            hex::encode(*k.recv),
            "3e94af2dce7fac960e2a778e7d3d94dcba89ef8a7136220a15809dcc249b2a5b"
        );
        assert_eq!(
            hex::encode(*k.relay_token),
            "99879edb81bd5cbb2209470db5b4ffff48859c966c9b079dab5a13193c71bdcd"
        );
        assert_eq!(INFO_CALLER_TO_CALLEE, b"rchat-call-v1 key caller->callee");
        assert_eq!(INFO_CALLEE_TO_CALLER, b"rchat-call-v1 key callee->caller");
        assert_eq!(INFO_RELAY_TOKEN, b"rchat-call-v1 relay-token");
    }

    #[test]
    fn caller_and_callee_mirror_each_other_and_share_the_token() {
        let caller = derive(&id(), &[0x11; 32], &[0x22; 32], true).0;
        let callee = derive(&id(), &[0x11; 32], &[0x22; 32], false).0;
        assert_eq!(*caller.send, *callee.recv);
        assert_eq!(*caller.recv, *callee.send);
        assert_eq!(*caller.relay_token, *callee.relay_token);
        let other = derive(&CallId([0xFF; 16]), &[0x11; 32], &[0x22; 32], true).0;
        assert_ne!(*other.send, *caller.send, "the call id salts every key");
    }

    #[test]
    fn video_keys_match_the_fixed_vectors() {
        let (k, kv) = derive(&id(), &[0x11; 32], &[0x22; 32], true);
        assert_eq!(
            hex::encode(*kv.send),
            "06288dfa655a90a01a7edb108933906e6080f3f4f6f3caccbdf95d2165720f46"
        );
        assert_eq!(
            hex::encode(*kv.recv),
            "f85cac33231724ad9d76dd106c630d5e00ed29c3a34a9c10da8f6acc7b4ebd42"
        );
        assert_eq!(
            hex::encode(*kv.ctl_send),
            "46177df5344e7e96e48885e60149875f33aa1a1858d33aa5eced6c8964530659"
        );
        assert_eq!(
            hex::encode(*kv.ctl_recv),
            "15f18a92eef33aa79ecb9a9c74106e4f6ee336bbda4862332836c7302ed6d7de"
        );
        let (_, ev) = derive(&id(), &[0x11; 32], &[0x22; 32], false);
        assert_eq!(*ev.send, *kv.recv);
        assert_eq!(*ev.recv, *kv.send);
        assert_eq!(*ev.ctl_send, *kv.ctl_recv);
        assert_eq!(*ev.ctl_recv, *kv.ctl_send);
        assert!([&*k.send, &*k.recv, &*k.relay_token]
            .iter()
            .all(|a| **a != *kv.send
                && **a != *kv.recv
                && **a != *kv.ctl_send
                && **a != *kv.ctl_recv));
        assert_eq!(
            INFO_VIDEO_CALLER_TO_CALLEE,
            b"rchat-call-v1 video caller->callee"
        );
        assert_eq!(
            INFO_VIDEO_CALLEE_TO_CALLER,
            b"rchat-call-v1 video callee->caller"
        );
        assert_eq!(
            INFO_VIDEO_CTL_CALLER_TO_CALLEE,
            b"rchat-call-v1 video-control caller->callee"
        );
        assert_eq!(
            INFO_VIDEO_CTL_CALLEE_TO_CALLER,
            b"rchat-call-v1 video-control callee->caller"
        );
    }
}
