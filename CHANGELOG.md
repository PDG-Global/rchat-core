# Changelog

## 2.1.0 (2026-10-31)

Voice and video calls through your own relay. Calls need a 2.1.0 relay and an app with calls (Android today); messaging stays compatible with 2.0.0 apps and relays.

- Voice calls: end-to-end encrypted with keys derived inside the conversation's session (HKDF) and ChaCha20-Poly1305 media frames. Opus voice (libopus through `opus-codec`, behind the core's `calls-codec` feature): 48 kHz mono, 16 or 24 kbps CBR, in-band FEC. Each phone opens two call connections to the relay, on the same HTTPS port as messages, and sends every frame on both; an adaptive playout buffer conceals loss.
- No STUN, TURN or other call servers: the relay passes on frames it can't read. It can see that a call is happening, roughly when, for how long and how much data.
- Video calls: signalling in a new `0x0E` plaintext (Caps, Request, Accept, Decline, Camera), separate video keys, stream frames `0x81` (video) and `0x82` (control) with a 1024-frame replay window, fragmenting and reassembly. A quality ladder from 240p to 1080p with pause and resume, health notes and an unstable-connection notice. Video only starts from a local action (Accept, or tapping the camera). Video data volume changes with movement, so the relay can tell that a call has video and roughly when there is movement on camera.
- Relay protocol: media frame prefix `0x05`; control messages `MediaGrant`, `MediaJoin`, `MediaJoined`, `MediaPeerGone` (19-22); capabilities `calls-v1` and `video-v1`. A media token is usable only once both members of a conversation grant it; at most one per circuit and two per chat connection; it expires 60 s after the grants if nobody joins, and 30 s after its last call connection leaves.
- Relay: call lanes 0-1 carry audio (64 kbps each) and 2-3 video (about 4 Mbps, a 256 KiB queue, video waiting over 500 ms is dropped). Call connections keep little unsent data (`TCP_NOTSENT_LOWAT` 16 KiB on Linux, a 32 KiB send buffer on FreeBSD and macOS). New call and video metrics.
- Relay: pings only connections that have gone quiet (above the app's background keepalive, 30 s to answer); holds relayed records until the app's TCP acknowledgement shows they arrived, with a budget of their own, and saves them with the offline queue on shutdown; closes a member's stale connections when it publishes again.
- Core: `rchat_call_*` and `rchat_call_video_*` C functions with JNI wrappers and error codes 31-36; `rchat_set_background_keepalive`; `rchat_verify_ed25519`, a stateless Ed25519 check; a stale identity circuit closes at once, also during a call; pinning a requester answers its knock.
- Building: minimum Rust 1.88. The core's `calls-codec` feature needs CMake; the relay never builds it.

## 2.0.0 (2026-10-16)

Protocol v3, a hard cutover: update the relay and the app together; v2 apps are refused.

- Post-quantum encryption: every session and every message request combines X25519 with ML-KEM-768 (FIPS 203). Each ask signs its own ephemeral keys. Authentication stays Ed25519 and P-256.
- Blinded pairing: after a first conversation, two phones reconnect by a token that changes every 10 minutes and at every reconnect. While a conversation is open the relay's memory still links its two members; once both have been gone about 10 minutes nothing it keeps names the pair, waiting blind asks name no one, and no token or circuit id links one connection period to the next. Identity asks remain for first contact, lost sessions, key rotation and a once-a-day fallback (at most one forced per pair per 24 hours). A phone whose clock is more than 5 minutes off the relay's can't connect at all, so any two connected phones are close enough in time to pair blind.
- Steady traffic (opt-in, while the app is open): one same-size packet per slot (0.5, 1 or 2 s) to a random open conversation, so timing reveals less. Fully effective only when both people use it.
- Relay invites: `rchat-server --print-invite` prints an `rchat://relay` link and QR code; the app's Scan, Paste and Share flows set the relay address and pin its identity in one step. New `[server] public_port` and `--public-port`.
- Post-quantum TLS key exchange: X25519MLKEM768 (hybrid ML-KEM-768 + X25519) between app and relay, full and resumed handshakes; X25519 (relay also P-256, P-384) as the fallback. Certificates, relay identity and connection proofs stay classical.
- TLS 1.3 resumption tickets (`[server.tls] session_tickets`, default on; memory-only keys rotated every 6 hours; no 0-RTT). Every connection still proves its identity over its own TLS exporter.
- Per-relay decoy sites: the built-in page is seeded from the relay's secret identity key and host name; `--render-decoy` writes the same site as a static site and now needs `--config` and must run as the service user; new `[server.decoy] host`. Every relay with a host name gets a new decoy design once, on upgrade. Range requests follow nginx 1.24 (multi-range 206 `multipart/byteranges`; `bytes=abc` and `bytes=5-3` give 416; no `Accept-Ranges` on a 206).
- Media: photos re-encoded without metadata by default; "Send as file" for originals and any document (up to 4 MiB − 128 KiB); Save to Photos (add-only) and Save to Files; higher-quality voice messages.
- Disappearing messages: per-conversation timer (5 min to 4 weeks), synced inside the session.
- Alerts while the app is closed: local notifications from background checks, no notification server; name only by default.
- Contact codes are v3 (about 1.7 KB, with the ML-KEM key); older codes are refused. Knocks are 5120 bytes.
- Relay: blind asks have their own caps, `max_pending_blind_per_connection` (default 1024) and `max_pending_blind_per_source` (default 4096); `max_pending_per_connection` and `max_pending_per_source` count identity asks only. Busy relays should raise `max_pending_circuit_targets` (default 10,000; blind asks take about 4 per offline contact per online user, about 2.8 KB each).
- Relay: `offline_queue.ttl_secs` is capped at 72 hours; steady-size entries capped at half a recipient's queue; new blinded-pairing metrics; unknown frame types close the connection.
- Known limitation: re-pairing can take up to about 3–4 minutes when the first asker drops before the other side's first reply.

## 1.1.0 (2026-10-11, first public release)

- Protocol v2: signed key bundles, connection proofs bound to the TLS session, mutual-intent circuits, sealed relay payloads, padding.
- Sessions persist across app restarts (sealed, excluded from backups); a phone that loses its sessions has undelivered messages resent automatically, gated by the contact's device key (hardware-backed where the phone has secure hardware), or offered for a manual resend.
- Delivery states: Sending, Sent, Delivered, Read, Not delivered, Resent.
- Relay: hands packets to online members that have not resumed yet; re-queues frames a dropped connection never finished receiving; per-source fair shares and memory budgets; PROXY protocol v2; built-in ACME.
- Relay binaries for macOS (notarised), Linux (gnu and static) and FreeBSD x86_64, with SHA-256 checksums.
