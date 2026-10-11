# Changelog

## 1.1.0 (2026-10-11, first public release)

- Protocol v2: signed key bundles, connection proofs bound to the TLS session, mutual-intent circuits, sealed relay payloads, padding.
- Sessions persist across app restarts (sealed, excluded from backups); a phone that loses its sessions has undelivered messages resent automatically, gated by the contact's device key (hardware-backed where the phone has secure hardware), or offered for a manual resend.
- Delivery states: Sending, Sent, Delivered, Read, Not delivered, Resent.
- Relay: hands packets to online members that have not resumed yet; re-queues frames a dropped connection never finished receiving; per-source fair shares and memory budgets; PROXY protocol v2; built-in ACME.
- Relay binaries for macOS (notarised), Linux (gnu and static) and FreeBSD x86_64, with SHA-256 checksums.
