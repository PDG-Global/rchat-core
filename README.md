# rChat

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

rChat is a self-hosted end-to-end encrypted messenger. Messages are encrypted on your phone and decrypted only by the person you send them to. The relay in between passes on ciphertext it cannot read, and keeps no lasting record of who talks to whom.

This repository contains the relay (`rchat-server`) and the client library (`rchat-core`: cryptography, protocol, transport and the C FFI). The native apps are maintained separately.

## Architecture

- **X3DH v2** key agreement, where both sides contribute ephemeral keys
- **Double Ratchet** for continuous key rotation and forward secrecy
- **XChaCha20-Poly1305** authenticated encryption
- **Ed25519 / X25519** for signatures and key agreement
- **Signed key bundles and TLS-bound connection proofs**, so the relay cannot swap in keys of its own
- **Mutual-intent circuits**: a conversation opens only when both sides ask for it
- **Sealed, padded relay payloads**
- **Persistent sealed sessions** with guarded recovery, gated by a P-256 device key (hardware-backed where the phone has secure hardware)
- **A relay that terminates TLS 1.3 itself**, over a single WebSocket connection

## What the relay sees

Messages are end-to-end encrypted. The relay passes on ciphertext it cannot decrypt.

It is not blind to metadata. While it is running, the relay can see which accounts are connected, when, and from which IP address, and which two accounts have a conversation open, and, for up to ten minutes, which account is trying to reach which. It does not write this to its logs. It keeps no lasting record of who talks to whom: what it holds in memory to route a conversation is discarded within ten minutes of both people disconnecting; a request waiting for someone who is offline is held in memory until it is delivered, for at most 72 hours, and keeps a keyed pair tag for that time. Messages for someone who is offline are held in memory for up to 72 hours at the default setting, and deleted once delivered.

The full threat model is at [docs.r-chat.net/security](https://docs.r-chat.net/security/).

## Repository Structure

```
rchat/
  Cargo.toml         Relay package and binaries
  Cargo.lock
  src/               rchat-server: the relay (and its test clients)
  shared/rchat-core/ Client library: crypto, protocol, transport, C FFI
```

## Building

Requires Rust 1.75+. The client library builds BoringSSL, so it also needs cmake and a C toolchain.

```bash
cd rchat

# Build the relay
cargo build --release --bin rchat-server

# Run the relay tests
cargo test

# Build and test the client library
cd shared/rchat-core
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

### Cross-compilation

Install [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and [zig](https://ziglang.org/):

```bash
# macOS (Apple Silicon)
cargo zigbuild --release --target aarch64-apple-darwin --bin rchat-server

# macOS (Intel)
cargo zigbuild --release --target x86_64-apple-darwin --bin rchat-server

# Linux x86_64
cargo zigbuild --release --target x86_64-unknown-linux-gnu --bin rchat-server

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-gnu --bin rchat-server

# Linux ARMv7
cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --bin rchat-server

# Linux RISC-V
cargo zigbuild --release --target riscv64gc-unknown-linux-gnu --bin rchat-server

# Linux musl (static)
cargo zigbuild --release --target x86_64-unknown-linux-musl --bin rchat-server
cargo zigbuild --release --target aarch64-unknown-linux-musl --bin rchat-server

# FreeBSD x86_64
cargo zigbuild --release --target x86_64-unknown-freebsd --bin rchat-server
```

## Running the relay

Create the relay identity key once, then start the relay:

```bash
rchat-server --config /etc/rchat/server.toml --init-relay-identity
rchat-server --config /etc/rchat/server.toml
```

## Documentation and downloads

- Documentation: [docs.r-chat.net](https://docs.r-chat.net)
- Relay binaries with SHA-256 checksums: [r-chat.net/downloads](https://r-chat.net/downloads)

## Licensing

rChat is dual-licensed:

- **AGPL-3.0** for open-source use
- **Commercial license** for proprietary use, service providers, or when AGPL obligations cannot be met

See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

Commercial licensing: license@pdg-global.com

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately to security@pdg-global.com. See [SECURITY.md](SECURITY.md).

## About

PDG Global Limited (Hong Kong)

- Website: https://r-chat.net
- GitHub: https://github.com/PDG-Global/rchat-core
