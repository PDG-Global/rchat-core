# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.1.x   | Yes       |
| < 1.1   | No        |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Report them by email to:

**security@pdg-global.com**

We will acknowledge receipt within 48 hours and send a more detailed response within 72 hours, saying what happens next.

### What to Include

- **Description**: a clear description of the vulnerability
- **Impact**: what an attacker could achieve
- **Reproduction**: step-by-step instructions
- **Environment**: versions, platforms and configuration affected
- **Mitigation**: any suggested fix or workaround
- **Your contact**: how to reach you for follow-up questions
- **Disclosure preference**: your preferred timeline for public disclosure

## Scope

In scope:

- The relay (`rchat-server`): connection handling, key authentication, circuits, the offline queue, rate limits and budgets, TLS and ACME handling.
- The client library (`shared/rchat-core`): X3DH v2, the Double Ratchet, sealed payloads, key authentication, relay pinning, key rotation, session persistence and recovery, and the C FFI.

Out of scope:

- The iOS app source, which is not in this repository.
- A relay you do not operate being run by someone else, and the contents of their server configuration.
- Attacks that need a compromised device or a stolen identity key (see the threat model).
- Denial of service by traffic volumes that rate limits and budgets are documented not to withstand.

## Security Response Process

1. **Acknowledgment** (within 48 hours): we confirm receipt and assign a tracking identifier.
2. **Assessment** (within 72 hours): we validate the report, rate its severity and identify the affected versions.
3. **Remediation** (timeline varies): we develop and test a fix, prepare an advisory and coordinate release timing with you.
4. **Disclosure**: we release a patched version, publish the advisory and credit you unless you prefer anonymity.

## Disclosure Policy

- We ask for reasonable time to address the issue before public disclosure.
- We aim to address critical vulnerabilities within 30 days.
- We will credit you in the advisory unless you prefer anonymity.
- We will not take legal action against researchers who follow this policy.

## Threat Model

What rChat protects, what it does not, and what a relay can see while it is running are described at <https://docs.r-chat.net/security/>.

In short: messages are end-to-end encrypted and the relay passes on ciphertext it cannot decrypt. The relay is not blind to metadata. While it is running it can see which accounts are connected and which pairs have a conversation open. It keeps no lasting record of who talks to whom and does not write identifiers to its logs.

## Security Best Practices for Operators

- Use the latest release.
- Let the relay terminate TLS 1.3 itself. A TLS-terminating proxy breaks key authentication; only TCP passthrough works.
- Keep `relay_identity.key` private and backed up. Never share it.
- Run with minimal privileges and the supplied systemd hardening.
- Keep the configuration file readable only by the service user.

## Contact

- **Security issues**: security@pdg-global.com
- **General questions**: https://github.com/PDG-Global/rchat-core/discussions
- **Website**: https://r-chat.net

---

*This security policy is subject to change. Please refer to the latest version in the repository.*
