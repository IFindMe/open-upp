# Security model

## Status

This is an initial checklist of security topics, not a completed threat model or security guarantee.

## Assets to protect

- Private identity keys and ephemeral session secrets.
- Peer identity integrity.
- Confidentiality and integrity of application data.
- Authorization policies and service boundaries.
- Discovery metadata and relationship graphs.
- Availability of peers and relay/discovery infrastructure.

## Threats to analyze

- Active network attackers and malicious relays.
- Impersonation, replay, downgrade, and key substitution.
- Compromised or malicious peers.
- Unauthorized service access and confused-deputy behavior.
- Malicious discovery records and stale endpoint data.
- Denial of service, resource exhaustion, and traffic amplification.
- Metadata correlation and traffic analysis.
- Supply-chain compromise of clients, libraries, and build artifacts.

## Required design properties

- Authenticate peers before granting access.
- Bind session negotiation to authenticated identities and negotiated parameters.
- Use established cryptographic protocols and vetted implementations.
- Separate long-term identity keys from ephemeral session/transport keys.
- Support key rotation, revocation, and recovery procedures.
- Apply explicit least-privilege authorization.
- Bound memory, CPU, connection counts, message sizes, and retries.
- Treat discovery data as untrusted hints until authenticated.
- Document what relays can observe and what they cannot.
- Make security-relevant events observable without logging secrets.

## Open questions

- How should users verify a first-contact identity?
- How should identities be recovered after key loss?
- What is the revocation propagation model?
- How can discovery resist Sybil attacks without a mandatory authority?
- What metadata is visible to rendezvous and relay operators?
- How are compromised devices removed from groups and delegated capabilities?
