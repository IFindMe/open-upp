# Architecture

## Purpose

This document records the current architectural direction. It is exploratory and is not a finalized specification; the frozen v1 decisions are recorded in the [Protocol v1 specification](protocol-v1.md), and the user-facing flow is documented in the [Getting started](../user-guide/getting-started.md) guide. The frozen two-peer v1 slice — local identity primitives and the wire protocol itself — is implemented and verified and remains the shipped baseline.

**Tailcat-core release (implemented and verified):** [ADR-002](adr-002-tailcat-core.md) selects **Tailcat as the default/primary connectivity core** and has landed; the v2 two-peer flow over Tailcat is implemented and verified. UPP identity, pairwise verification, explicit scoped authorization, and the no-TOFU policy from v1 are the trust core and are unchanged.

## Core separation

Open UPP separates five concerns:

1. **Identity:** Stable cryptographic identity and key lifecycle.
2. **Discovery:** Finding candidate peers and current connection information.
3. **Authorization:** Deciding which authenticated peer may perform which action.
4. **Session:** Negotiating, establishing, monitoring, and closing authenticated sessions.
5. **Transport:** Moving encrypted bytes through direct paths or relays.

Applications consume a stable API and should not need to understand NAT traversal or transport-specific addresses.

## Identity is not location

A peer identity must remain stable when its IP address, network interface, relay, or transport changes. Discovery returns candidate connection information associated with an identity; it does not redefine that identity.

## Identity is not authorization

Possession of a peer's public key proves control of a corresponding private key during an authenticated exchange. It does not grant permission to access arbitrary services. Authorization for v1 is an explicit, scoped local grant (deny by default, no allow-from-fingerprint path), checked against strict out-of-band pairwise safety-number verification, and revocation is local only — no propagation. Authorization must remain auditable.

## Transport abstraction

The frozen, shipped v1 two-peer slice uses an untrusted, out-of-band endpoint hint file and TCP; protection terminates at the UPP peers, not at the socket or a relay. That stays the historical baseline. The Tailcat-core release ([ADR-002](adr-002-tailcat-core.md), landed) reverses the v1 transport non-goal and makes **Tailcat the default/primary connectivity core** — implemented and verified. TCP is retained only as an explicit local-test fallback, never an automatic downgrade.

A Tailcat `tc...` address is a **secret bearer routing hint**: possession yields reachability only. It is never UPP identity, proof-of-possession state, a pin, or a grant subject, and no allow-from-address path exists. UPP identity, pairwise verification, scoped authorization, session establishment, wire records, fingerprints, and the application API are inherited from v1 unchanged; the chain is substrate → identity → verification → authority, not a merger.

The adapter boundary must prevent Tailcat-specific APIs, identifiers, capability addresses, and wire formats from leaking into the UPP protocol specification or application API. Tailcat's APIs and wire formats may be unstable and are not UPP's public protocol; a version swap must not change UPP semantics. Other peer-to-peer transports, relays, and conventional network paths remain research/comparison options, not a competing default.

## Discovery: v1 frozen, broader models remain research

For the shipped v1 slice, discovery is an untrusted out-of-band endpoint hint (a local file) resolved to a TCP address; a hint is never identity or authorization evidence. In the Tailcat-core release ([ADR-002](adr-002-tailcat-core.md), landed, implemented and verified), the same 0600 hint carries an opaque `tc...` routing capability plus a service port and a closed transport discriminator; it is still untrusted routing data, never identity or authority. Other models — local network discovery, federated rendezvous services, distributed lookup, and cached peer hints from multiple providers — remain research options.

A single global directory is not assumed. Discovery must account for privacy leakage, Sybil resistance, availability, abuse, and stale records.

## Application interface

The initial interface should prioritize authenticated byte streams and service access. UDP datagrams and TUN-based IP networking should be considered only after session semantics, authorization, and transport behavior are validated.

## Design notes

- [ADR-002: Tailcat as connectivity core](adr-002-tailcat-core.md) — reversal of the v1 transport non-goal; landed in the Tailcat-core release (implemented and verified).
- [Peer identity and key lifecycle](identity-and-key-lifecycle.md) — identity model, fingerprint rules, rotation, revocation, and testable invariants (Issue #2). Its choices remain proposals unless explicitly marked otherwise; the v1 encoding, transport, verification, and grant decisions are frozen in the [Protocol v1 specification](protocol-v1.md).
- [Protocol v1 specification](protocol-v1.md) — frozen architecture, canonical encoding, and wire format.
- [Getting started](../user-guide/getting-started.md) — two-peer user guide.
