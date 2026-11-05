# Architecture

## Purpose

This document records the current architectural direction. It is exploratory and is not a finalized specification.

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

Possession of a peer's public key proves control of a corresponding private key during an authenticated exchange. It does not grant permission to access arbitrary services. Authorization must be explicit, scoped, revocable, and auditable.

## Transport abstraction

The first research target is a Tailcat-backed transport adapter. The adapter boundary must prevent Tailcat-specific APIs, identifiers, and wire formats from leaking into the UPP protocol specification or application API.

Tailcat's APIs and wire formats may be unstable. No dependency on them is finalized. Other peer-to-peer transports, relays, and conventional network paths may be evaluated.

## Discovery is an open design question

Potential models include manual out-of-band exchange, local network discovery, federated rendezvous services, distributed lookup, and cached peer hints from multiple providers.

A single global directory is not assumed. Discovery must account for privacy leakage, Sybil resistance, availability, abuse, and stale records.

## Application interface

The initial interface should prioritize authenticated byte streams and service access. UDP datagrams and TUN-based IP networking should be considered only after session semantics, authorization, and transport behavior are validated.
