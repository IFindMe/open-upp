# Roadmap

This roadmap describes intended research milestones, not guaranteed delivery dates. Scope and ordering may change as assumptions are tested.

## Stage 0 — Project foundation
- [x] Publish project purpose and design principles.
- [x] Establish contribution, conduct, security, and governance documents.
- [x] Create public project repository.
- [ ] Review project name and possible naming conflicts.
- [ ] Open initial design discussions.

## Stage 1 — Requirements and threat model
- [ ] Define entities, identity lifecycle, and key rotation.
- [ ] Define trust, authorization, revocation, and recovery requirements.
- [ ] Define attacker capabilities and security boundaries.
- [ ] Define availability, privacy, and metadata goals.
- [ ] Document non-goals and deployment assumptions.

## Stage 2 — Protocol architecture
- [ ] Define protocol layers and component boundaries.
- [ ] Specify peer identity format and fingerprint representation.
- [ ] Compare discovery models: rendezvous, federated, distributed, and local discovery.
- [ ] Define session establishment and state machines.
- [ ] Define version negotiation and extensibility.
- [ ] Select encoding and canonicalization rules.

## Stage 3 — Transport research
- [ ] Evaluate Tailcat API and integration constraints.
- [ ] Build a transport adapter prototype.
- [ ] Measure direct connection and relay behavior.
- [ ] Evaluate alternative transports and fallback behavior.
- [ ] Define transport-independent conformance tests.

## Stage 4 — Interoperable MVP
- [ ] Implement identity creation and verification.
- [ ] Implement authenticated peer sessions.
- [ ] Implement explicit authorization policies.
- [ ] Implement one application-level stream API.
- [ ] Add CLI, diagnostics, and integration tests.
- [ ] Publish reproducible two-peer demonstration.

## Stage 5 — Ecosystem
- [ ] Publish language-neutral protocol specification.
- [ ] Publish test vectors and interoperability suite.
- [ ] Add service discovery and naming.
- [ ] Add additional language bindings.
- [ ] Evaluate UDP datagrams and IP-layer networking.
- [ ] Establish release and compatibility policy.

## Not in the initial MVP

- A global public-key directory.
- A mandatory centralized account or identity provider.
- A production-grade decentralized PKI.
- A replacement for the public Internet.
- A claim of anonymity or metadata-free communication.
- A production VPN replacement or kernel networking stack.

## MVP completion criteria

Two independently configured peers can identify one another using stable cryptographic identities, discover a usable route, authenticate a session, enforce explicit authorization, and exchange application data. The result must be reproducible, documented, tested, and must not require manually configured public IPs or inbound port forwarding in the supported test environment.
