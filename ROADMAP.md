# Roadmap

This roadmap describes intended research milestones, not guaranteed delivery dates. Scope and ordering may change as assumptions are tested.

## Stage 0 — Project foundation
- [x] Publish project purpose and design principles.
- [x] Establish contribution, conduct, security, and governance documents.
- [x] Create public project repository.
- [ ] Review project name and possible naming conflicts.
- [ ] Open initial design discussions.

## Stage 1 — Requirements and threat model
- [x] Define entities, identity lifecycle, and key rotation.
- [ ] Define trust, authorization, revocation, and recovery requirements.
- [ ] Define attacker capabilities and security boundaries.
- [ ] Define availability, privacy, and metadata goals.
- [ ] Document non-goals and deployment assumptions.

> Implementation note: the identity lifecycle in Stage 1 is not design-only — a stdlib-only Go prototype of local identity creation, verification, both-signed rotation, local-only revocation, and the `uppid` CLI is merged on `main`, with local unit tests. It does not implement any wire protocol.

## Stage 2 — Protocol architecture
- [ ] Define protocol layers and component boundaries.
- [ ] Specify peer identity format and fingerprint representation.
- [ ] Compare discovery models: rendezvous, federated, distributed, and local discovery.
- [ ] Define session establishment and state machines.
- [ ] Define version negotiation and extensibility.
- [ ] Select encoding and canonicalization rules.

> Architecture note: the Stage 2 choices are frozen for v1 in the architecture decisions — canonical v1 tags with unchanged identity-statement encoding and `CANON-1` for new wire records, untrusted out-of-band hint file plus TCP transport (Tailcat only as an interface seam), and strict pairwise safety-number verification. The protocol specification and the code implementing the two-peer v1 slice are delivered and verified; see the [Protocol v1 specification](docs/architecture/protocol-v1.md).

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

> Implementation note: the Stage 4 two-peer slice is implemented and verified — authenticated sessions, explicit scoped-grant enforcement, the single stream API, CLI diagnostics, integration tests, and a reproducible two-peer demonstration all pass. The frozen v1 policy is strict pairwise safety-number verification before authorization, explicit scoped grants with no allow-from-fingerprint path, and local-only revocation (no propagation). See the [Getting started](docs/user-guide/getting-started.md) guide.

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

## Related documents (implemented v1 slice)

- [Protocol v1 specification](docs/architecture/protocol-v1.md)
- [Getting started](docs/user-guide/getting-started.md)
