# Open UPP

**Universal Peer Protocol — identity-based connectivity for everything, with Tailcat as the default/primary connectivity core (Tailcat-core release, ADR-002 landed).**

Open UPP is an open protocol project exploring how devices, services, applications, and autonomous agents can discover, authenticate, authorize, and communicate across network boundaries. Reachability is a delivered property of the system through Tailcat — WireGuard peer-to-peer tunnels, magicsock NAT traversal, and DERP relay fallback with no account, root, or control plane. The v2 two-peer flow over Tailcat is implemented and verified.

> Give every participating entity a cryptographic identity and a standard way to establish secure, authorized communication with any other reachable entity—regardless of network, location, operating system, or application. Tailcat supplies the reachability; stable UPP identity, strict pairwise verification, and explicit scoped authorization turn reachability into trust.

**Status: The frozen two-peer v1 slice is implemented and verified — `CANON-1` framing, an untrusted out-of-band hint over TCP, a mutually authenticated proof-of-possession handshake, an X25519/HKDF/AES-GCM session, strict pairwise safety-number verification, explicit scoped grants, one application stream, and the `upp` CLI; unit/integration tests and a reproducible two-peer demo pass. Not production-ready: no relay service, discovery directory, revocation propagation, or post-quantum/TOFU support (TOFU is deferred and has no operator-reachable flag), and no UPP compatibility claim yet.**

**Tailcat-core release (implemented and verified; [ADR-002](docs/architecture/adr-002-tailcat-core.md) landed):** Tailcat is now the default/primary connectivity core, reversing the v1 transport non-goal; the v2 two-peer flow over Tailcat is implemented and verified by C4/C5/C6 (full suite including race, live Tailcat lifecycle, and a two-process default-Tailcat smoke). UPP identity, strict pairwise out-of-band verification, explicit scoped deny-by-default authorization, and the no-TOFU policy are **unchanged** — they are the trust core. The shipped v1 hint-over-TCP slice remains the frozen baseline, and TCP is retained only as an explicit local-test fallback with no auto-downgrade. Tailcat API/wire instability, best-effort/rate-limited public DERP, and the Go 1.27.1 requirement remain documented limitations.

Open UPP is independent and is not affiliated with or endorsed by Tailscale, Tailcat, WireGuard, or their maintainers.

## Why Open UPP?

VPNs provide network-layer connectivity but often require network administration. Peer-to-peer tools establish connections but may lack reusable identity, naming, authorization, and service models. Application protocols generally assume connectivity already exists.

Open UPP investigates a composable layer connecting these concerns while keeping them independently replaceable.

## Design principles

1. **Identity before location.** Cryptographic identity is stable; IP addresses and transport endpoints are not.
2. **Authorization is explicit.** Knowing a public key must never automatically grant access.
3. **Transport-independent identity and authorization.** UPP identity, verification, grants, and wire records must not depend on any networking backend — including Tailcat. The project has landed Tailcat as its default/primary connectivity core in the Tailcat-core release ([ADR-002](docs/architecture/adr-002-tailcat-core.md)); what stays independent is the trust layer, not the project's transport choice.
4. **Secure by default.** Authenticate peers, minimize exposed services, and make trust decisions explicit.
5. **Interoperability.** Publish versioned specifications, test vectors, and language-neutral behavior.
6. **Incremental adoption.** Start with application-level streams; consider virtual IP networking separately.
7. **No mandatory global authority.** Explore federated and decentralized discovery, documenting trade-offs.
8. **Operational clarity.** Observability, debuggability, and bounded resource use are design requirements.

## Conceptual architecture

```text
Applications and services
  SSH | HTTP | file transfer | RPC | agent messaging
                         |
                 Open UPP API / CLI
                         |
  +----------------------+----------------------+
  | Identity | Discovery | Authorization | Session |
  +----------------------+----------------------+
                         |
                Transport abstraction
                 /        |        \
              Direct    Relay    Other backends
                         |
                  Network connectivity
```

This is a conceptual model, not a finalized protocol stack. The frozen, shipped v1 two-peer slice uses an untrusted out-of-band endpoint hint and TCP; that remains the baseline. The Tailcat-core release ([ADR-002](docs/architecture/adr-002-tailcat-core.md), landed) reverses the v1 transport non-goal and makes Tailcat the default/primary connectivity core — implemented and verified — with TCP retained only as an explicit local-test fallback and no auto-downgrade. A Tailcat `tc...` address is a **secret bearer routing hint**: it confers reachability only and is never a UPP identity, proof, pin, or authority. Tailcat's internal APIs and wire formats are not assumed stable and are not suitable as Open UPP's public protocol; the adapter boundary keeps them out of the identity, grant, wire, and application layers.

## Project status

This repository contains project documentation and a stdlib-only Go implementation of the **frozen two-peer v1 slice**: Ed25519 identity creation and verification, both-signed key rotation, and local-only revocation (`uppid`), plus a working wire protocol — `CANON-1` framing, an untrusted out-of-band hint resolved over TCP, a mutually authenticated handshake with proof of possession, an X25519/HKDF/AES-GCM session, strict pairwise safety-number verification before authorization, explicit scoped grants (no allow-from-fingerprint path), and a single application stream, exposed through the `upp` CLI. Unit, integration, and negative tests and a reproducible two-peer demo all pass. Revocation is local only, with no propagation; trust on first contact (TOFU) is deferred in v1 and has no operator-reachable flag.

Documents for the implemented v1 slice:

- [Protocol v1 specification](docs/architecture/protocol-v1.md) — frozen architecture and wire format.
- [Getting started](docs/user-guide/getting-started.md) — two-peer user guide.

Current documentation:

- [ADR-002: Tailcat as connectivity core](docs/architecture/adr-002-tailcat-core.md) — reversal of the v1 transport non-goal; landed in the Tailcat-core release (implemented and verified).
- [Architecture](docs/architecture/README.md)
- [Protocol design](docs/protocol/README.md)
- [Security model](docs/security/README.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)

## Getting involved

We welcome participation in protocol design, threat modeling, documentation, interoperability research, and implementation. Please open an issue before proposing substantial changes. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Unless otherwise stated, project materials and code are licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE).

## Compatibility

"Open UPP" is the working project name. Protocol identifiers, wire formats, and compatibility guarantees are not finalized. No implementation should claim UPP compatibility until a versioned specification and conformance tests exist; adopting Tailcat as the connectivity core does not create a compatibility claim.
