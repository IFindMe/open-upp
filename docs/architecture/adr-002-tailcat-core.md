# ADR-002 — Tailcat as the primary connectivity core

- **Status:** Accepted (direction ratified; implementation and verification tracked separately as C4/C5/C7)
- **Date:** 2026-11-20
- **Owner:** Architecture
- **Supersedes:** v1 Decision C (out-of-band hint file + plain TCP, with Tailcat as a future seam only)
- **Evidence basis:** `philosopher-agent-C1-philosophy.md`, `architect-agent-C2-architecture.md`, `explorer-agent-E1-tailcat.md` (all under `.opencode/reports/tailcat-core/`)

## Context

Open UPP's ratified purpose is secure, authorized peer communication made *universal*: Tailcat is the **core of connectivity**, while stable UPP identity, strict pairwise verification, and explicit scoped authorization are the **core of trust** and win every conflict (`philosopher-agent-C1-philosophy.md:11-40`). The relationship is a chain — *connectivity → identity → verification → authority* — not a merger: a working tunnel answers *how peers reach each other*, never *who may speak* or *what they may do* (`philosopher-agent-C1-philosophy.md:25`).

v1 froze the opposite stance. It mandated an out-of-band hint file plus plain TCP and treated Tailcat as "only an interface seam" / an explicit non-goal (`ROADMAP.md:29`, `docs/architecture/protocol-v1.md:273`, `docs/architecture/README.md:29-31`, `architect-agent-W3-architecture.md:65-78`). E1 confirmed that v1 shipped a defined-but-uninjected `transport.Transport` seam (`Conn = net.Conn`, `Acceptor`, `Transport{Listen, Dial}`) with **no Tailcat code, package, or dependency**; callers hardcoded concrete `transport.TCP` (`explorer-agent-E1-tailcat.md:33-44`). The word "reachable" in the v1 promise ("any other reachable entity") was an assumption rather than a delivered property (`philosopher-agent-C1-philosophy.md:15`).

The user's direction — *make Tailcat the core because it provides universal connectivity* — is decisive and is a reason about **reachability**. Tailcat (WireGuard tunnels, magicsock NAT traversal, DERP fallback, no account/root/control plane) supplies the missing half, making "universal" a property of the system (`philosopher-agent-C1-philosophy.md:88`). Verified external facts used here: module `github.com/tailscale/tailcat` at `v0.7.0`, BSD-3-Clause; `Server{OnTCP}`, `Start()`, `TailcatAddr()`, `Close()`; `NewClient(Addr(addr))`, `DialTCPPort(ctx, port)`; a `tc...` capability address; and **no API/CLI/wire-stability promise** (`architect-agent-C2-architecture.md:20`).

v1 security decisions are **inherited, not renegotiated**. Every gate, wire record, fingerprint encoding, and the application API remain frozen; this ADR changes only *how peers reach each other* (`architect-agent-C2-architecture.md:31`).

## Decision

Adopt Tailcat as the selected, default connectivity substrate for open-upp, reversing v1 Decision C. Specifically:

1. **Tailcat-primary transport.** Tailcat is the default/primary transport; the "hint + TCP, Tailcat only a future seam" stance of v1 Decision C is explicitly superseded (`architect-agent-C2-architecture.md:4,31`).
2. **Widened but UPP-neutral seam.** `Conn = net.Conn` is retained because Tailcat's `DialTCPPort` / `OnTCP` both yield `net.Conn`. Exactly three interface points widen: `Acceptor.Addr() net.Addr` → `Acceptor.Endpoint()` (a `tc...` capability is not a `net.Addr`), `Dial(addr string)` → `Dial(ctx, Endpoint)`, and a `Name()` routing selector (`architect-agent-C2-architecture.md:5,46-66`).
3. **Opaque secret-bearer locator.** A Tailcat `tc...` address is stored verbatim in the 0600 out-of-band hint as an opaque locator. It is **not identity** and **not authority** (see Trust boundary).
4. **Layered encryption preserved.** UPP's X25519/AES-GCM session layer remains on top of Tailcat's WireGuard tunnel, unchanged (see Security layering).
5. **TCP as explicit local-test fallback only.** TCP is retained solely behind an explicit `-transport tcp` flag; there is **no automatic downgrade** and no allow-from-address path (`architect-agent-C2-architecture.md:8,134,149`).
6. **Exact dependency pin + adapter isolation.** Pin `github.com/tailscale/tailcat v0.7.0` exactly with a committed `go.sum` and BSD-3-Clause attribution; confine every Tailcat import to `transport/tailcat.go` (and its test) (`architect-agent-C2-architecture.md:9,140-144`).

UPP identity, pairwise verification, scoped grants, revocation/rotation checks, session establishment, wire records, fingerprints, and the application API are **frozen** — inherited from v1, not renegotiated (`architect-agent-C2-architecture.md:31`).

## Alternatives considered

From the C2 trade-off analysis (`architect-agent-C2-architecture.md:22-29`):

| Option | Architecture | Advantages | Costs / Risks | Disposition |
|---|---|---|---|---|
| **A. Tailcat-primary, widened UPP-neutral seam, TCP explicit fallback** | Tailcat default; `transport` interface widened minimally; UPP gates and session crypto unchanged | Delivers reachability, NAT traversal, DERP fallback with no control plane; gates stay transport-independent; single-file version swap | Unstable upstream API/wire; public DERP rate-limited/no SLA; double-encryption CPU | **Chosen** |
| **B. Keep v1 TCP default; Tailcat as an alternate adapter only** | No default change | Zero new dependency; deterministic demo | Contradicts ratified direction; fails MVP reachability without manual port-forward; "universal" stays a qualifier | Rejected |
| **C. Tailcat-primary; drop UPP session crypto, trust WireGuard only** | One encryption layer | Less CPU/code | Destroys identity-bound PoP/transcript binding, per-session keys, grant binding; violates identity/authority invariants, key-use isolation, and peer-terminated protection | Rejected |
| **D. Tailcat-primary with no TCP path at all** | Remove TCP | Single code path | Removes deterministic CI/demo baseline and comparison transport; no reversibility lever | Rejected as a default-only stance; folded in as explicit opt-in fallback |

## Trust boundary — a Tailcat address is not identity or authority

A Tailcat `tc...` address is a **secret bearer capability**: possession yields *reachability* to a Tailcat server. UPP deliberately refuses to promote that fact (`architect-agent-C2-architecture.md:127-134`; `philosopher-agent-C1-philosophy.md:27,62-73`):

- **Not identity.** UPP identity is the root-anchored, stable fingerprint from the identity file and the authenticated handshake. No fingerprint, pin, grant subject, or identity field is derived from a Tailcat address, WireGuard key, disco key, PSK, DERP region, or discovery record (INV-8). Address rotation therefore cannot change identity.
- **Not authority / not authentication.** A successful `Dial`, magicsock/direct connection, or DERP acceptance produces only a `net.Conn`. The full gate chain still runs and can deny: mutual PoP + transcript binding → fresh out-of-band full-digest pairwise confirmation (no TOFU/degraded path) → explicit enabled in-scope scoped grant → session keys → stream (INV-9). A verified peer with no grant is denied; a granted peer with a revoked grant is denied.
- **Capability leakage is a reachability leak, not identity takeover.** Mitigate by 0600 storage and secret-free diagnostics — never by treating the address as a credential or authorization token. No allow-from-address path exists or is added; error text must never interpolate the capability string.
- **Transport changes cannot bypass a gate.** The explicit `tcp` fallback is a routing choice, never a downgrade of identity, verification, or grant checks.

The decisive acceptance question: *can a stranger holding a valid Tailcat address reach my process and still do nothing until pairwise-verified and explicitly granted?* Both halves must hold — reachability succeeds, authority does not follow (`philosopher-agent-C1-philosophy.md:80`).

## Security layering — UPP crypto stays above WireGuard

**Both layers remain; UPP's X25519/AES-GCM session layer runs unchanged on top of Tailcat's WireGuard tunnel** (`architect-agent-C2-architecture.md:112-123`; `philosopher-agent-C1-philosophy.md:25,68`):

- WireGuard protects the *path* (including DERP relay hops) but does not provide UPP's identity-bound gates: mutual PoP, transcript binding, out-of-band full-digest pairwise verification, per-session keys bound to identity + resource, explicit scoped grant decisions, or revocation/rotation checks. Those are transport-independent and are the project's trust core.
- **End-to-end invariant:** protection terminates at UPP peers; transports/relays see only framed ciphertext (metadata visible, no anonymity). Keeping UPP's AEAD preserves this across a swap to TCP fallback or any future backend.
- **Key-use isolation / identity binding:** UPP session keys derive from identity-authenticated ECDH and signed transcripts, never from WireGuard or Tailcat keys (INV-8/INV-9). "The tunnel is already secure" reasoning is explicitly forbidden; double encryption is a feature, not redundancy to remove.
- The extra CPU cost for a low-rate two-peer CLI is accepted and recorded as an honest, bounded claim. UPP wire records and fingerprint bytes do not change, so there is no compatibility impact.

Implementation consequence: the `net.Conn` returned by Tailcat is treated as an encrypted-but-untrusted byte pipe. All gate code in `upp/peer.go` (`establish()`), and all files in `session/`, `identity/`, `verify/`, `authz/`, and `spec/`, are **frozen** and semantically unchanged (`architect-agent-C2-architecture.md:161`).

## Dependency, version, and stability strategy

1. **Exact pin:** `github.com/tailscale/tailcat v0.7.0` in `go.mod` (no caret/range), committed `go.sum`, BSD-3-Clause notice (`architect-agent-C2-architecture.md:140`).
2. **Adapter isolation:** the only Tailcat import is `transport/tailcat.go` (+ test); UPP sees only `transport.Transport`, `Endpoint`, and `net.Conn`. A version bump is a single-file change; no Tailcat type, identifier, or wire format enters identity, grants, the wire spec, or the application API.
3. **Conformance enforcement:** compile-time interface assertions and a transport-conformance suite that runs identically against Tailcat and TCP, so substituting a backend cannot silently change UPP semantics.
4. **No wire coupling:** Tailcat's unstable wire format never becomes UPP's public protocol; UPP's v1 wire records and fingerprints stay frozen.
5. **Secret hygiene:** sanitized errors — the capability string never appears in stdout/stderr, reason tokens, or wrapped errors (only in the 0600 hint).
6. **Stability risks accepted:** no upstream API/CLI/wire stability promise; public DERP is rate-limited with no SLA. These are contained by the seam, not inherited by UPP. C5 pass/fail must not depend on public DERP availability (use direct/local or self-hosted and record environment blockers).
7. **Provisional Builder checks (no design change):** verify Tailcat v0.7.0's Go requirement against the declared `go 1.24` (no silent toolchain change), and confirm whether `Client.Close()` terminates `DialTCPPort` connections (wrap the returned `net.Conn` if so) (`architect-agent-C2-architecture.md:147-148`).

## Migration and rollback notes

- **Default selection is centralized.** The default transport is chosen in one place — `cmd/upp` via a `-transport` flag (`tailcat` default, `tcp` explicit) — so reverting the default is a one-line change (`architect-agent-C2-architecture.md:79,149`).
- **No runtime auto-downgrade.** TCP is an explicit opt-in for local testing/CI comparison only; no path silently switches transports or bypasses a gate.
- **Hint format change.** The 0600 atomic JSON hint gains a `transport` discriminator (`"tailcat" | "tcp"`), keeps `subject_fp`, `addr` (opaque `tc...` capability or TCP host), and `port`, and retires `Hint.Target()` from the dial path. `subject_fp` remains a routing consistency check only and must never be derived from the Tailcat address (`architect-agent-C2-architecture.md:88-108`).
- **Rollback lever and version changes.** Reverting to TCP is `cmd/upp` configuration only; it does not alter identity, grants, wire records, or the application API. Any Tailcat **upgrade** is a single-file change that requires the full C5 gate-regression matrix to pass before release.

## Acceptance criteria summary

Full criteria are in `architect-agent-C2-architecture.md:153-176`.

- **C4 (implementation):** exact `v0.7.0` pin with committed `go.sum`; `transport/tailcat.go` the sole import site with `var _ Transport` assertions; `Endpoint`, `Name()`, `Dial(ctx, Endpoint)`, `Acceptor.Endpoint()` present; `upp.Config.Transport` required and injected with no hardcoded `transport.TCP` outside the explicit fallback branch and no `*net.TCPAddr` cast; Tailcat default with a 0600 hint carrying `transport:"tailcat"` + `tc...` addr; capability absent from all diagnostics; `establish()` and all gate/crypto files semantically unchanged (diff-verifiable).
- **C5 (verification):** transport-conformance suite passes for both Tailcat and TCP; two-process direct P2P reachability (DERP behavior recorded, not gating on public DERP); **decisive gate-regression proof** — a peer holding a valid Tailcat capability is still denied until PoP+transcript binding, fresh OOB full-digest confirmation (no TOFU), and an explicit enabled in-scope grant all pass, including ungranted-verified, revoked-grant, root/key-change re-verification, and capability-only/no-identity cases; hint validation and 0600 mode enforced; secret-leak test passes; CLI smoke reaches gate 1; `SESSION_READY` exchanged under UPP AEAD over the Tailcat conn.
- **C7 (release):** gated on a clean C6 verdict with zero blocking findings; C3 doc rescission verified (no stale "optional seam"/"non-goal"/"Tailcat only" claim and no new Tailcat-wire-is-UPP or compatibility claim); NOTICE BSD-3-Clause attribution present; default confirmed Tailcat, TCP confirmed opt-in, rollback lever recorded.

## Consequences

**Positive**
- The reachability half of the ratified philosophy is delivered: peers connect across NAT without manual public IPs or inbound port forwarding, no account/root/control plane.
- The five-concern separation (identity, discovery, authorization, session, transport) is preserved; identity and authorization remain strictly transport-independent.
- The isolation boundary becomes stronger: one adapter file contains an unstable external API.
- Reversibility is cheap — the default is a single configuration point with an explicit TCP fallback.

**Negative / accepted**
- A new external dependency with no API/wire stability promise; public DERP is best-effort.
- Double-encryption CPU cost, accepted as an honest bounded claim.
- Two provisional upstream checks (Go-version compatibility; client/conn lifetime) remain for Builder verification; both have defined mitigations and neither changes this decision.

**Neutral**
- "Transport independence" is narrowed honestly: independence of *identity and authorization from transport* remains absolute; independence of *the project from any transport commitment* ends.
- v1 remains a frozen historical slice whose security decisions are inherited, not renegotiated; C3 owns rescinding stale "optional seam"/"non-goal" documentation without introducing a compatibility claim.

## Evidence map

| Claim | Source |
|---|---|
| Connectivity-vs-trust split; gates win all conflicts; address ≠ identity/authority | `philosopher-agent-C1-philosophy.md:11-40, 62-82` |
| Reversal of v1 Decision C; Option A decision; frozen gates | `architect-agent-C2-architecture.md:4, 22-36` |
| Module path, `v0.7.0`, BSD-3-Clause, exact pin, adapter isolation, stability risks | `architect-agent-C2-architecture.md:20, 138-149` |
| Trust boundary; secret bearer locator; no allow-from-address path | `architect-agent-C2-architecture.md:127-134` |
| UPP X25519/AES-GCM over WireGuard; gates frozen | `architect-agent-C2-architecture.md:112-123, 161` |
| TCP explicit `-transport tcp` fallback; no auto-downgrade | `architect-agent-C2-architecture.md:5, 8, 79, 134, 149` |
| v1 shipped defined-but-uninjected seam, no Tailcat code/dependency | `explorer-agent-E1-tailcat.md:20-25, 33-44` |
| Migration/rollback, acceptance criteria | `architect-agent-C2-architecture.md:88-108, 149, 153-176` |
