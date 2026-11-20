# UPP Protocol v1

> **Status: IMPLEMENTED AND VERIFIED (v1 two-peer slice).** This document is the normative specification of
> the wire protocol shipped in the two-peer v1 slice (ROADMAP Stage 4). Both `uppid` and `upp`, the wire format,
> discovery, handshake, session, transport, grants, and the single stream API are implemented; W6/W7 and the
> independent W8 review verified the builds, full test suite (including race), and the two-process demo.
>
> **Still out of scope / not shipped:** Stage 5 ecosystem work, a relay service or discovery directory,
> revocation propagation, post-quantum suites, and any operator-reachable TOFU/degraded path (§10–§11).
>
> **Audience:** implementers, testers, and reviewers building the two-peer slice. **Reader's goal:** implement
> or verify the protocol without guessing any encoding, constant, message field, or gate.
>
> **Source of truth:** W3 architecture decisions D1–D9 (`.opencode/reports/product-ready/architect-agent-W3-architecture.md`),
> W2 state model Models 1–5 and invariants (`.opencode/reports/product-ready/workflow-architect-agent-W2-state-model.md`),
> and W4 stable tokens (`.opencode/reports/product-ready/designer-agent-W4-ux.md`). Section references below
> point to those reports; the resolved v1 trust policy (`philosopher-agent-W5c-trust-policy.md`) is reflected
> in §6 and §11.
>
> **Tailcat-core release (not part of this frozen spec):** [ADR-002](adr-002-tailcat-core.md) reverses the v1
> transport non-goal (§10) and selects Tailcat as the default/primary connectivity core; that release has **landed
> and is implemented and verified** (v2 two-peer flow). UPP identity, strict pairwise out-of-band verification,
> explicit scoped authorization, and the no-TOFU policy in this document are inherited unchanged. A Tailcat `tc...`
> address is a **secret bearer routing hint** — never identity or authority — TCP is an explicit local-test fallback
> with no auto-downgrade, and Tailcat's wire format does not become UPP's public protocol. This document remains the
> normative description of the shipped v1 baseline.

## 1. Scope

Defines, for protocol version 1: canonical encoding and framing, record/message types, the cryptographic
suite and key schedule, transcript binding, the ordered security gates, the authorization model, error
classes, and the invariants an implementation must not violate. Section 10 lists explicit non-goals.

Two independently configured peers, each holding its own identity, pin store, and grant file, mutually
authenticate, verify out of band, authorize a scoped operation, and exchange bytes over one stream. Exactly
one logical stream exists; all protection terminates at the UPP peers, never at a socket or relay.

## 2. Terminology and frozen constants

**Terms.** *Identity key* signs only. *Ephemeral key* does X25519 only. *Session (AEAD) key* encrypts data only.
*Fingerprint (`fp`)* is the 32-byte SHA-256 identity digest. *Pairwise safety number (SN)* is a 32-byte digest
over both fingerprints, rendered for out-of-band comparison. *Grant* is a local, signed, scoped authority object.
*Hint* is an untrusted out-of-band endpoint locator. *transcript hash (`th`)* commits to the handshake.

**Version/suite registry** (W3 D2): protocol `1` only; identity suite `Ed25519`; KEX suite `X25519`; AEAD
`AES-256-GCM`; KDF `HKDF-SHA256`; hash `SHA-256`. All v1 protocol primitives use only the Go standard library;
the Tailcat transport dependency lives outside this frozen v1 protocol slice (`go.mod` now requires Go 1.27.1 and
`github.com/tailscale/tailcat v0.7.0`). Any other version, suite, or extension bit is rejected; there is **no fallback**.

**Frozen defaults** (W3 D2; test-overridable):

| Parameter | Value |
|---|---|
| Max identity key-log length | 16 |
| Max frame size | 64 KiB (65536 B) |
| Replay/freshness window `W` | 60 s |
| Retry budget `N` | 3 |
| Route timeout | 5 s |
| Handshake timeout | 10 s |
| Max challenge cache | 4096 |
| Max grants | 1024 |

**Domain-tag registry** (W3 D1; `spec` is the only place a tag literal may appear):
`open-upp/identity/fingerprint/v1`, `.../key-fingerprint/v1`, `.../self-bind/v1`, `.../continuity/v1`,
`.../acknowledgment/v1`, `.../pop/v1` (frozen from `identity/identity.go:29-34`); plus
`open-upp/identity/safety-number/v1`, `open-upp/handshake/pop/v1`, `open-upp/session/kdf/v1`,
`open-upp/session/data/v1`, `open-upp/grant/v1`.

## 3. Canonical encoding and framing

### 3.1 CANON-1 (new wire records and artifacts)

`CANON-1` is the concatenation of `u32_be len(field) || field_bytes` over fields in a fixed, published order
(W3 D1, §3):

1. All integers are unsigned, fixed-width, big-endian.
2. Strings are UTF-8 bytes. There are no maps and no optional/omitted fields; an absent value is an empty
   byte string, never an omitted field.
3. A domain tag is always field 0 of any blob that is hashed, signed, or derived.
4. Field order is defined once per type (Section 4) and is not inferred at decode time.

### 3.2 Framing

`frame = u32_be payload_len || payload`, where `payload = u8 type || CANON-1(fields…)` and
`payload_len <= 65536`. An oversize frame is rejected **before** decode. Unknown type, version, or suite is
an immediate terminal failure.

### 3.3 Identity statements (frozen; do not change)

Identity statements (self-binding, continuity, acknowledgment, PoP message) keep the existing
`message(domain, encoding/json.Marshal(fixed-field struct))` form (`identity/identity.go:310-328`). It is
deterministic because the struct has fixed field order and no maps; it is canonical-for-v1. Golden byte
vectors are a W7 test deliverable; cross-language interop is Stage 5. Two serializers therefore coexist by
design: JSON for identity statements, CANON-1 for new wire records.

Fingerprint bytes do **not** change (W3 D1; `identity/identity.go:150-160`):

```
fp = SHA256(tag_fp || 0x00 || "Ed25519" || 0x00 || root_pubkey_32)
```

No migration and no identity-test change is permitted (`identity/identity_test.go:85-97`).

## 4. Record and message types

All payloads are `type(u8) || CANON-1(fields)` in the order shown (W3 §3). Sizes: key 32 B, signature 64 B,
challenge 32 B, fp/SN digest 32 B, random id 16 B, seq `u64_be`.

| Type | Value | Fields (in order) |
|---|---|---|
| `HELLO` | `0x01` | version=1; suite_set (`"Ed25519,X25519,AES-256-GCM"`); `c_local`; `eph_pub`; `record` |
| `HELLO_RESPONSE` | `0x02` | version=1; suite=registry; `c_peer`; `eph_pub`; `record`; `pop_B` (64 B) |
| `FINISHED` | `0x03` | `pop_A` (64 B) |
| `SESSION_READY` | `0x04` | AEAD record, seq 0, empty plaintext |
| `DATA` | `0x05` | AEAD record; see AAD/nonce in §5.3; plaintext = application bytes |
| `CLOSE` | `0x06` | AEAD record, reason token (ASCII) |
| `ERROR` | `0x07` | reason token (ASCII); no secrets, no transcript |

`record` fields (in order): `{version u8, suite, class_hint, root_key(32), self_binding(64), count u32,
[key(32), continuity(64), ack(64)] × count}`. It is decoded with a private-key-free `Identity` so the
existing `Verify()` (`identity/identity.go:95-146`) enforces self-binding and both-signed continuity.
Local revocation lists are **not** transmitted.

## 5. Cryptographic suite and key schedule

### 5.1 Handshake (signed-ephemeral ECDH, SIGMA-shaped; W3 D4)

1. `HELLO(A)` = `{v, suites, c_A (32 B random), eph_A, record_A}`.
2. `HELLO_RESPONSE(B)` = `{v, suite, c_B, eph_B, record_B, pop_B}`.
3. `FINISHED(A)` = `{pop_A}`.
4. `SESSION_READY` both ways = AEAD record, seq 0, empty payload.

`th = SHA256(CANON-1(raw_HELLO_A_bytes, raw_HELLO_RESPONSE_bytes_without_pop))` — both sides hash the exact
bytes received. The PoP message is
`CANON-1("open-upp/handshake/pop/v1", c_peer, c_local, eph_local, eph_peer, th)`, signed with the current
identity key using the existing `SignChallenge` / `VerifyChallenge` (`identity/identity.go:207-242`). No new
identity-crypto API is introduced.

`HS_PROOF_CHECKING` requires: both records `Verify()`; both PoPs verify under `c_local`/`c_peer`; each
challenge single-use and within `W`; the peer's current key not on **our own** local deny list; continuity
root→current valid. At this point `ecdh = X25519(eph_priv_local, eph_pub_peer)` is held in a zeroizable
handshake context. **No traffic key exists yet.**

### 5.2 Key derivation (only after verification *and* grant)

In `ESTABLISHING_SESSION`:

```
prk = HKDF-Extract(th, ecdh)
okm = HKDF-Expand(prk, CANON-1("open-upp/session/kdf/v1", fp_A, fp_B), 72)
c2s_key || s2c_key || c2s_salt || s2c_salt = 32 + 32 + 4 + 4 bytes
```

Keys are installed exactly once. Reconnect always re-runs the full handshake with fresh challenges and
derives **new** keys; old keys are never reused and are zeroized on loss, close, failure, or revocation.

### 5.3 Data protection (W3 D4)

AEAD nonce = `salt(4 B) || u64_be seq`; AAD =
`CANON-1("open-upp/session/data/v1", th, seq, resource, op)`; sequence numbers are strict per direction from
0. A low or out-of-order sequence is `FAILED(replay)`. Identity keys sign only, ephemerals do ECDH only,
AEAD keys do data only (key-use isolation). Any failure zeroizes the handshake/session context.

## 6. State gates and ordering

Gates are sequential and none is implied by another (W2 TL;DR, Models 1–5):

```
mutual PoP + transcript binding
  → out-of-band pairwise-SN verification
    → explicit scoped grant
      → session keys
        → stream
```

The handshake (`HS_INIT → … → HS_AUTHENTICATED`) yields an **authenticated, unverified, unauthorized**
binding only; it must never derive session keys, pin trust, or grant authority. `HS_AUTHENTICATED` is not a
gate pass for anything later. Verification is **session-scoped**: a verified result in one session never
authenticates another; every session re-runs possession and continuity.

Flow-to-state mapping (W3 §4; W2 Models 1–4):

| Step | Action | W2 state / transition |
|---|---|---|
| 0 | Load identity, `Verify()`, own key not locally revoked | `IDLE → ROUTING` |
| 1 | Read hint file, TCP dial (hint untrusted) | `ROUTING → HANDSHAKING` |
| 2 | Generate `c_A`, X25519 ephemeral, send `HELLO` | `HS_INIT → HS_VERSION_NEGOTIATING` |
| 3 | Exact registry match, bind offer to raw-byte transcript | `→ HS_IDENTITY_EXCHANGING` |
| 4 | Exchange/decode records, `Verify()`, sign peer challenge | `→ HS_PROOF_CHECKING` |
| 5 | PoPs, continuity, freshness, local deny pass; compute `th` | `→ HS_TRANSCRIPT_BINDING → HS_AUTHENTICATED` |
| 6 | Display pairwise SN; operator compares OOB (`upp verify`) | `AWAITING_OOB_CONFIRM`, `VER_AWAIT_OOB` |
| 7 | Pin fp+key+SN (verified) or reject — no degraded path in v1 | `→ AUTHZ_CHECK` |
| 8 | `authz.Decide(fp, "stream", "open")` on signed local grant | `AUTHZ_EVAL → AUTHORIZED(scope) | DENIED` |
| 9 | Derive/install keys once; `SESSION_READY` both ways | `ESTABLISHING_SESSION → STREAMING` |
| 10 | Stream read/write; per-op scope and sequence checks | `STREAM_OPEN → STREAM_DATA` |
| 11 | `CLOSE` + zeroize, or failure token | `TERMINATING → ENDED` / `FAILED` / `RECOVERY` |

**Pairwise SN** (W3 D5): `base32upper_no_pad(SHA256(CANON-1("open-upp/identity/safety-number/v1",
min(fpA,fpB), max(fpA,fpB))))`, 32 bytes → 52 chars in 8-char groups (six groups of 8 + a final group of
4). Machine comparison is over the **full digest**, constant-time; display grouping is not a trust basis.
The legacy `SafetyNumber()` (`identity/identity.go:175-194`), a single-identity 13×4 display, is deprecated
presentation only and is not accepted as a pairwise SN.

**Verification outcomes (resolved v1 policy — W5c):** strict out-of-band pairwise safety-number verification
is required before any grant or session; **v1 has no degraded or trust-on-first-use path**. An OOB full-digest
match yields `VERIFIED` and pins fp+key+SN; a mismatch yields `FAILED(unverified_safety_number)` (root/fingerprint
change forces full re-verification and a new grant). A verified pin may be **reused across sessions only as
change-detection state** — never as standing trust — under four conditions: (1) fresh proof of possession over
new session data each session, (2) a valid continuity chain from pinned root to the presented current key,
(3) a fresh explicit per-session OOB safety-number confirmation, and (4) a change alert on any fingerprint or
key change. A reused pin never auto-authorizes; verification results are never authority (INV-9). The
`UNVERIFIED_DEGRADED` / `Degraded` structure may remain dormant in the data model but no v1 input path may set
it: there is no `--allow-tofu` flag, no reachable degraded state, no TOFU prompt, and no TOFU demo step (§11).

## 7. Authorization model

Local, Ed25519-signed, scoped grant file (`grants.json`, mode 0600); not a wire capability, not
attribute/federated policy (W3 D6). Fields signed by the **granting local identity's current key** under
`open-upp/grant/v1`: `{version u8, grant_id 16 B random, subject_fp 32 B, resource string, ops string[],
enabled bool}`. Demo resource `stream`, ops `open|read|write`; no wildcards. No absolute timestamps are used
(synchronized clocks are not assumed); a revoke is `enabled=false`.

`authz.Decide(subjectFP, resource, op)` passes only when an exact fingerprint lookup finds an enabled grant,
the op is in `ops`, and the grant signature verifies under the stored grant-authority public key. Absent,
revoked, scope-mismatched, or invalid grants → `DENIED`. The fingerprint is **only a lookup key**; no path
leads from `VERIFIED`, `HS_AUTHENTICATED`, discovery, or transport acceptance to `AUTHORIZED`. Every
`send/recv` re-checks scope and a denial emits a secret-free audit event. Grant revocation takes effect at
the next authorization decision; locally known identity-key revocation terminates a live session (M-8).

## 8. Error classes and reason tokens

Terminal failures print stable reason tokens; no private key, passphrase, identity-file body, transcript
byte, PoP signature, or stack trace is ever emitted (W3 D8; W4 §3/§7a). Style:
`upp: <token>: <plain sentence>` on stderr, optional `  Next: <action>` recovery line on stderr.

| Class / W2 source | Reason token |
|---|---|
| Route failure/timeout (`ROUTING`) | `route_failed` |
| Unknown peer | `unknown_peer` |
| Version/suite/extension refusal | `version_rejected` |
| Bad proof (self-binding/continuity/PoP) | `bad_proof` |
| Stale challenge / replay | `stale_challenge` |
| SN mismatch / root replacement | `unverified_safety_number` |
| Verification timeout or cancel | `verification_aborted` |
| No / revoked / out-of-scope grant | `authorization_denied` |
| Local deny-list key, at establishment or live | `revoked` |
| Session key establishment failure | `session_key_error` |
| Duplicate / out-of-order data sequence | `replay` |
| Connection loss after `N` re-handshakes | `connection_lost` |
| Mid-stream scope violation (non-terminal, audit only) | `scope_violation` |
| Graceful close / success statuses | `ended`, `key_rotated`, `granted`, `verified`, `authorized`, `session_open`, `listening` |
| Usage / malformed input | `usage error` |

Exit codes (W4 §1c): `0` success; `1` terminal `FAILED(reason)`; `2` usage/input; `3` operator decline or
cancel. A missing/invalid grant is `1`; an operator answering `no` to a grant or verification prompt is `3`.
See the getting-started guide for the exact message table and per-class recovery lines.

## 9. Security invariants (must never happen)

From W2 "Security invariants" (which trace to INV-1..INV-9, AC3, SR-1..SR-11):

1. No session key before mutual PoP and transcript binding.
2. No authorization from identity facts (fingerprint equality, key possession, verified status, discovery, or transport/relay acceptance).
3. No stream without an explicit scoped grant; scope constrains every `send/recv`.
4. No verified status without out-of-band full-digest pairwise binding; v1 has no degraded/TOFU path — verification is strict or the attempt fails.
5. No pin change on routine rotation; no auto-accept on root replacement (which forces re-verification and a new grant).
6. No unknown/critical version or suite; no silent downgrade; negotiation is transcript-bound.
7. No identity material accepted without a root→current continuity chain with both signatures valid.
8. No stale/replayed challenge; every PoP and freshness check uses an unused, in-window challenge.
9. Key-use isolation: identity keys sign only; session/transport keys never sign identity statements; identity keys never encrypt or derive session keys.
10. No revoked key in PoP or establishment; live sessions terminate on locally known revocation (M-8).
11. Verification is session-scoped; one session never authenticates another — every session requires fresh PoP, valid continuity, and a fresh OOB confirmation even when a pin is reused.
12. Full-digest comparisons only; truncated/display fingerprints are never a trust basis.
13. Secrets zeroized on close/failure/revocation; no secrets in diagnostics.
14. Every failure denies or terminates; no implicit fallback.

## 10. Explicit non-goals

Out of scope for protocol v1 / this slice:

- Wire-format or identity-statement encoding changes that alter fingerprint bytes or existing signatures.
- Tailcat or any external transport dependency; NAT traversal, relays, or cross-NAT rendezvous **in v1**.
  This non-goal is frozen for the shipped v1 slice only and is reversed by the landed Tailcat-core release
  ([ADR-002](adr-002-tailcat-core.md), Tailcat as default/primary connectivity core; implemented and verified).
  The relay sees framed ciphertext, sizes, timing, and endpoints; metadata privacy / anonymity is **not** provided.
- TLS or transport-layer termination; AEAD terminates at UPP peers only.
- Grant expiry, absolute timestamps, delegation/chain, and bearer capability tokens over the wire.
- Revocation propagation, status services, offline cache freshness, or signed root-revocation authority
  (M-8 is local deny + local live-termination only).
- Backup/recovery, multi-device aggregation, key transparency, post-quantum suites, service naming/directory,
  UDP/IP or TUN modes, language bindings, and cross-language interop test vectors (Stage 5).
- Anonymity, metadata-free operation, VPN behavior, mandatory IdP/PKI.
- Optional GUI/QR transfer of the SN (raw-32-byte/QR transfer is out of scope for this CLI).
- An operator-reachable TOFU or degraded first-contact path in v1: no `--allow-tofu`, no degraded state, no
  TOFU prompt, no TOFU step in the demo. The mechanism is **deferred to a future version, not shipped** (W5c).
  v1 is strict pairwise verification only; a successful first connection never counts as authentication.

## 11. Resolved v1 trust policy

The two value questions isolated in W3 §8 are now **resolved** by `philosopher-agent-W5c-trust-policy.md`:

1. **TOFU in v1: NO.** No operator-reachable degraded first-contact path. The degraded-mode *mechanism*
   remains documented and frozen for a future version, but v1 omits `--allow-tofu`, any input path that sets
   `Degraded=true`, any TOFU prompt, and any TOFU demo step. Strict out-of-band pairwise verification is the
   only verification path; this closes the first-session MITM gap (T1/T4) rather than conceding it.
2. **Pin reuse across sessions: YES — as change-detection state only.** A verified pin is retained across
   sessions, but each session still requires fresh PoP, a valid continuity chain from pinned root to presented
   current key, and a fresh explicit per-session OOB confirmation; any fingerprint/key change raises a change
   alert. Root replacement forces full re-verification and a new explicit grant. A pin never authorizes and
   never substitutes for fresh proof (`AUTHORIZED` is reachable only through §7).

These are settled v1 decisions, not open items. W4's strict, deny-by-default UX is confirmed unchanged; W6
omits the TOFU flag; W7 asserts that no TOFU/degraded surface exists. Only UX defaults remain unspecified by
W3: the prompt timeout (120 s) and the optional two-host LAN bind address (W4).

## 12. Traceability

| Doc section | Evidence |
|---|---|
| §2–§3 encoding, tags, bounds, fingerprint | W3 D1/D2, §3; `identity/identity.go:29-34,150-160,310-328` |
| §4 message/record schemas | W3 §3 |
| §5 handshake, `th`, PoP, KDF, AEAD | W3 D4, §3 |
| §6 gates, flow mapping, pairwise SN | W3 §4/D5; W2 Models 1–4, Model 3 note |
| §7 grants / `Decide` | W3 D6; W2 Model 3 `AUTHZ_EVAL` |
| §8 tokens / exit codes | W3 D8; W4 §1c, §3, §7a |
| §9 invariants | W2 "Security invariants"; W2 AC map |
| §10 non-goals | E1 Step 4 deferred list; W3 D3/D9; W4 §4; W5c Decision 1 |
| §11 resolved trust policy | W5c Decisions 1–2; W3 D5/§8; W4 §1b/§5 |

## Handoff record

```text
goal:                    Implementable v1 protocol spec for the two-peer slice.
hypothesis:              Reader is an implementer/tester who must not guess a constant, field, or gate.
evidence:                W3 D1-D9 + §3/§4; W2 Models 1-5, invariants, AC map; W4 tokens/exit codes;
                         W5c resolved trust policy; E1 deferred list; main code cmd/uppid/main.go,
                         go.mod, identity/identity.go.
actions_taken:           Wrote canonical encoding/framing, record types, crypto/key schedule, transcript
                         binding, ordered gates, authorization, error classes, 14 invariants, non-goals;
                         synced §6/§9/§10/§11 to the resolved no-TOFU, conditional-pin-reuse policy.
result:                  docs/architecture/protocol-v1.md (this file).
verification:            Each section cites W2/W3/W4/W5c; frozen fingerprint formula and constants copied
                         verbatim; both former value questions recorded as settled v1 decisions.
confidence:              high (all v1 policy decisions resolved and traced).
remaining_unknowns:      None blocking v1; only UX defaults (120s timeout, LAN bind) and W4's peer
                         public-record export detail. A future version may revisit shipping the TOFU mechanism.
recommended_next_action: Builder (W6) implements against this spec; Tester (W7) publishes golden byte vectors.
```
