# Open UPP peer identity and key lifecycle

This document proposes a peer identity model and key lifecycle for Open UPP, answering Issue #2: what an identity represents, and how it is created, verified, rotated, revoked, and recovered. It expands the identity concern of the [architecture notes](README.md) and applies the requirement and threat identifiers of the [threat model](../security/threat-model.md), a draft cited here as existing analysis, not settled law. It does not design discovery (Issue #3), transport backends such as Tailcat (Issue #4), the handshake, authorization policy, or any wire format; those appear only as interfaces or open dependencies.

**Implementation and decision status.** A merged, stdlib-only Go prototype implements the local identity primitives described here — creation, verification, both-signed rotation, local-only revocation, the `uppid` CLI, and local unit tests — but no wire protocol. The v1 decisions previously left open here (encoding, hint/TCP transport, verification, grants, and M-8) are now frozen in the [Protocol v1 specification](protocol-v1.md): strict out-of-band pairwise safety-number verification is the gate, authorization requires an explicit scoped grant with no allow-from-fingerprint path, and revocation is local only, with no propagation. See also the [Getting started](../user-guide/getting-started.md) guide. The **Proposed** labels below are preserved for the identity-layer choices this document owns; the frozen v1 decisions govern the protocol slice.

**Decision labels.** Every significant design decision carries exactly one label:

- **Proposed** — a new recommendation made here, awaiting review; not established project direction.
- **Accepted** — a position already established in a merged repository document as project direction; used only for those positions.
- **Deferred** — explicitly out of the MVP, kept compatible with a future path.
- **Open question** — genuinely undecided; recorded only in section 15 and cross-referenced from elsewhere.

No new choice here is labeled **Accepted**. Requirements traced from the draft threat model (SR and M identifiers) are traces, not decisions, and are not labeled.

**Normative terms.** RFC 2119 keywords are used as in the threat model and impose no current obligation on this repository.

## 1. Scope and design goals

**In scope.** What an identity is and may represent; the logical identity record and fingerprint; creation; first-contact verification; separation of identity keys from session and transport keys; rotation and continuity; identity-layer revocation; backup and recovery posture; multi-device posture; identity-specific threats; testable invariants; migration considerations.

**Out of scope.** Discovery, rendezvous, and relay protocols (Issue #3); transport adapters and Tailcat evaluation (Issue #4); handshake, session state machines, and wire encodings; authorization grants and delegation mechanics; service naming; anything requiring a global directory, mandatory identity provider, or production PKI — all non-goals ([ROADMAP](../../ROADMAP.md), [root README](../../README.md)).

**Goals.**

- **Accepted.** Identity stays stable across IP addresses, interfaces, relays, and transport backends ("identity is not location").
- **Accepted.** Identity proves key possession only and never grants authorization (architecture notes, "Identity is not authorization"; root README principle 2).
- **Accepted.** Established, reviewed primitives only — no invented primitives ([protocol design](../protocol/README.md)).
- Rotation and revocation preserve continuity (traces SR-2, SR-7).

**Non-claims.** No anonymity, unlinkability, or metadata freedom; no forward secrecy (a session-design goal; handshake open, threat model section 10); no Sybil resistance; no post-quantum guarantee; no global revocation guarantee.

## 2. Terminology

Definitions follow the [threat model](../security/threat-model.md) where defined; extensions are marked.

- **Principal** — the entity on whose behalf authority is exercised; one principal may control several identities (threat model, section 4).
- **Identity** — a cryptographic, key-bound representation of a principal, device, service, or agent; not a name, address, role, or permission (threat model, section 4). Here: an append-only record anchored by one root public key.
- **Identity key** — a long-term signing key in an identity's key log; the **root key** is the anchor defining the identity. Identity keys sign statements and authenticate sessions; they never encrypt.
- **Fingerprint** — a collision-resistant identifier computed from an identity's root key (section 6); distinct from a **key fingerprint** (per key) and a **safety number** (pairwise, section 7).
- **Device / service / application / agent** — the key-holding entity classes an identity may represent (section 4). Applications must not inherit ambient authority; agent delegation and attribution are out of scope (threat model, sections 4 and 10).
- **Session and transport keys** — ephemeral per-session material owned by the session design, and transport-scoped material owned by the adapter; both distinct from identity keys (threat model, section 2; SR-2).
- **Proof of possession** — a signature over fresh challenge-bound data proving control of a private key; possession proves control, not intent, truth, or permission (threat model, sections 1 and 3).
- **Continuity proof** — a domain-separated signed statement linking a root key to a successor, or an old root to a new root, so a verifier follows key changes without losing the identity binding.

## 3. Requirements and assumptions

**Traced requirements** (draft [threat model](../security/threat-model.md)):

- **SR-1 / M-2 / M-4** — peers prove possession and bind identity to session parameters; encoding, display, comparison, first contact, and trust-on-first-use must be defined; discovery, transport success, relay acceptance, and key possession are not authentication or authorization; identity is verified independently of the discovery record.
- **SR-2 / M-1** — long-term, session, and transport keys must be distinct; rotation and revocation must preserve continuity; secrets must not appear in logs; established algorithms only; storage and isolation remain open.
- **SR-7 / M-8** — revocation must distinguish identity-key, device, grant, and session scope; a locally known revoked identity must be denied at session establishment; propagation, offline behavior, and cache freshness are open and post-MVP.
- **SR-4 / SR-5 / SR-6** — discovery is not identity proof; protection must not rely on transport identity; negotiation must be transcript-protected with no silent downgrade (owned by session and protocol designs).
- **SR-10** — applications and agents receive explicit scoped authority and must not inherit keys or grants.

**Binding constraints from Issue #2.** Identity must be independent of IP addresses, transport endpoints, and Tailcat-specific identifiers, and public-key possession must not grant service authorization — both from the architecture notes (**Accepted**).

**Assumptions.**

- **Accepted.** No mandatory global authority, directory, or production PKI exists and the MVP must not require one (root README principle 7; threat model section 5; ROADMAP).
- **Accepted.** Discovery data stays untrusted hints until authenticated ([security model](../security/README.md)).
- **Accepted.** Tailcat, if adopted, is one optional adapter with no identity field depending on it (architecture notes).
- The network is hostile and endpoints may be compromised (threat model, sections 5-6); synchronized clocks must not be assumed, so identity records carry no timestamps; the MVP targets two-party application streams.

**Interface dependencies** (decided elsewhere): the session design provides fresh challenge data, transcript binding, and suite negotiation; Stage 2 v1 encoding is frozen in the [Protocol v1 specification](protocol-v1.md) (section 15 records the earlier question and its resolution); authorization owns the v1 explicit scoped grants; discovery owns endpoint records.

## 4. Identity data model

**What an identity is.** An Open UPP identity is an append-only, key-bound record anchored by a single **root public key**: the root key defines the identity, and the record carries a self-binding statement, an optional class hint, and a key log of successor keys covered by continuity proofs. Addresses, endpoints, names, and roles live outside it, in the discovery and authorization layers this document does not design.

```text
Principal (human, org, or workload)
   |   association recorded OUTSIDE the identity:
   |   contact records, authorization policy, discovery
   |   (binding open, section 15)
   v
Identity  -- stable across key rotation and network changes --
+----------------------------------------------------------+
| root public key K0 + suite     (identity anchor)         |
| format version                 (signed, not fingerprinted)|
| optional class hint            (self-asserted, non-auth) |
| key log: K0 -> K1 -> ... -> Kn (current)                 |
|   each link: continuity proof by predecessor             |
|              and acknowledgment by successor             |
+----------------------------------------------------------+
identity fingerprint fp = SHA-256(domain-separation || suite || K0)
   |
   +--> session keys      (fresh, per session; session design owns them)
   +--> transport keys    (adapter-scoped; transport design owns them)
```

Logical structure, not a wire format; byte encoding is an open dependency (section 15).

**Independence from network and transport.** No identity field contains an IP address, port, hostname, interface, relay name, or backend identifier, and the fingerprint is computable from the anchor alone. Identity material travels in band during session establishment, or through untrusted discovery records that merely point at an identity; discovery never defines it (**Accepted**, "identity is not location").

**Issue #2 question 1 — what can an identity represent?** **Proposed.** One identity represents exactly one key-holding entity instance: a device, service, application, or agent instance — or, with no further subdivision, the principal itself, matching the threat model's definition of identity as "a principal, device, service, or agent" (section 4). A human user is primarily a **principal** who may control several identities. The record therefore carries at most an optional **class hint** (device, service, application, agent, principal), signed by the root key and explicitly non-authoritative: UI and policy input, never permission (identity-is-not-authorization, section 8).

**Design decisions.**

- **Proposed.** The identity anchor is the root public key: identity is key-bound at its root yet stable under successor-key rotation (section 9).
- **Proposed.** The signed record contains no name, role, permission, address, endpoint, or timestamp: names are not authoritative (threat model, T1) and clock behavior is unresolved.
- **Proposed.** One identity per key-holding instance in the MVP; multiple identities per principal are normal and are not aggregated by the identity layer (section 12).

## 5. Cryptographic choices and rationale

**Issue #2 question 2 — Ed25519-only or an algorithm-abstracted identity format?** **Proposed.** The identity format abstracts over algorithms through an explicit **suite identifier**: every key names its suite, and a suite registry maps identifiers to signature algorithms with fixed encodings. The MVP proposes **Ed25519 (RFC 8032)** as default for new root keys. Records are long-lived and post-quantum policy is open, so a fixed algorithm would force identity migration on every change, while a suite-tagged key log allows successors under a new suite without changing the fingerprint. Abstraction costs no security if the suite identifier is signed, the transcript binds negotiated suites (M-7, SR-6), and verifiers reject unknown suites.

**Signature suite trade-offs.** Sizes are approximate; standardization status is verified in section 17.

| Suite | Standardization | Typical sizes (key, signature) | Trade-offs for identity use |
| --- | --- | --- | --- |
| Ed25519 | RFC 8032; FIPS 186-5 | 32 B, 64 B | Deterministic signing, no nonce handling, wide support; 128-bit security |
| Ed448 | RFC 8032; FIPS 186-5 | 57 B, 114 B | Higher classical strength; slower, larger, less widely implemented |
| ECDSA P-256 | FIPS 186-5; SP 800-186 | 33-65 B, ~64 B | FIPS-friendly; nonce and encoding pitfalls require care (RFC 6979) |
| ECDSA secp256k1 | SECG SEC 2; no IETF or NIST profile | 33-65 B, ~64 B | Large blockchain ecosystem; no federal standard or identity-interop profile |
| BLS | draft-irtf-cfrg-bls-signature-07 (not an RFC) | 48-96 B at 128-bit level (BLS12-381) | Aggregation irrelevant to two-party authentication; rogue-key attacks need proofs of possession |
| ML-DSA / SLH-DSA | FIPS 204 / FIPS 205 (final, August 2024) | 1.3-2.6 KB keys; 2.4-4.6 KB and 7.8-49.9 KB signatures | Post-quantum; larger artifacts, younger interop; deferred pending project policy |

**Why Ed25519 as the MVP default.** RFC 8032 gives deterministic signing with no per-signature randomness to get wrong and small fixed encodings that simplify fingerprints; FIPS 186-5 approves EdDSA for FIPS deployments. Ed448, ECDSA variants, and BLS remain registry options only.

**Issue #2 question 4 — separating long-term identity keys from ephemeral session and transport keys.** **Proposed.** Three rules. Identity keys are sign-only — never encryption, key agreement, or session key derivation — so compromise cannot directly decrypt recorded traffic. Session keys are ephemeral and owned by the session design; this document requires only that they be distinct and never sign identity statements. Transport keys belong to the adapter and are never identity material: a backend's own authentication does not bind a UPP identity, and protection must not rely on transport identity (SR-5). Forward secrecy comes from the session key schedule; nothing here claims it (SR-2).

**Design decisions.**

- **Proposed.** Algorithm-agile suite registry with per-key suite identifiers; Ed25519 is the MVP default suite for new root keys.
- **Proposed.** Identity keys sign only; encryption and key agreement are excluded from the identity layer.
- **Deferred.** Post-quantum suites (ML-DSA, SLH-DSA, hybrids) in the MVP. The registry keeps them compatible: a successor under a PQ suite preserves the fingerprint, so migration is a rotation, not a new identity (section 9). NIST IR 8547 (final, October 2026) deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them after 2035 under NIST standards, so the migration path must exist though project policy is open (section 15).

## 6. Identity creation and fingerprinting

**Creation flow (Proposed).** (1) Generate a root key pair in the chosen suite with a vetted library; randomness failure is fatal. (2) Choose a format version and optional class hint. (3) Produce the self-binding statement: a domain-separated root-key signature over version, suite, root public key, and class hint. (4) Compute the fingerprint for first-contact verification (section 7). (5) No registration: creation involves no authority, directory, or network action.

**Issue #2 question 3 — how are fingerprints encoded and compared?** **Proposed.** The identity fingerprint is `SHA-256(domain-separation tag || suite identifier || root public key octets)`, where key octets are the suite's fixed canonical public-key encoding (for Ed25519, the 32 octets of RFC 8032 section 5.1.2) and the tag is a project-reserved ASCII string with an explicit version suffix, assigned with the future specification so fingerprints cannot collide with other Open UPP object hashes. SHA-256 (FIPS 180-4) is proposed as ubiquitous, fast, and conservative; the tag's structure is fixed here, its exact value ships with test vectors.

- **Display form (Proposed).** Uppercase base32 (RFC 4648 alphabet A-Z plus 2-7, no padding), grouped in blocks of eight characters. The digits 0, 1, 8, and 9 never occur, so a confusion such as 0/O or 1/I resolves to exactly one valid character. QR codes carry the raw 32 digest bytes, so scanning cannot be confused with typing.
- **Comparison rules (Proposed).** Machine comparison normalizes case and whitespace, then compares the full 32-byte digest in constant time; only full-digest equality accepts, and characters outside the alphabet are rejected rather than mapped (no 0-to-O or 1-to-I leniency; RFC 4648 sections 3.3 and 3.4). Human comparison uses the full grouped string or a safety number (section 7), never a truncated prefix. A truncated fingerprint may appear as a decorative hint but **must not** base any trust decision; prefix collisions are a stated impersonation vector (threat model, T1).
- **Key fingerprints (Proposed).** Each key in the log has a per-key fingerprint, `SHA-256(distinct domain-separation tag || suite || key octets)`, whose tag cannot collide with identity fingerprints; key fingerprints feed safety numbers and revocation statements.

**Canonical encoding dependency.** Fingerprints are defined over suite-defined raw key octets, so their structure is fixed now and independent of statement serialization. The v1 tag registry and suite identifiers are frozen in the [Protocol v1 specification](protocol-v1.md) with fingerprint bytes unchanged: identity statements keep their deterministic fixed-field encoding, and new wire records use length-prefixed `CANON-1` (section 15 records the earlier open question and its resolution; golden byte vectors are defined in the W7 tests — `spec/spec_w7_test.go`, `identity/identity_w7_test.go`, `verify/verify_w7_test.go`).

**Design decisions.**

- **Proposed.** Local, authority-free creation with a self-binding statement; no registration step exists.
- **Proposed.** Fingerprint definition, base32 display, full-digest constant-time comparison, and display-only truncation as specified above.
- **Implementation note.** The merged `uppid` CLI still prints a `safety number:` line of 13 groups of 4 characters; that is a legacy display of a **single** identity fingerprint, deprecated presentation only and never accepted as the pairwise number for peer verification. The pairwise safety number used for verification is the full-digest, 8-character-group form of section 7 (see the [Protocol v1 specification](protocol-v1.md) and [Getting started](../user-guide/getting-started.md)).

## 7. First-contact verification

**The problem.** On first contact nothing about the peer is known: an on-path attacker can present a valid-looking record, a discovery provider can substitute keys or endpoints (threat model, T1, T6), and anyone can mint a fresh identity. Out-of-band verification adds an independent channel carrying the binding.

**What is verified, and over which channel (Proposed).** Peers exchange identity records inside the session (root key, suite, key log, continuity chain, possession proof over fresh transcript data — mechanism owned by the session design). Independently, over a channel the attacker is assumed not to control (in person, QR scan, voice call, or an already-verified channel), the peers compare a **pairwise safety number**:

```text
Alice                                        Bob
  | creates identity, fingerprint fp(A)         creates identity, fp(B)
  | <---- identity records, key logs, chains over the UPP session ----> |
  |        (authenticity not yet established at this point)            |
  |                                                                    |
  |  out-of-band channel (QR, voice, or in person):                    |
  |  SN = SHA-256(domain-separation || min(fp(A),fp(B)) || max(...))   |
  |  <-------------- both sides compute and compare SN ------------>   |
  |                                                                    |
  |  each side pins: fp, last verified key, SN = verified              |
  |  session transcript binds fp, current keys, suites, fresh data     |
  v  authenticated identity binding; authorization decided separately
```

Session and discovery designs own message formats. The safety number uses both identity fingerprints in sorted order, binding the pair symmetrically (resisting unknown-key-share) and giving both sides the same string. Because fingerprints are root-anchored, routine successor rotation (section 9) does not change it; only a root replacement does, forcing re-verification. In the frozen v1 flow this pairwise number is the strict verification gate: the full digest is compared in constant time, and the display uses 8-character base32 groups — not the legacy single-identity 4-character display code.

**Issue #2 question 6 — how does first contact prevent key substitution?** **Proposed.** Four cumulative checks: (1) the in-band record must carry a continuity chain from presented root to current key, and the current key must prove possession over fresh session data, so a copied identity without private keys fails; (2) the out-of-band safety number binds both parties' exact root keys, so an attacker substituting their own root yields different safety numbers; (3) transcripts bind identity and negotiated suites, so a relayed or downgraded handshake cannot change the binding (M-2, M-7); (4) verified fingerprints are pinned, so key changes surface against prior state. If (2) has not happened the peer is **unverified** and must be shown as such; trust-on-first-use is only an explicitly marked degraded mode with change alerts, never a silent default.

**Trade-offs and residual risk (Proposed).** QR scan gives the highest assurance but needs a camera; numeric comparison works by voice but is error-prone; out-of-band files inherit the channel's security; TOFU is cheapest and gives no first-session MITM protection. Verification proves key binding, not real-world identity — a correct safety number means "the holder of these keys," not "this person is who they claim socially" (threat model first-contact residual, M-12).

**Design decisions.**

- **Proposed.** Pairwise safety numbers over identity fingerprints, verified out of band, pinning fingerprint plus last verified key.
- **Proposed.** Unverified-by-default status; TOFU permitted only as an explicitly marked degraded mode with change alerts.
- **Open question (recorded in section 15):** which deployment-level trust anchors beyond pairwise verification are permitted; this document selects none.

**Implementation note (resolved v1 policy).** The v1 user flow requires strict out-of-band pairwise safety-number verification before any grant or session; verification is never authority. There is no degraded or trust-on-first-use path in v1: the TOFU mechanism stays frozen as an explicitly marked degraded mode for a future version and is deferred, not shipped — no operator-reachable flag, prompt, or degraded state. A verified pin may be reused across sessions as change-detection state only: each session still requires a fresh proof of possession, a valid continuity chain, and a fresh out-of-band confirmation; any fingerprint or key change raises a change alert and requires re-verification, and root replacement forces full re-verification and a new explicit grant.

## 8. Authentication and authorization boundaries

- **Accepted.** Possession of a peer's public key proves control of the corresponding private key during an authenticated exchange; it grants no permission to any service (architecture notes, "Identity is not authorization"; root README principle 2).
- **Accepted.** The five concerns are separate: identity, discovery, authorization, session, transport (architecture notes). This document owns only identity.
- **Accepted.** Discovery returns candidate connection information associated with an identity; it does not redefine that identity, and discovery data stays untrusted hints until authenticated (architecture notes; [security model](../security/README.md)).
- **Proposed.** The identity layer exposes exactly one output: an authenticated binding of (fingerprint, current key, class hint) to a session, or a failure — never an authorization decision. Transport success, relay acceptance, or a key lookup is not identity evidence (trace SR-1), and an authenticated identity is still not permission: grants live in authorization policy and are enforced at the resource (trace SR-3).
- **Proposed.** Verification results are context-bound to the session that produced them: verifying a fingerprint in one session does not authenticate another; every session re-establishes binding through possession plus continuity.

Consequences are testable in section 16: no path may derive an allow decision from fingerprint equality alone.

## 9. Key rotation

**Issue #2 question 5, part one — rotation semantics.** **Proposed.** Rotation is append-only continuity, not identity replacement. The current key signs a domain-separated **successor statement** over the identity fingerprint and the successor's suite and public key, and the successor **acknowledges** by signing back over the same content. Both signatures are required: the predecessor's proves authorization to extend the log, the successor's proves the new key is held by its future user, blocking enrollment of a key a third party does not control.

```text
 K0  (root; pinned at first contact)
  |  successor statement signed by K0  +  acknowledgment signed by K1
  v
 K1  (current)   ...   Kn
      fp = SHA-256(domain-separation || suite || K0)   [unchanged by rotation]

 Root replacement (identity migration; fp CHANGES to fp'):
 K0  -- cross-certification signed by K0 and acknowledged by R0 -->  R0
      fp' = SHA-256(domain-separation || suite_R || R0)
      MVP: explicit user confirmation required; silent acceptance forbidden
```

Logical structure; not a wire format.

**Rules.**

- **Proposed.** Routine successor rotation never changes the fingerprint, never requires out-of-band re-verification, and never changes what is pinned; a new current key is accepted only when its chain to the pinned root verifies (INV-2, INV-3).
- **Proposed.** Root replacement is a distinct event — **identity migration** — producing a new fingerprint: the old root cross-certifies the new root and the new root acknowledges it, so a peer pinned to the old fingerprint can follow. In the MVP the change must be surfaced and confirmed explicitly: auto-following trusts the old root's continued honesty, which a stolen root key destroys.
- **Deferred.** Automatic trust transfer on root replacement for peers holding a verified cross-certification chain.
- **Proposed.** Algorithm migration happens through the key log: successors may switch suites without changing the fingerprint, so a future PQ suite is a rotation, not a new identity; replacing the root itself is identity migration with the same confirmation rule.
- **Proposed.** Rotation statements are domain-separated by type and bind the identity fingerprint, so a statement for one identity cannot be replayed as another or spliced in from another context. Statement byte encoding remains an open dependency (section 15).

**Residual risk.** A stolen root key lets an attacker mint successor statements that verify against pinned fingerprints; no continuity mechanism can distinguish that from legitimate rotation. Containment is revocation (section 10) and pinning hygiene; propagation is open (section 15). Rotation also does not protect sessions that used the old key before revocation is known (threat model, T12).

## 10. Revocation

**Issue #2 question 5, part two — revocation semantics.** **Proposed.** Revocation keeps the threat model's four scopes distinct (section 5, "Revocation scope"): identity-key revocation, device revocation, grant revocation, session termination. This document specifies mechanics only for identity-key revocation; the others are boundary-checked, not designed.

- **Identity-key revocation (Proposed).** A revocation statement is a domain-separated signed statement naming the identity fingerprint and revoked key fingerprint, signed by a key that outranks the revoked key (the root revokes a successor). Statements append rather than rewrite history, giving verifiers an auditable trail. Because the MVP runs one identity per device (section 12), revoking a compromised device's identity *is* identity-key revocation; removing one of several principal devices needs the multi-device binding model, an open question (section 15).
- **Grant revocation (out of scope).** Withdrawing a scoped authorization belongs to the authorization design (trace SR-3); identity verification results carry no grants.
- **Session termination (out of scope, interface).** Ending live sessions when revocation becomes known is owned by the session design (SR-7); the identity layer supplies the "this key is revoked" signal.
- **Root-key revocation (Proposed, MVP posture).** A compromised root cannot soundly revoke itself: whoever holds the stolen root could authorize or deny anything, so a self-signed revocation proves nothing new. MVP responses are local — deny a locally known bad identity at establishment, plus out-of-band warnings among peers who pinned the fingerprint. A signed root-revocation authority requires a recovery or delegation mechanism, deferred (section 11).

**Distribution and offline peers.** Local enforcement is specified: a locally known revoked identity MUST be denied at session establishment (trace SR-7, M-8), and revocation material must be authenticated whatever channel carries it (trace SR-4). The publication and propagation mechanism — list, status service, signed exchange, or gossip — plus cache freshness is an open question (section 15), mirroring threat model section 10. Offline peers therefore keep trusting a revoked key until they learn otherwise: the threat model's "Revocation latency" residual (section 9), not papered over.

**Scope note (resolved for v1).** M-8 identity-key revocation is **included** in the v1 slice: deny-at-establishment for locally known bad keys, and termination of a live session on locally known revocation, with no propagation, status service, or signed root-revocation authority. This supersedes the earlier conditional wording in the threat model; the local-only posture matches the recommendation originally marked Proposed here.

## 11. Backup and recovery

**Issue #2 question 5, part three — backup and recovery semantics.**

- **Proposed (MVP posture).** The MVP ships no backup and no recovery mechanism. This is deliberate: with no recovery path there is no recovery attack surface — no password database to crack, no social process to social-engine, no secondary credential whose theft yields takeover. The threat model's open question "does recovery preserve identity?" (section 10) therefore stays open and is recorded in section 15; nothing here answers it.
- **Proposed (MVP behavior).** Key material lives only where it was created. Loss of the root key without backup means loss of the identity: the operator creates a new identity and re-verifies with peers out of band — an availability loss, not a silent takeover. Theft means impersonation until revocation: the threat model's T2 residual, contained not prevented.
- **Proposed (requirements for any future mechanism).** Any future recovery design MUST be no weaker than the identity it recovers: no attacker without the legitimate recovery credential may install a successor or root key, first-contact pinning must not be bypassed silently, recovery events must be distinguishable from routine rotation, and the abuse surface documented before adoption. Requirements, not mechanisms.
- **Deferred.** All recovery mechanisms: encrypted backup export, passphrase-protected backups, hardware-backed storage of the root key, multi-party or secret-sharing recovery (Shamir, 1979), social or attested recovery, and password-based recovery on an augmented PAKE such as OPAQUE (RFC 9807). Each carries abuse paths — offline guessing, collusion or coercion, or identity takeover if weaker than first-contact verification — and storage and isolation are open in SR-2, so selection waits on those decisions.

**Residual risk.** Users who never back up lose identities on device failure; users who copy key files manually create theft surface no protocol control covers. Documented honestly rather than solved here.

## 12. Multi-device considerations

**Proposed.** The MVP supports one identity per key-holding instance: laptop, phone, service host, and agent runtime each hold their own identity with its own root key, associated with one principal only through out-of-band records (contact records, authorization policy — mechanism open, section 15). This is the smallest model consistent with the threat model's statement that user, device, service, and agent identity relationships are undefined (section 4), keeping the identity layer free of a principal-binding scheme.

- **Proposed.** Delegation is not an identity-layer feature in the MVP: a device identity authenticates itself and nothing else, while applications and agents receive explicit scoped authority from authorization and must not inherit keys or grants (trace SR-10).
- **Proposed.** Because identities are independent records, any future aggregation scheme — delegation statements, Matrix-style cross-signing, or MLS groups (RFC 9420) — layers on without changing the identity format, fingerprint, or lifecycle rules, which is why per-device identities are safe to choose now.
- **Open question (recorded in section 15):** which aggregation or delegation mechanism, if any, Open UPP should adopt, including how a compromised device is removed from a principal's set. This document does not answer it.

**Residual risk.** Without aggregation, "remove one device of many" is just revoking that device's identity, and no cryptographic statement yet says "these identities belong to one principal." That absence is visibility, not a vulnerability: nothing in the MVP trusts sibling devices.

## 13. Threat analysis and mitigations

Each entry pairs a mitigation with its residual risk (draft threat-model identifiers).

- **Identity substitution (T1).** *Mitigation:* full-digest comparison, out-of-band safety numbers at first contact, pinning of fingerprint plus last verified key, continuity chains from pinned root to current key, and no authentication from truncated fingerprints or display names. *Residual:* users can approve the wrong identity under social engineering, and unverified first contact stays attackable (T1 residual).
- **Man-in-the-middle (T4).** *Mitigation:* mutual possession proofs over fresh transcript data, transcript binding of identity and negotiated suites (M-2, M-7), and safety numbers binding both root keys out of band. *Residual:* a transport-terminating relay sits in the middle by design; where protection terminates and what a relay can read are open (T4, section 10).
- **Replay (T3).** *Mitigation:* identity material alone establishes nothing — every acceptance binds fresh session challenge data (INV-1) — continuity statements are domain-separated and identity-bound, and pinned state makes stale records fail. *Residual:* replay rejection depends on the session design's freshness mechanism, open (T3, section 10).
- **Stolen or compromised private keys (T2).** *Mitigation:* sign-only identity keys, distinct session and transport classes, root-signed revocation of compromised successors, local deny for known-bad keys, no secrets in logs (M-10). *Residual:* a stolen root key is total identity takeover until peers learn of it; detection is not guaranteed; it has no signed revocation authority in the MVP (sections 10-11).
- **Malicious discovery providers (T6).** *Mitigation:* records are verified against pinned fingerprints and possession, never against the discovery result; discovery may point at an identity but never define it (**Accepted** architecture position). *Residual:* providers can return stale or wrong endpoints, eclipse queries, or publish false revocation, misleading a user who never verifies out of band (SR-4).
- **Malicious relay operators (T7, T10).** *Mitigation:* no identity field or fingerprint depends on transport or relay identifiers; identity keys are never exposed to the transport layer; protection must not rely on transport identity (SR-5); a relayed connection is never identity evidence. *Residual:* relays observe metadata and can deny or delay service; the end-to-end termination question is open; no anonymity is claimed (T7, T9).
- **Sybil attacks (T14).** *Mitigation:* identity creation is intentionally cheap and authority-free — no Sybil resistance claimed; fake identities gain nothing without an explicit grant (deny-by-default, M-3); quotas belong to discovery and resource bounds (SR-8). *Residual:* cheap identities can pollute discovery and consume quotas; no uniqueness mechanism exists (T14 residual).
- **Downgrade attacks (T11).** *Mitigation:* suite identifiers live inside signed identity material and must be transcript-bound by the session design (M-7, SR-6); fingerprints commit to the root suite; verifiers reject unknown suites and critical statement types rather than falling back. *Residual:* version policy and cross-protocol isolation are open (threat model section 10); downgrade resistance cannot be guaranteed here alone.
- **Revocation propagation and offline peers (T12).** *Mitigation:* local deny at session establishment for locally known revoked keys (SR-7, M-8), append-only signed revocation statements with outranking signatures, and authenticated revocation on every channel (SR-4). *Residual:* distribution is open (section 15); offline peers keep trusting revoked keys until contact; cache freshness undefined.
- **Recovery abuse and unauthorized identity takeover.** *Mitigation:* no recovery mechanism exists in the MVP, so the takeover path does not exist; any future mechanism must satisfy section 11's strength requirements first. *Residual:* key loss becomes identity loss, manual key copying creates unprotected theft surface, and future recovery reintroduces takeover risk to be re-analyzed (threat model, sections 9-10).

## 14. Alternatives considered

- **Ed25519-only identity format.** Simplest interop, no registry; but any future algorithm change becomes an identity migration for every peer, because the fingerprint commits to a hard-wired suite. Not adopted: post-quantum policy is open, and the registry with an Ed25519 default is nearly as simple (**Proposed**, section 5).
- **X.509 mutual TLS PKI (RFC 5280).** Mature and audited, with revocation and path validation; but it needs certificate authorities as trust anchors, colliding with the no-mandatory-PKI non-goal, and TLS endpoint authentication would not establish UPP identity binding (threat model, "challenged assumptions"). Not adopted; UPP over TLS keeps its own identity semantics.
- **W3C Decentralized Identifiers (DID Core 1.0, Recommendation 2022).** Portable identifiers with resolvable documents; but practical methods need a resolver, ledger, or registry — infrastructure overlapping the global-directory non-goal — and the method landscape fragments interoperability. Not adopted; UPP fingerprints are self-contained.
- **Trust on first use alone.** Zero effort; but an active first-session attacker succeeds silently. Not adopted as default; only as an explicitly marked degraded mode with change alerts (section 7).
- **Key transparency logs (CONIKS, USENIX Security 2015; Certificate Transparency style, RFC 9162).** Signed logs with monitors make directory-style key substitution detectable at scale, the strongest known answer; but they need log infrastructure and monitoring clients — a quasi-directory — solving a problem pairwise first contact does not have. Not adopted; compatible with a future limited-deployment trust anchor (section 15).
- **RPKI-style resource certificates (RFC 6480, RFC 6482).** Clean hierarchy of signed authorizations; but it is built for route origin authorization with registry operators as trust anchors. Not adopted; prior art for scoped signed authorizations.
- **Blockchain or consensus-anchored identity.** Public verifiability; but global state, per-operation cost, and on-chain graph leakage buy a property Open UPP does not require. Not adopted.
- **Hardware-only models (W3C WebAuthn Level 3, Recommendation 2026).** Strong key protection and attestation; but services and servers often lack a suitable authenticator, and vendor binding would leak into the identity format. Not adopted as the identity definition; hardware-backed storage stays a candidate for the open storage question.
- **Hash-of-key peer identifiers (libp2p-style peer IDs).** Elegant: the identifier is a hash of the public key; but any key rotation changes it, conflicting with SR-2 continuity and making identity migration routine. Not adopted; the root-anchored fingerprint stays stable under rotation.
- **Coordination-server identities (Tailscale-style node keys).** A coordination service maps device keys to an account; but the operator becomes an identity authority, conflicting with the no-mandatory-provider non-goal. Research input for Issue #4, not an identity model.
- **Multi-device delegation schemes (Matrix cross-signing; MLS groups, RFC 9420).** Real solutions for one principal with many devices; but both assume a principal-device binding model Open UPP has not defined (threat model, section 4). Not adopted for MVP; a compatible future path for section 15's open question.

## 15. Open questions

Genuinely undecided unless marked resolved; nothing elsewhere answers the open entries, and other sections cross-reference them.

- **Resolved for v1 (previously: canonical encoding framework).** The v1 encoding is frozen in the [Protocol v1 specification](protocol-v1.md): a fixed tag registry (identity fingerprint bytes unchanged), the existing deterministic fixed-field encoding retained for identity statements, and `CANON-1` length-prefixed encoding for new wire records. Golden byte vectors are defined in the W7 tests (`spec/spec_w7_test.go`, `identity/identity_w7_test.go`, `verify/verify_w7_test.go`); cross-language interoperability remains Stage 5.
- **Open question: revocation publication and propagation.** What mechanism carries revocation — list, status service, signed exchange, or gossip — and how cache freshness, offline behavior, and false-revocation resistance work. Mirrors threat model section 10; post-MVP per SR-7.
- **Open question: does recovery preserve identity?** Verbatim from threat model section 10. Section 11 defers all mechanisms and states only requirements, so the answer is untouched here.
- **Open question: multi-device and principal binding.** Whether Open UPP will support statements binding several device identities to one principal, how a compromised device is removed from a principal's set, and whether delegation, cross-signing, or nothing is the model.
- **Open question: agent delegation and attribution.** How an agent authenticates, how authority is scoped and revoked, and how actions are attributed (threat model, section 10); section 12 notes only that an agent may hold an identity.
- **Open question: deployment trust anchors.** Whether a deployment may use organizational, provider-based, transparency-based, or local-directory anchors beyond pairwise out-of-band verification, and each failure mode (threat model, section 10 "Trust anchors"); section 7 selects none.
- **Open question: post-quantum policy.** When, if ever, post-quantum suites become required, and on what timeline (threat model, section 10); section 5 defers PQ suites and fixes the migration path, not the policy.
- **Open question: identity key storage and isolation.** Where and how root and successor keys are stored, how key use is mediated per application, and whether hardware backing is required (SR-2 marks storage and isolation open); section 11 defers mechanisms.
- **External open dependencies.** Handshake and transcript binding mechanics, clock and freshness behavior, end-to-end termination through relays, discovery record authenticity, and protocol versioning remain open in threat model section 10 or in Issues #3 and #4; this document specifies contracts, not solutions.

## 16. MVP recommendations

**In scope for the MVP (Proposed).** Local root key generation (Ed25519) with a self-binding statement, no registration; section 6 fingerprint rules with golden byte vectors defined in the W7 tests; the first-contact flow (in-band exchange, out-of-band safety numbers, pinning, unverified status otherwise) with documented risk (M-12); sign-only identity keys distinct from session and transport keys (M-1, SR-2); rotation via both-signed successor statements with stable fingerprints and explicit confirmation on root replacement; identity-layer revocation with local deny at establishment and local live-session termination (M-8 included for v1, no propagation); and negative tests for substitution, replay without possession, broken chains, truncated-fingerprint acceptance, and log leakage (M-13, M-10).

**Explicitly out of scope for the MVP.**

- Everything excluded in section 1; its no-global-directory, no-mandatory-identity-provider, and no-production-PKI items are **Accepted** non-goals from [ROADMAP.md](../../ROADMAP.md) and the root README.
- **Proposed.** Backup and recovery (section 11), multi-device aggregation (section 12), key transparency (section 14), and revocation propagation beyond local knowledge (section 10).
- **Deferred.** Post-quantum suites (section 5).

**Testable invariants.** Each is labeled or names its dependency.

- **INV-1 (Proposed; mechanism owned by the session design).** A peer MUST NOT be treated as authenticated unless the transcript binds the claimed root key and suite, the current key, negotiated suites and versions, and fresh handshake data.
- **INV-2 (Proposed).** Routine successor rotation MUST NOT change the identity fingerprint; a root replacement MUST surface the fingerprint change and MUST NOT be accepted without explicit MVP confirmation.
- **INV-3 (Proposed).** Every authenticated session MUST carry a continuity chain verifying from the presented root key to the presented current key, with both signatures valid under their stated domain separations.
- **INV-4 (Proposed).** Trust decisions MUST use the full fingerprint digest; a truncated fingerprint MUST NOT be the sole basis for authentication or trust.
- **INV-5 (Proposed).** Where out-of-band verification has not occurred, the peer MUST be presented as unverified and MUST NOT be counted as verified.
- **INV-6 (Proposed).** Identity keys MUST NOT be used for encryption or session key derivation, and session or transport keys MUST NOT sign identity statements (SR-2, M-1).
- **INV-7 (included for v1, local only; session design owns live termination).** A locally known revoked identity key MUST be denied at session establishment, and a live session MUST be terminated on locally known revocation. No propagation, remote status service, or signed root-revocation authority is required or claimed.
- **INV-8 (Proposed).** An identity fingerprint MUST be computable from the anchor alone and MUST NOT change when IP address, interface, endpoint, relay, or transport backend changes.
- **INV-9 (Proposed, restating an Accepted principle as a test).** Identity verification MUST NOT grant authorization; no code path may derive an allow decision from fingerprint equality or key possession alone.
- **INV-10 (dependency: the v1 encoding decision, section 15; see the [Protocol v1 specification](protocol-v1.md)).** Each identity statement MUST have exactly one canonical encoding, and cross-implementation test vectors MUST demonstrate identical fingerprints and verification results. The v1 decision keeps the existing identity-statement encoding and uses `CANON-1` for new wire records; the golden vectors are defined in the W7 tests (`spec/spec_w7_test.go`, `identity/identity_w7_test.go`, `verify/verify_w7_test.go`).

**Migration considerations.**

- *Algorithm migration:* new suites enter the registry; successors under a new suite preserve fingerprints; only root replacement changes a fingerprint and requires confirmation. Hybrid classical-plus-PQ suites fit as future registry entries without a format break.
- *Post-quantum timeline:* NIST IR 8547 (final, October 2026) deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them after 2035 under NIST standards, so the successor-key path must exist before then, though project policy is open (section 15).
- *Format versioning and stability:* the format version is signed inside statements and verifiers reject versions they cannot parse; fingerprints stay stable across suite additions, format versions, and routine rotation because they commit only to the domain-separated root key — the compatibility promise peers may rely on. Rules for unknown fields belong to the future specification (section 15).
- *No compatibility claim yet:* per the root README, no implementation may claim UPP compatibility until a versioned specification and conformance tests exist; the merged local identity prototype makes no such claim, and this document is design input, not that specification.

## 17. References

Primary specifications and research consulted. Citing a reference does not mean Open UPP implements it: these are background references, and nothing is adopted until a later specification says so.

- **[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), Edwards-Curve Digital Signature Algorithm (EdDSA).** Ed25519 and Ed448 with canonical key encodings; the proposed default suite.
- **[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html), The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol.** Hides the password from the server even during registration; resists precomputation attacks on server compromise; future password-recovery candidate.
- **[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), The Messaging Layer Security (MLS) Protocol.** Group key agreement; considered for future multi-device work, not selected.
- **[draft-irtf-cfrg-bls-signature-07](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/), BLS Signatures (IRTF CFRG draft, not an RFC).** Aggregating signatures; evaluated, not adopted. Note: RFC 9381 is Verifiable Random Functions, not BLS.
- **[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final), Digital Signature Standard (NIST, February 2023).** Approves ECDSA and EdDSA for FIPS deployments.
- **[SP 800-186](https://csrc.nist.gov/pubs/sp/800/186/final), Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters (NIST, February 2023).** Curve parameters cited in the section 5 table.
- **[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), Module-Lattice-Based Digital Signature Standard (ML-DSA) (NIST, final August 2024).** Standardized CRYSTALS-Dilithium; deferred post-quantum option.
- **[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), Stateless Hash-Based Digital Signature Standard (SLH-DSA) (NIST, final August 2024).** Standardized SPHINCS+; conservative deferred option.
- **[NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final), Transition to Post-Quantum Cryptography Standards (NIST, final October 2026).** Deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them after 2035 under NIST standards; sets no project policy.
- **[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/final), Secure Hash Standard (NIST).** SHA-256, the proposed fingerprint hash.
- **[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html), Deterministic Usage of DSA and ECDSA.** Deterministic nonces; cited for the ECDSA trade-off.
- **[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), The Base16, Base32, and Base64 Data Encodings.** Base32 alphabet for fingerprint display.
- **[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), Internet X.509 Public Key Infrastructure Certificate and CRL Profile.** The X.509/mTLS PKI alternative.
- **[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html), Certificate Transparency Version 2.0.** Signed logs with monitors; prior art for key transparency.
- **[RFC 6480](https://www.rfc-editor.org/rfc/rfc6480.html), An Infrastructure to Support Secure Internet Routing**, and **[RFC 6482](https://www.rfc-editor.org/rfc/rfc6482.html), A Profile for Route Origin Authorizations (ROAs).** RPKI-style hierarchical authorization; evaluated, not adopted.
- **[W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did/), W3C Recommendation (2022).** Decentralized identifiers; evaluated, not adopted.
- **[W3C Web Authentication (WebAuthn) Level 3](https://www.w3.org/TR/webauthn-3/), W3C Recommendation (2026).** Hardware-backed credentials; a storage-model candidate, not the identity definition.
- **[CONIKS: Bringing Key Transparency to End Users](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/melara), USENIX Security 2015 (Melara, Blankstein, Bonneau, Felten, Freedman).** Key transparency prior art for section 14.
- **[Signal safety number updates](https://signal.org/blog/safety-number-updates/).** Pairwise numeric fingerprints and QR comparison; basis of the section 7 model (key material, not real-world identity).
- **[libp2p specifications](https://github.com/libp2p/specs), peer IDs.** Hash-of-key identifiers; alternative model.
- **[How Tailscale works](https://tailscale.com/blog/how-tailscale-works/).** Coordination-server node keys; an alternative model.
- **[Matrix client-server specification](https://spec.matrix.org/), cross-signing.** Multi-device signing patterns (section 14).
- **SECG SEC 2 v2.0, Recommended Elliptic Curve Domain Parameters (Certicom/SECG, 2010).** secp256k1 parameters; no IETF or NIST identity profile.
- **Shamir, "How to Share a Secret," Communications of the ACM 22(11), 1979.** Secret sharing; recovery candidate, not adopted.
- **[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html).** Requirement levels and security-considerations methodology, as in the threat model.
