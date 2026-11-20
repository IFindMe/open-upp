# Architect report — Issue #2 peer identity & key lifecycle design (T2)

**Status:** [DONE] Deliverable written and fully self-checked. [PENDING] Reviewer/Orchestrator acceptance of the design. [BLOCKED] none.

## TL;DR

- [DONE] Wrote `docs/architecture/identity-and-key-lifecycle.md`: 1 H1, 17 ordered H2 sections, 0 H3, 6,998 words (target ≤7,000).
- [DONE] All six Issue #2 questions answered (Q5 in three parts), 10 threats each with *Mitigation:* + *Residual:*, 10 testable invariants, 10 alternatives, 9 open questions + external dependencies, 3 ASCII diagrams in ```text fences.
- [DONE] Label discipline: every decision carries exactly one label; no line holds two labels; **Accepted** only for merged-doc positions; all **Open question** labels in §15 or explicitly "(recorded in section 15)".
- [DONE] `git status --short` shows only `?? .opencode/` and `?? docs/architecture/identity-and-key-lifecycle.md`; no branch/commit/push; threat model and all READMEs untouched.
- [NOTE] Brief's citation "BLS (RFC 9381)" is wrong — RFC 9381 is Verifiable Random Functions; BLS is `draft-irtf-cfrg-bls-signature-07` (not an RFC). Documented in §17 references.
- [NOTE] `AGENTS.md` does not exist in the repo; conventions were taken from observed `docs/` files (one H1, H2-only, no front matter, bold-lead bullets, "Open UPP").

## Objective

Produce exactly one design doc answering Issue #2 (what an identity represents; creation, fingerprinting, verification, key separation, rotation, revocation, backup/recovery) plus this single report — without designing discovery (Issue #3), transport/Tailcat (Issue #4), wire formats, or any mandatory directory/PKI/provider, and without claiming anonymity or implementing any external standard.

## Files read (evidence)

- `.opencode/reports/identity-issue-2/explorer-agent-T1-repo-state.md` (repo/threat-model facts)
- `docs/security/threat-model.md` (constraint source; not modified)
- `docs/architecture/README.md`, `docs/security/README.md`, `docs/protocol/README.md`
- `README.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SECURITY.md`, `CHANGELOG.md`
- Web research (below). `AGENTS.md`: absent.

## Research sources with identifiers

RFC 8032 (EdDSA), RFC 6979 (deterministic ECDSA), RFC 4648 (base32), RFC 5280 (X.509), RFC 9162 (Certificate Transparency), RFC 6480/RFC 6482 (RPKI/ROA), RFC 9420 (MLS), RFC 9807 (OPAQUE aPAKE), RFC 2119/RFC 3552 (requirements/security-considerations), RFC 8446/7748/9180 reviewed and dropped as uncited; **draft-irtf-cfrg-bls-signature-07** (BLS, not an RFC — brief's "RFC 9381" pairing corrected); FIPS 180-4, FIPS 186-5, FIPS 204, FIPS 205 (final Aug 2024), NIST IR 8547 (final Oct 2026); SECG SEC 2 v2.0; W3C DID Core 1.0 (Rec 2022); W3C WebAuthn Level 3 (Rec 2026); CONIKS (USENIX Security 2015); Signal safety-number updates; Shamir (CACM 22(11), 1979).

## Decision register

**Proposed (new, all labeled in-doc):** identity = append-only record anchored by root public key K0 (§4); one identity per key-holding instance with non-authoritative class hint (§4); signed record carries no name/role/permission/address/timestamp (§4); algorithm-agile suite registry with Ed25519 (RFC 8032) MVP default (§5); identity keys sign-only, encryption/key-agreement excluded (§5); fingerprint = SHA-256(domain-separation tag || suite || root key octets) with base32 display, full-digest constant-time comparison, display-only truncation (§6); local authority-free creation with self-binding statement, no registration (§6); pairwise safety numbers over identity fingerprints, pinning, unverified-by-default, TOFU only as marked degraded mode (§7); identity layer outputs only authenticated-binding-or-failure, never authorization (§8); rotation via both-signed successor statements; root replacement = "identity migration" requiring explicit MVP confirmation (§9); identity-key revocation statements + local deny at establishment; root-key revocation local-only in MVP (§10); MVP ships no backup/recovery, with stated requirements for any future mechanism (§11); per-device identities, delegation outside the identity layer (§12); MVP scope and INV-1..INV-10 (§16).

**Accepted (merged-doc positions only):** identity-is-not-location and identity-is-not-authorization and five-separate-concerns (architecture notes); no mandatory directory/identity provider/PKI (root README principle 7, ROADMAP non-goals); discovery returns untrusted hints until authenticated (security model); only established primitives (protocol design README); discovery may point at but never define an identity (architecture notes — also used in T6 mitigation); Tailcat optional adapter (architecture notes).

**Deferred:** post-quantum suites ML-DSA/SLH-DSA/hybrids (§5); automatic trust transfer on root replacement (§9); all recovery mechanisms — encrypted/passphrase backups, hardware storage, multi-party/Shamir, social, OPAQUE-based (§11).

**Open questions (§15 only):** canonical encoding framework; revocation publication/propagation; does recovery preserve identity; multi-device/principal binding; agent delegation & attribution; deployment trust anchors; post-quantum policy; identity key storage/isolation; plus external dependencies (handshake/transcript binding, clock/freshness, end-to-end termination through relays, discovery record authenticity, protocol versioning).

## Issue #2 question mapping

| Q | Section | Answer in one line |
|---|---|---|
| Q1 what can an identity represent | §4 | exactly one key-holding entity instance (device/service/application/agent, or undivided principal) + non-authoritative class hint |
| Q2 Ed25519-only or algorithm-abstracted | §5 | abstracted suite registry, Ed25519 (RFC 8032) as MVP default |
| Q3 fingerprint encoding/comparison | §6 | SHA-256(tag‖suite‖root octets), base32 display, full-digest comparison |
| Q4 identity vs session/transport keys | §5 | three rules: sign-only identity keys; ephemeral session keys owned by session design; transport keys never bind UPP identity |
| Q5-1 rotation semantics | §9 | both-signed successor statements; fingerprint stable; root replacement = identity migration with explicit confirmation |
| Q5-2 revocation semantics | §10 | four threat-model scopes kept distinct; identity-key mechanics specified; local deny at establishment |
| Q5-3 backup/recovery semantics | §11 | MVP: none, deliberately; requirements-only for future mechanisms; all mechanisms Deferred |
| Q6 first contact vs key substitution | §7 | four cumulative checks (chain+possession, out-of-band safety number, transcript binding, pinning); unverified-by-default |

## Threat-by-threat mitigation / residual summary (§13)

1. **T1 substitution** — full-digest compare, out-of-band safety numbers, pinning, continuity chains, no truncated-fingerprint auth → residual: social-engineering approval; unverified first contact still attackable.
2. **T4 MITM** — possession over fresh transcript data, transcript binding (M-2/M-7), dual safety numbers → residual: transport-terminating relay is middle by design; end-to-end termination open.
3. **T3 replay** — identity alone establishes nothing (INV-1), domain-separated statements, pinned state → residual: depends on session freshness mechanism; clock/window behavior open.
4. **T2 stolen keys** — sign-only keys, class separation, root-signed revocation, local deny, no secrets in logs (M-10) → residual: stolen root = takeover until peers learn; no signed root-revocation in MVP.
5. **T6 discovery providers** — verify against pins/possession, never the discovery result; discovery points, never defines (**Accepted**) → residual: stale/false endpoints or revocation; DoS or misdirection for non-verifying users.
6. **T7/T10 relays** — no identity field depends on transport/relay identifiers; relayed connection never identity evidence (SR-5) → residual: metadata exposure, denial; no anonymity claimed.
7. **T14 Sybil** — identity creation cheap by design (no Sybil claim), deny-by-default (M-3), quotas owned by discovery (SR-8) → residual: discovery pollution, quota use; no uniqueness mechanism.
8. **T11 downgrade** — suite inside signed material, transcript-bound (M-7/SR-6), reject unknown suites/critical types → residual: version/fallback policy open in threat model §10.
9. **T12 revocation/offline** — local deny at establishment (SR-7/M-8), append-only outranked-signed statements, authenticated channels (SR-4) → residual: distribution open (§15); offline peers trust until contact.
10. **Recovery abuse / takeover** — no recovery path in MVP → residual: key loss = identity loss; manual key copying; future recovery reintroduces takeover risk to re-analyze.

## Self-check evidence (commands run)

- `wc -w` → **6,998** (target ≤7,000; started ~9,400, compressed by section-level cuts).
- `grep '^# '` → 1 H1; `grep -E '^#{3,} '` → 0 H3; `grep '^## '` → 17, numbered 1–17 in order, each preceded by a blank line (awk check).
- Label audit (awk over `\*\*(Proposed|Accepted|Deferred|Open question)\*`): zero lines with ≥2 label tokens; 3 **Deferred** decisions (§5, §9, §11); all **Open question** labels at §15 or with "(recorded in section 15)" (§7, §12); **Accepted** occurrences only in legend/note and merged-doc citations (Goals, Assumptions, independence, T6, out-of-scope).
- Question markers: 8 hits = Q1, Q2, Q3, Q4, Q5-part one/two/three, Q6.
- Threats: 10 bullets with `*Mitigation:*` = 10 and `*Residual:*` = 10.
- Diagrams: 6 fence lines = 3 balanced ```text blocks (§4 identity record, §7 first-contact flow, §9 rotation/root replacement).
- Relative links: all 7 resolve (`README.md`, `../security/threat-model.md`, `../security/README.md`, `../protocol/README.md`, `../../ROADMAP.md`, `../../README.md`, plus the above).
- Hygiene: no TODO/TBD/FIXME; no secret patterns; no "OpenUPP/Open-UPP" variants; no British spellings; no "Open UPP implements <standard>" claim (§17 explicitly disclaims).
- `git status --short` → only `?? .opencode/` and `?? docs/architecture/identity-and-key-lifecycle.md`; HEAD `1e41417` on `docs/threat-model`; no commits made.

## Word count

**6,998** (`wc -w docs/architecture/identity-and-key-lifecycle.md`), within the ~5,000–7,000 target.

## Reviewer risks / notes

1. **Top-of-range length.** 6,998 leaves no headroom: any reviewer-requested addition must be offset by a cut.
2. **Diagram removals during compression.** The §5 key-classes diagram and §12 multi-device diagram were deleted to meet the word cap; their content survives in §5 Q4 prose and §12 bullets. Restoring either costs ~50–75 words over budget.
3. **Brief citation error.** "BLS (RFC 9381)" is incorrect (9381 = VRF); §17 cites `draft-irtf-cfrg-bls-signature-07` and notes the discrepancy — flag if the brief must be corrected elsewhere.
4. **`AGENTS.md` absent** — conventions inferred from existing `docs/` files, not from an agent-instructions file.
5. **Section order vs question order.** Q4 (§5) precedes Q3 (§6) because section topics are semantic (crypto choices → fingerprinting); labels still match Issue #2 numbering.
6. **Traces unlabeled by design.** SR-/M- identifiers are traces, not decisions; a strict "label every bullet" reading would disagree (stated explicitly in the legend).
7. **M-8 contingency.** Identity-key revocation is recommended in MVP but bound to the Stage 4 scope decision; if excluded it moves to post-MVP unchanged (documented in §10 scope note and INV-7).
8. **No wire formats / no encoding choice.** Statement encoding is an open question owned by Stage 2; fingerprints are defined over raw suite key octets so they stay valid regardless (§6 canonical-encoding dependency).

## Handoff

**Status:** DECISION_READY — architecture and implementation scope are fully specified for this document's own content; no Builder handoff is required (deliverable is the doc itself).

**Recommended next agent:** **Reviewer** — independently verify the deliverable against Issue #2's requirements and this report's self-check claims; then **Orchestrator** for acceptance.

**Architect changes:** `docs/architecture/identity-and-key-lifecycle.md` (new) and this report (new). No other file touched.
