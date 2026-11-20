# Reviewer report — Issue #2 identity & key lifecycle design (T3)

**Status:** [DONE] Review complete, report written. [PENDING] Builder fixes for the two blocking/major findings. [BLOCKED] none.

## TL;DR

- **Verdict: ACCEPT WITH CHANGES.** The design is substantively sound: all 17 required sections exist in order, all six Issue #2 questions are answered, all ten threats carry mitigation + residual, the model is internally coherent with the threat model, and no scope creep or file contamination exists.
- **Defect count: 2 blocking/major (must fix before commit), 5 factual/citation minors (should fix in same change), 5 phrasing/convention minors (follow-up OK).**
- BLOCKING: line 296 labels this document's own MVP exclusions as "**Accepted** non-goals from ROADMAP.md" — ROADMAP does not list them, and it contradicts the doc's own legend claim (line 12) and its own Proposed/Deferred labels (lines 113, 232, 241).
- MAJOR: line 131's fingerprint display rule is self-contradictory — "RFC 4648 alphabet A-Z and 2-7" **includes** letters I and O (RFC 4648 Table 3), yet the same sentence claims the form "excludes 0, O, 1, I, and 9". This is the normative answer to Issue question 3.
- Everything else checked out against primary sources: RFC 8032/9807/9381/6482/4648, NIST IR 8547 final (Oct 2026), FIPS 204/205, WebAuthn L3 Rec (Aug 2026), draft-irtf-cfrg-bls-signature-07 all verified; no standard is implied to be implemented.

---

## Step 1: Completeness and structure — [PASS]

- Exactly one H1 (`docs/architecture/identity-and-key-lifecycle.md:1`), 17 H2 sections numbered 1–17 and in the required order (`grep '^## '` → lines 14, 29, 42, 63, 100, 125, 142, 175, 185, 215, 228, 239, 249, 264, 278, 292, 318), zero H3+.
- All six Issue questions explicitly marked and answered: Q1 line 92, Q2 line 102, Q3 line 129, Q4 line 117, Q5 parts one/two/three lines 187/217/230, Q6 line 165 (8 markers, matches the architect's claim).
- Ten threats in §13 (lines 253–262): `grep -c '*Mitigation:*'` = 10, `grep -c '*Residual:*'` = 10 — every required threat present with both parts.
- Migration considerations present (lines 311–316); alternatives considered present (§14, lines 266–276, 11 entries); testable invariants INV-1…INV-10 present (lines 300–309), each labeled or naming its dependency (line 298).
- Word count `wc -w` = 6,998, matches the architect's claim.

## Step 2: Decision-label discipline — [FAIL]

- Legend present (lines 5–12); no line carries two labels (verified by regex); all "Open question" labels are in §15 or marked "(recorded in section 15)" (lines 173, 245); no buried answer contradicts §15 (checked each of the 9 entries against §5–§12); no settled-fact phrasing ("Open UPP uses…") anywhere — §17 explicitly disclaims implementation (line 320).
- **However:** finding **F1 (BLOCKING)** below — a new design choice is labeled Accepted and misattributed to ROADMAP, contradicting line 12 ("No new choice here is labeled **Accepted**") and the doc's own Proposed/Deferred labels for the same decisions.
- Accepted usage audit of the other 13 occurrences (lines 22, 23, 24, 52, 56, 57, 58, 90, 177, 178, 179, 257): all trace to merged documents (architecture README, root README, protocol README, security README, threat model — all tracked/merged). Lines 23 and 56 have citation-precision problems (F9) but the underlying positions are genuinely established.

## Step 3: Non-contradiction with `docs/security/threat-model.md` — [PASS]

Checked each constraint; no contradictions found:

- No mandatory central identity provider / no global directory / no production PKI claim (lines 18, 56; X.509 PKI explicitly rejected at line 267 for exactly this reason).
- No anonymity/metadata claim (line 27 non-claims; line 258 residual "no anonymity is claimed").
- Discovery stays untrusted (lines 57, 179); identity ≠ authorization (lines 23, 177, 180, INV-9 line 308); transport independence (lines 22, 90, 117); long-term vs ephemeral separation (lines 38, 117, INV-6 line 305).
- Revocation taxonomy keeps the threat model's four scopes distinct (line 217) and honors M-8's conditional Stage-4 status (lines 226, INV-7 line 306) — matches threat-model lines 111 and 230.
- Residuals not silently eliminated: first contact (lines 167, 253), revocation latency/offline peers (lines 224, 261), metadata (lines 27, 258), recovery abuse (line 262), Sybil (line 259), stolen root (lines 213, 256).
- Presenting Ed25519 as **Proposed** does not contradict threat-model §10 ("no algorithm selected… must not be silently chosen"): the proposal is labeled, not settled — that is the deliverable's purpose.
- One citation error, not a contradiction: **F3** (line 217 cites "section 10, 'Revocation scope'" — that text is in threat-model **section 5**, line 111).

## Step 4: Technical and standards accuracy — [FAIL]

Primary sources fetched and compared (RFC Editor, NIST, W3C, IETF datatracker). Findings:

**F2 (MAJOR) — base32 exclusion claim is false and self-contradictory.** `docs/architecture/identity-and-key-lifecycle.md:131` states the display form is "RFC 4648 alphabet A-Z and 2-7" and then "It excludes 0, O, 1, I, and 9". RFC 4648 Table 3 (verified verbatim) is `A–Z 2 3 4 5 6 7` — it **includes** I (value 8) and O (value 14); the characters actually absent are digits **0, 1, 8, 9** (8 is not even listed). This is the normative display rule for Issue question 3; as written it is internally contradictory and factually wrong. *Why it matters:* a spec writer could implement either reading; also the stated rationale ("removing the commonest transcription confusions") only holds because digits 0/1/8/9 are absent, not because O/I are. *Correction:* restate as e.g. "RFC 4648 base32 (A–Z, 2–7, no padding); the digits 0, 1, 8, and 9 are absent from the alphabet, so letter–digit confusions such as O/0 and I/1 cannot arise" — or, if I/O must be dropped, declare a named variant alphabet and stop calling it "RFC 4648 alphabet".

**Facts verified correct (no finding):**

| Identifier | Correct? | Relevance accurate? | Implementation implied? |
|---|---|---|---|
| RFC 8032 (EdDSA; §5.1.2 =32-octet point encoding) | yes | yes — §5.1.2 "Encoding" defines the 32-octet encoding cited at line 129; cross-checked against RFC 9381's own citation of 8032 §5.1.2 | no (§17 disclaimer, line 320) |
| RFC 9807 OPAQUE (July 2025) | yes | mostly — but see F5 (gloss overstates) | no (Deferred, line 235) |
| RFC 9420 MLS | yes | yes — "considered, not selected" (lines 244, 276, 324) | no |
| draft-irtf-cfrg-bls-signature-07 | yes — current version (last updated 2026-07-06, datatracker) | yes — "not an RFC" note correct; RFC 9381 = VRFs verified (correcting the brief's "BLS RFC 9381"); sizes 48/96 B and rogue-key/PoP claim match draft §1.1/§3.3 | no |
| FIPS 186-5 (Feb 2023) approves EdDSA | yes | yes | no |
| FIPS 204 / 205 (final Aug 2024) | yes | yes — see F6 on SLH-DSA size range | no (Deferred) |
| NIST IR 8547 final October 2026 | yes (published 10/27/26) | yes — final PDF states verbatim "deprecate quantum-vulnerable public-key cryptography after 2030 and disallow its use under NIST standards and guidelines after 2035" (lines 123, 314, 329 accurate) | no (explicitly "sets no project policy", line 329) |
| FIPS 180-4 SHA-256 | yes | yes | no |
| RFC 6979, RFC 4648, RFC 5280, RFC 9162, RFC 6480, RFC 2119/3552 | yes | yes | no |
| RFC 6482 | identifier yes, **title wrong — F4** | n/a | no |
| W3C DID Core 1.0 Rec 2022 | yes | yes | no |
| W3C WebAuthn Level 3 Rec (2026) | yes — Recommendation dated 25 Aug 2026 | yes ("storage-model candidate") | no |
| CONIKS (USENIX Sec 2015), Signal safety numbers, libp2p peer IDs, Tailscale, Matrix cross-signing, SEC 2 v2.0 (2010), Shamir CACM 22(11) 1979 | yes | yes (hash-of-key peer-ID rotation critique at line 274 is accurate) | no |
| SP 800-186 | exists, correct | cited only in the §5 table (line 110) but **absent from §17 — F7** | no |

**Soundness of the model (checked, no defect found):** fingerprint stability under rotation holds because fp commits to K0 only (lines 82, 194); suite is inside signed material and inside the fingerprint, and unknown suites are rejected (lines 102, 260) — cross-algorithm confusion addressed; possession proofs are bound to fresh transcript data with mechanism delegated to the session design as an explicit interface dependency (lines 61, 146, INV-1); both-signed successor statements block enrolling a key an attacker does not control (line 187) and the stolen-root residual is stated (line 213); first contact requires an out-of-band channel *explicitly* assumed attacker-free (line 146) with residual stated (line 167) — it does not silently trust the in-band channel (line 144–165, unverified-by-default, TOFU only as marked degraded mode); revocation propagation is honestly left open with local deny as the MVP mechanism (lines 224, 261); MVP ships no recovery so no recovery takeover vector exists, with strength requirements for any future mechanism (lines 232–235); per-device identities keep delegation out of the identity layer, coherent with identity ≠ authorization (lines 241–243). Invariants INV-1…INV-10 are testable (tied to M-13 negative tests, line 294) and each names its dependency (INV-7 ↔ M-8, INV-10 ↔ encoding open question). Algorithm trade-offs argue standardization/sizes/pitfalls/migration, not popularity (lines 104–115).

## Step 5: Unsupported claims and scope creep — [PASS with notes]

- No claim that protection is implemented; line 316 explicitly claims no compatibility; §17 header disclaims implementation.
- Authentication/authorization/discovery/transport are kept separate (§8, lines 177–183); public-key possession explicitly grants nothing (line 177, INV-9); no Tailcat-specific dependency (only "optional adapter", lines 58, 275).
- No discovery/relay/handshake/wire-format design: diagrams marked "Logical structure, not a wire format" (lines 88, 203); statement encoding, transcript mechanics, propagation, and trust anchors are deferred to §15/other issues (lines 61, 282–290).
- Note (not a defect): line 24 "Only established primitives are **used**" is present tense in a repo with no implementation (see F8).

## Step 6: Conventions and repo scope — [PASS with notes]

- One H1 ✓; no H3 ✓; no front matter ✓; no TODO/TBD/FIXME ✓; no British spellings ✓; no "OpenUPP/Open-UPP" variants ✓; 3 diagrams all in balanced ```text fences (lines 67/86, 148/161, 189/201) ✓; no secrets ✓; "Open UPP" spelling ✓; all 6 unique relative links resolve (verified by script) ✓.
- Deviations: markdown table at lines 106–113 where no existing tracked doc uses tables (observed convention, not a written rule — F11); 12 MUST usages without the threat model's RFC 2119 normative-terms note (F12).
- Scope: `git status --short` → only `?? .opencode/` and `?? docs/architecture/identity-and-key-lifecycle.md`; HEAD = `1e41417 docs: add Open UPP threat model` — nothing committed, no other file touched, threat model and READMEs unmodified. ✓

---

## Findings

### BLOCKING

**F1 — A new design choice is labeled Accepted and misattributed to ROADMAP.**
- Severity: BLOCKING
- Evidence: `docs/architecture/identity-and-key-lifecycle.md:296` — "…plus backup and recovery, multi-device aggregation, key transparency logs, post-quantum suites, and revocation propagation beyond local knowledge (**Accepted** non-goals from [ROADMAP.md](../../ROADMAP.md))."
- Problem: ROADMAP's "Not in the initial MVP" list (ROADMAP.md:50–56) contains only: global public-key directory, mandatory identity provider, production-grade decentralized PKI, public-Internet replacement, anonymity claim, production VPN. It does **not** list backup/recovery, multi-device aggregation, key transparency logs, PQ suites, or revocation propagation. Those are this document's own positions — labeled **Proposed** at line 232 (no recovery), **Proposed** at line 241 (one identity per instance), **Deferred** at line 123 (PQ suites), **Not adopted** at line 270 (key transparency) — and line 12 explicitly claims "No new choice here is labeled **Accepted**." Line 296 makes that claim false and violates Issue #2's rule that Accepted is reserved for merged-repo positions.
- Why it matters: readers/reviewers would treat unreviewed MVP scope decisions as settled project direction; it also conflicts with the label legend itself (line 8).
- Correction: split the sentence — keep "**Accepted** non-goals from ROADMAP" only for the directory/provider/PKI items (which are genuinely in ROADMAP and in §1 line 18), and relabel the remaining exclusions "Proposed (MVP scope), consistent with sections 5, 11, 12, 14" (or "Deferred" for PQ suites, matching line 123).

### MAJOR

**F2 — Fingerprint display alphabet contradicts its own RFC citation.**
- Severity: MAJOR (must fix before commit — correctness of the Issue-question-3 answer)
- Evidence: line 131 — "Uppercase base32 (RFC 4648 alphabet A-Z and 2-7, no padding)… It excludes 0, O, 1, I, and 9".
- Problem: RFC 4648 Table 3 (verified at rfc-editor.org/rfc/rfc4648.txt) is A–Z plus 2–7: letters **I and O are in the alphabet**; the excluded characters are digits 0, 1, 8, 9 (8 unmentioned). The two sentences cannot both be true.
- Why it matters: this is the normative display rule for fingerprint comparison; ambiguity or error here propagates into the Stage 2 specification and test vectors, and the "transcription confusion" rationale is stated incorrectly.
- Correction: either (a) keep RFC 4648 base32 and rewrite as "the digits 0, 1, 8, and 9 do not occur, so digit/letter confusions (0/O, 1/I) cannot arise within a fingerprint", or (b) if I and O are to be removed, define an explicit variant alphabet (and cite it as a project variant, not "RFC 4648 alphabet"). Also decide and state the handling of the RFC's noted input-side leniency (RFC 4648 §3.4 notes decoders may map 0→O, 1→I/L — the doc's comparison rules at line 132 should say strict-character-set rejection).

### MINOR — factual / citation (fix in the same change; all one-liners)

**F3 — Wrong threat-model section citation.** Line 217: `(section 10, "Revocation scope")`. The "Revocation scope" text is in threat-model **section 5** (threat-model.md:111), not section 10 (which has no such heading; its revocation bullet is "Revocation and recovery", line 209). Correction: cite section 5. *Why it matters:* reviewers tracing the four-scope taxonomy will not find it where told.

**F4 — RFC 6482 title misquoted.** Line 335: "A Profile for Resource Certificate Route Authorizations (ROAs)". Actual title (rfc-editor): "A Profile for **Route Origin** Authorizations (ROAs)". Correction: use the exact title. (RFC 6480's title on the same line is correct.)

**F5 — OPAQUE gloss overstates the RFC.** Line 323: "Server-learn-nothing password key exchange". RFC 9807's abstract says OPAQUE hides the password from the server *including during registration* and resists **precomputation** attacks on server compromise — but its introduction states offline dictionary attacks on a leaked credential file are "inevitable" for aPAKEs. "Server-learn-nothing" reads as a stronger guarantee than the RFC claims. Correction: "hides the password from the server during registration and use; resists precomputation attacks upon server-file compromise" (or simply "augmented PAKE; candidate for future password-based recovery").

**F6 — SLH-DSA signature-size range understated / inconsistently scoped.** Line 113: "7.8-17 KB signatures". That range covers only the 128-bit parameter sets (7,856–17,088 B); FIPS 205 sizes run to 49,856 B (SHA2-256f). The ML-DSA figures on the same row (2.4–4.6 KB) span all security levels, so the two halves of the cell use different scopes. Correction: either add "128-bit level" to the SLH-DSA figure (as the BLS row does at line 112) or widen to "7.8–49.9 KB". (ML-DSA 1.3–2.6 KB keys and 2.4–4.6 KB signatures are correct as written.)

**F7 — §17 does not contain everything §5 says it verifies.** Line 104: "standardization status is verified in section 17", but **SP 800-186** (cited in the table at line 110) has no §17 entry. Correction: add an SP 800-186 reference bullet to §17 or drop it from the table.

### MINOR — phrasing / convention (follow-up acceptable)

**F8 — Present-tense implementation claim.** Line 24: "**Accepted.** Only established primitives **are used**" — no implementation exists (threat model: "No security property is implemented"). Correction: "must be used" / "are to be used". Same class: line 257's "records are verified…" is standard design-prose and acceptable, but line 24 is stated as a project fact.

**F9 — Citation attribution imprecision (two places).** Line 23 attributes the quoted phrase "Identity is not authorization" to "root README principle 2" — that string is the **architecture README** heading (docs/architecture/README.md:23); root README principle 2 reads "Authorization is explicit. Knowing a public key must never automatically grant access" (README.md:22). The claim is supported; the attribution conflates two sources. Line 56 attributes "…directory, or production PKI … MVP must not require one" to "root README principle 7" — principle 7 (README.md:27) says only "No mandatory global authority…"; the directory/production-PKI wording comes from threat-model.md:90 and ROADMAP.md:52–54. Correction: cite both sources as line 177 already does.

**F10 — "Fully specified now" overstated.** Line 135: fingerprints are "fully specified now" — but two fingerprint inputs are still open: the domain-separation tag's exact value (line 129: "ships with test vectors") and the suite-identifier encoding/registry values (line 282, §15). Correction: "structure is fixed now and independent of statement serialization; tag value and suite-identifier encoding ship with the Stage 2 test vectors (section 15)."

**F11 — Markdown table vs observed convention.** Lines 106–113 introduce a table; no existing tracked doc uses tables (explorer report §5: lists and bold-lead bullets instead). Not a written rule — flagging as a convention deviation, not a violation. Follow-up: convert to bold-lead bullets or get maintainer sign-off on tables.

**F12 — No normative-terms note for 12 MUST usages.** The threat model carries an explicit RFC 2119 note ("impose no current obligation on this repository", threat-model.md:7); this document uses MUST 12 times (e.g., lines 300–309, 224, 234) with only an indirect §17 reference (line 345). Follow-up: add one sentence to the §1 or §16 preamble mirroring the threat model's note.

---

## Coverage matrix — 17 required sections

| # | Required section | Status | Evidence (line) |
|---|---|---|---|
| 1 | Scope and goals | covered | 14 |
| 2 | Terminology | covered | 29 |
| 3 | Requirements and assumptions | covered | 42 |
| 4 | Identity data model | covered | 63 |
| 5 | Cryptographic choices and rationale | covered | 100 |
| 6 | Creation and fingerprinting | covered (F2 defect in display rule) | 125 |
| 7 | First-contact verification | covered | 142 |
| 8 | Authentication/authorization boundaries | covered | 175 |
| 9 | Key rotation | covered | 185 |
| 10 | Revocation | covered (F3 citation error) | 215 |
| 11 | Backup and recovery | covered | 228 |
| 12 | Multi-device | covered | 239 |
| 13 | Threat analysis and mitigations | covered (10/10 with residual) | 249 |
| 14 | Alternatives considered | covered (11 entries) | 264 |
| 15 | Open questions | covered (9 entries, all elsewhere cross-referenced) | 278 |
| 16 | MVP recommendations | covered (invariants + migration) | 292 |
| 17 | References | covered (F4, F5, F7 defects) | 318 |

## Coverage matrix — six Issue #2 questions

| Q | Question | Status | Evidence (line) |
|---|---|---|---|
| 1 | What does identity represent (device/user/service/application/agent) | covered — one key-holding instance; user → principal; non-authoritative class hint | 92 |
| 2 | Ed25519 vs algorithm-abstracted format | covered — suite registry, Ed25519 default (Proposed) | 102, 121 |
| 3 | Fingerprint encoding/comparison | covered with defect — F2 (base32 exclusion contradiction) | 129–133 |
| 4 | Long-term vs ephemeral session/transport keys | covered — three rules (sign-only, session-owned, transport-never-identity) | 117 |
| 5a | Rotation semantics | covered — both-signed successors, fp stable, root replacement = migration | 187–213 |
| 5b | Revocation semantics | covered — four scopes kept; identity-key mechanics; local deny; propagation open | 217–226 |
| 5c | Backup/recovery semantics | covered — MVP: none (Proposed); future requirements; all mechanisms Deferred | 230–237 |
| 6 | First-contact verification vs key substitution | covered — four cumulative checks, OOB channel assumption explicit, unverified default | 165–173 |

Also present: migration considerations (311–316) ✓; alternatives (264–276) ✓; testable invariants (300–309) ✓.

## Threat coverage matrix — §13 (lines 253–262)

| Threat (required) | Mitigation present | Residual present | Evidence |
|---|---|---|---|
| Identity substitution | yes | yes (social engineering; unverified first contact) | 253 |
| Man-in-the-middle | yes | yes (relay termination by design; E2E open) | 254 |
| Replay | yes | yes (session freshness open) | 255 |
| Stolen/compromised private keys | yes | yes (stolen root = takeover; no signed root revocation in MVP) | 256 |
| Malicious discovery providers | yes | yes (stale/false records; unverified users misled) | 257 |
| Malicious relay operators | yes | yes (metadata, denial; no anonymity claimed) | 258 |
| Sybil | yes | yes (pollution/quota use; no uniqueness mechanism) | 259 |
| Downgrade | yes | yes (version policy open) | 260 |
| Revocation propagation / offline peers | yes | yes (distribution open; offline peers keep trusting) | 261 |
| Recovery abuse / identity takeover | yes | yes (key loss = identity loss; future recovery re-risks) | 262 |

**10/10 mitigation + 10/10 residual — complete.**

## Label-discipline findings

- **Misused Accepted: 1** — line 296 (F1, BLOCKING). All other Accepted occurrences (lines 22–24, 52, 56–58, 90, 177–179, 257) trace to merged documents (positions verified against README.md, docs/architecture/README.md, docs/protocol/README.md, docs/security/README.md).
- **Unlabeled decisions: none found.** Every design choice located carries exactly one label; traces (SR-/M-) are explicitly exempted in the legend (line 12); §13 mitigations derive from labeled §4–§12 decisions.
- **Answer-duplication contradicting §15: none found.** Each of the 9 open questions was checked against the section that references it (§5 PQ policy, §7 trust anchors, §11 recovery, §12 multi-device); none is answered elsewhere.
- **Legend/consistency: pass** except F1 (contradicts line 12). No line holds two labels (regex-verified). Deferred count = 3 decisions + legend (lines 123, 209, 235), matching the architect's report.

## Validation commands run

```
git status --short                      → only ?? .opencode/ and ?? docs/architecture/identity-and-key-lifecycle.md
git log --oneline -3                    → HEAD 1e41417 (threat model); no new commits
grep -n '^# ' / '^#{3,} ' / '^## '     → 1 H1, 0 H3+, 17 H2 in required order
wc -w                                   → 6998 (matches claim)
grep -c '*Mitigation:*' / '*Residual:*' → 10 / 10
grep label regex (two-labels-per-line)  → no matches; Open-question locations → §15 + 2 cross-refs only
link-resolution script (6 unique rel.)  → all OK
grep TODO/TBD/FIXME, British spellings, OpenUPP/Open-UPP → no matches
grep '^```'                             → 6 fences = 3 balanced ```text blocks
grep 'MUST'                             → 12 (no normative-terms note → F12)
```

External verification (read-only fetches): rfc-editor RFC 8032 (TOC §5.1.2 = Encoding), RFC 9807 (title/date/abstract), RFC 9381 (= VRFs), RFC 6480/6482 (titles), RFC 4648 Table 3 (alphabet); csrc.nist.gov IR 8547 final page (Oct 2026) + final PDF text grep ("deprecate … after 2030 … disallow … after 2035"); nist.gov news (2030/2031/2035 timelines); w3.org WebAuthn L3 (Rec, 25 Aug 2026); datatracker draft-irtf-cfrg-bls-signature-07 (current, 2026-07-06).

## What must be fixed before commit vs follow-up

**Must fix before commit (blocking/major):**
1. **F1** — line 296 Accepted misuse/ROADMAP misattribution (also restores the truth of line 12).
2. **F2** — line 131 base32 exclusion contradiction (Issue Q3 normative rule).

**Should fix in the same change (one-line factual/citation fixes):** F3 (wrong section cite), F4 (RFC 6482 title), F5 (OPAQUE gloss), F6 (SLH-DSA size scope), F7 (SP 800-186 missing from §17).

**Acceptable as follow-up:** F8 (present tense), F9 (attribution precision), F10 ("fully specified now"), F11 (table convention), F12 (RFC 2119 note).

No design-level change is required; nothing here touches Issue #3/#4 scope, the threat model, or any other file.

---

## Handoff

- **status:** ACCEPT WITH CHANGES (2 must-fix findings, 5 same-change minors, 5 follow-up minors)
- **objective/problem:** adversarial verification of `docs/architecture/identity-and-key-lifecycle.md` against Issue #2's requirements, the threat model, and primary standards
- **evidence/completed work:** this report; all inputs read (deliverable, architect T2 report, explorer T1 report, threat model, READMEs, ROADMAP, CONTRIBUTING/GOVERNANCE context); primary-source fetches listed above; validation commands listed above
- **affected areas:** `docs/architecture/identity-and-key-lifecycle.md` lines 131, 217, 296 (must/should-fix), plus one-line citation fixes at 232, 23, 56, 323, 335, 113, 104
- **scope/decision boundary:** review only — no files modified other than this report; no design decisions made or altered
- **verification performed:** structure/label/threat/link/spelling audits (commands above), full read of the deliverable and threat model, standards checks against RFC Editor/NIST/W3C/IETF primary sources
- **remaining uncertainty:** none material; every finding above is backed by a fetched primary source or an in-repo citation (F11/F12 rest on observed conventions, flagged as such)
- **recommended next agent:** **Builder** — apply F1–F7 to the deliverable (all within the approved scope of Issue #2); then Orchestrator for re-review/acceptance
- **reason:** the defects are localized, understood, and inside the approved scope; no Architect decision is needed (F1's correction path is dictated by the doc's own legend and ROADMAP's actual non-goal list)

**Changes made by Reviewer:** this report only (`.opencode/reports/identity-issue-2/reviewer-agent-T3-design-review.md`).
