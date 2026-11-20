# Architect report — Issue #2 identity design revision (T4)

**Status:** [DONE] All BLOCKING, MAJOR, and F1–F7 findings fixed and source-verified; 4 of 5 follow-ups fixed, F11 deliberately left; self-check re-run green. Report written.

## TL;DR

- **Verdict: all blocking/major/same-change findings resolved in `docs/architecture/identity-and-key-lifecycle.md` only.** F1 (label/ROADMAP misattribution) and F2 (RFC 4648 self-contradiction) are rewritten; F3–F7 corrected against primary sources I fetched myself; F8/F9/F10/F12 fixed as low-risk wording; **F11 left deliberately** (residual disagreement, below).
- Word count **6,997** (≤7,000): fixes added ~130 words, offset by ~130 words of compression across §1–§17.
- Self-check: 1 H1, 0 H3, 17 H2 in order, 8 Issue #2 markers (six questions), 10 threats × (Mitigation + Residual), 10 invariants, 3 `text` diagrams (6 fences), all 6 relative links OK, no TODO/TBD/secrets, no multi-label lines, no new **Accepted**, no new open-question answer, `git status` shows only `.opencode/` and the deliverable.
- Verification performed: RFC 4648, RFC 6482, RFC 9807 (RFC Editor); SP 800-186 (NIST CSRC); FIPS 205 sizes (FIPS 205 Table 11 values via secondary quotes of the table — noted below); ROADMAP.md and threat-model.md read directly.

## Finding-by-finding disposition

### F1 — BLOCKING: §16 mislabels own MVP exclusions as "Accepted non-goals from ROADMAP.md"

- **Action:** Split §16 "Explicitly out of scope" into three one-label lines: ROADMAP-listed items keep **Accepted** (with root README added as source); this document's own exclusions (backup/recovery, multi-device aggregation, key transparency, revocation propagation beyond local knowledge) are labeled **Proposed**; PQ suites labeled **Deferred**. No line carries two label tokens.
- **Evidence:** `identity-and-key-lifecycle.md:297-301`; matches the doc's own §11 **Proposed (MVP posture)** (line 234), §12 **Proposed** (line 242), §5 PQ **Deferred** (line 121).
- **Source verified:** `ROADMAP.md:50-56` — "Not in the initial MVP" lists only directory / identity provider / production PKI / Internet replacement / anonymity / VPN-kernel stack; backup, multi-device, transparency, PQ, revocation propagation are **absent** (confirms reviewer).

### F2 — MAJOR: §6 display rule contradicts RFC 4648

- **Action:** Rewrote the display rule: alphabet is "A-Z plus 2-7" and the digits **0, 1, 8, 9 never occur**, so a 0/O or 1/I confusion resolves to exactly one valid character (no claim that I/O are excluded). Added strict-rejection to comparison rules: characters outside the alphabet are rejected, never mapped (no 0→O / 1→I leniency), citing RFC 4648 §§3.3–3.4.
- **Evidence:** lines 133 (display), 134 (comparison).
- **Source verified:** RFC 4648 full text (rfc-editor.org): Table 3 = A–Z, 2–7 (includes I and O; digits 0, 1, 8, 9 absent); §3.3 "MUST reject" non-alphabet input; §3.4 notes decoders may read 0 as O and 1 as I/L. Reviewer's direction confirmed; my wording states the correct rationale (only one of each confusable pair exists in valid strings).

### F3 — Minor: wrong threat-model section for "Revocation scope"

- **Action:** Citation changed from "section 10" to `(section 5, "Revocation scope")`.
- **Evidence:** line 218.
- **Source verified:** `docs/security/threat-model.md` — last `## ` heading before line 111 is `## 5. Assumptions and out-of-scope risks`; the four-scope paragraph sits there. (§10 holds "Revocation and recovery", a different bullet.)

### F4 — Minor: RFC 6482 title wrong

- **Action:** Title corrected to "A Profile for Route Origin Authorizations (ROAs)".
- **Evidence:** line 341.
- **Source verified:** RFC 6482 header at rfc-editor.org (exact title, February 2012).

### F5 — Minor: OPAQUE gloss imprecise

- **Action:** Gloss changed to "Hides the password from the server even during registration; resists precomputation attacks on server compromise; future password-recovery candidate."
- **Evidence:** line 328.
- **Source verified:** RFC 9807 abstract — "security against pre-computation attacks upon server compromise … the ability to hide the password from the server, even during password registration"; §1 states offline dictionary attacks on server compromise are "inevitable" (so no claim of immunity).

### F6 — Minor: SLH-DSA signature size range understated

- **Action:** Table cell changed `7.8-17 KB` → `7.8-49.9 KB`.
- **Evidence:** line 115.
- **Source verified:** FIPS 205 parameter-set sizes 7,856–49,856 B (SHA2/SHAKE-128s … 256f). NIST FIPS 205 PDF is not fetchable as text here; values confirmed via two independent secondary quotations of FIPS 205's size table (DigiCert, CryptiQ). **Confidence: medium-high** — secondary-sourced, not the PDF itself; range endpoints match the reviewer's reading of FIPS 205 Table 11.

### F7 — Minor: SP 800-186 cited in §5 table but absent from §17

- **Action:** Added §17 entry with exact NIST title and date.
- **Evidence:** line 332 (table cite at line 112).
- **Source verified:** csrc.nist.gov SP 800-186 final page — "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters", February 2023.

### F8 — Follow-up fixed: "Only established primitives are used"

- **Action:** Reworded to "**Accepted.** Established, reviewed primitives only — no invented primitives" (removes unsourced present-tense implementation claim).
- **Evidence:** line 26.
- **Source verified:** `docs/protocol/README.md:26` — "Prefer established, reviewed cryptographic protocols and libraries. Do not invent cryptographic primitives."

### F9 — Follow-up fixed: two misattributions

- **Action:** (a) line 25 now cites architecture notes heading "Identity is not authorization" **and** root README principle 2; (b) line 58 now cites root README principle 7 **plus** threat model section 5 **plus** ROADMAP.
- **Evidence:** lines 25, 58.
- **Source verified:** `docs/architecture/README.md:23` heading; `README.md` principles 2 and 7; `threat-model.md` §5 ("no mandatory global authority, directory, or production PKI; the MVP must not require one"); `ROADMAP.md:50-54`.

### F10 — Follow-up fixed: "fully specified now"

- **Action:** Now: "their structure is fixed now …; the tag value and suite-identifier encoding ship with the Stage 2 test vectors (section 15)." No open question answered — §15's canonical-encoding-framework question stays open.
- **Evidence:** line 137.

### F11 — Follow-up **deliberately left** (residual disagreement)

- **Finding:** §5 suite comparison uses a markdown table while §4/§9 use code-block diagrams and other sections use bullets.
- **Why left:** it is a convention observation, not an error — no written project rule forbids tables, the table is the densest form for six suites × four columns, and converting it to bullets would cost ~80 words against a 6,997/7,000 budget. Flagging for **maintainer sign-off** rather than spending the word budget unilaterally. Reviewer marked it follow-up-OK.

### F12 — Follow-up fixed: RFC 2119 note

- **Action:** Added "**Normative terms.** RFC 2119 keywords are used as in the threat model and impose no current obligation on this repository." after the decision-label legend (the doc has 12 MUST usages).
- **Evidence:** line 14; mirrors the threat model's normative-terms convention.

## Label / non-regression audit

- **No new Accepted:** every content **Accepted** line (25, 26, 54, 58, 92, 179, 258, 299; plus legend 8 and scope note 12) traces to a merged document (architecture notes, root README, protocol README, ROADMAP, threat model); all design choices remain **Proposed**, PQ **Deferred**, mechanisms **Deferred**.
- **No open question answered:** F10 and F12 touch §15 cross-references only; §15 entries unchanged.
- **No new unsupported claim:** every factual correction carries a fetched primary source (above) or a directly-read repo file.
- **No threat-model contradiction:** §16 exclusions match threat model §5/§10 (propagation post-MVP per SR-7, PQ algorithms open); F3 now points at the correct section.

## Self-check (re-run after edits)

| Check | Result |
| --- | --- |
| Words | **6,997** (≤7,000) |
| H1 / H3+ | 1 / 0 |
| H2 sections | 17, in required order (lines 16–323), each preceded by blank line |
| Issue #2 questions | 8 markers covering Q1–Q6 (Q5 has three parts) |
| Threats | 10 `*Mitigation:*` + 10 `*Residual:*` |
| Invariants | 10 (INV-1…INV-10) |
| Diagrams | 3 balanced ` ```text ` blocks (6 fences total) |
| Label rule | 0 lines with ≥2 decision-label tokens |
| Open-question labels | only legend (line 10), §7/§12 cross-refs, §15 (lines 283–287) |
| Relative links | 6/6 resolve (README, threat model, ROADMAP, root README, protocol README) |
| TODO/TBD/secrets/US-English/"Open UPP" variants | none |
| Git | `git status --short` → only `?? .opencode/` and `?? docs/architecture/identity-and-key-lifecycle.md`; no commits, no other files touched |

## Residual disagreement / open items

1. **F11 left as-is** (above) — reviewer should confirm or maintainer should rule on table-vs-bullets.
2. **F6 sourcing:** FIPS 205 range verified via secondary quotations of its size table, not the PDF text (NIST PDF is not machine-fetchable here). Low risk; endpoints match the reviewer and SPHINCS+ reference tables.
3. Word budget has ~3 words of headroom; any further edit needs an offsetting cut.

## Handoff

- **Status:** DECISION_READY
- **Objective:** revise Issue #2 deliverable per T3 review, single file, source-verified.
- **Approved scope:** `docs/architecture/identity-and-key-lifecycle.md` only — done; no other file modified.
- **Verification performed:** primary-source fetches (RFC 4648/6482/9807, SP 800-186), direct reads (ROADMAP, threat model, architecture/protocol/root READMEs), full structural self-check table above.
- **Remaining uncertainty:** F6 secondary sourcing; F11 convention ruling.
- **Recommended next agent:** **Reviewer** — independent re-verification of F1–F12 dispositions against the revised file before any commit.
