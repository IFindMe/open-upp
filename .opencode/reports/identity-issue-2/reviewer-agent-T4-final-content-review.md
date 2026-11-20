# Reviewer report — Issue #2 identity design final pre-commit review (T4)

**Status:** [DONE] Final content review complete, report written. [PENDING] none — verdict is commit-ready. [BLOCKED] none.

## TL;DR

- **Verdict: ACCEPT — ready to commit.**
- **Defect count: 0 BLOCKING, 0 MAJOR, 0 REQUIRED; 2 NOTE-level observations (non-blocking, optional follow-ups).**
- Every T3 finding F1–F10 and F12 is closed in the current file with line evidence; F6's FIPS 205 range re-confirmed via multiple independent sources (NIST PDF itself not machine-fetchable — same limitation the author reported); F11 ruled **acceptable as-is** (no written table prohibition exists).
- Re-verified corrected citations at primary sources: RFC 4648 (Table 3, §3.3, §3.4), RFC 6482 (title), RFC 9807 (abstract), SP 800-186 (title/date) — all accurate.
- Regression sweep clean: label usage legitimate (ROADMAP exclusions **Accepted** trace to merged ROADMAP; author exclusions **Proposed**; PQ **Deferred**), no open question newly answered, no new unsupported claim, no threat-model contradiction, no "Open UPP implements X" statement.
- Baseline acceptance re-confirmed: 17 sections in order, 6 Issue questions, 10 threats × (mitigation + residual), 10 invariants, migration + alternatives, no scope creep, 1 H1 / 0 H3, 6/6 links, no TODO/secrets, only the one file in the working tree, 6,997 words.

---

## Step 1: Finding-by-finding closure — [PASS]

T3 findings re-verified against the current file; author claims not trusted, each checked directly.

| Finding | Sev (T3) | Status | Evidence in current file |
|---|---|---|---|
| F1 — own MVP exclusions mislabeled Accepted / ROADMAP misattributed | BLOCKING | **CLOSED** | Lines 299–301 split into three single-label lines: ROADMAP-listed items keep **Accepted** (299); this doc's own exclusions (backup/recovery, multi-device aggregation, key transparency, revocation propagation) **Proposed** (300); PQ **Deferred** (301). ROADMAP.md:50–56 "Not in the initial MVP" verified to list exactly: global public-key directory, mandatory centralized account or identity provider, production-grade decentralized PKI, Internet replacement, anonymity, VPN — i.e. the three Accepted items are genuinely there, the Proposed/Deferred ones are not. Line 12 ("No new choice here is labeled Accepted") is true again. Regex for two-label lines: no matches. |
| F2 — base32 display rule contradicts RFC 4648 | MAJOR | **CLOSED** | Line 133 now reads "RFC 4648 alphabet A-Z plus 2-7 … The digits 0, 1, 8, and 9 never occur, so a confusion such as 0/O or 1/I resolves to exactly one valid character"; line 134 adds strict rejection "characters outside the alphabet are rejected rather than mapped (no 0-to-O or 1-to-I leniency; RFC 4648 sections 3.3 and 3.4)". Primary source re-fetched: RFC 4648 Table 3 = A–Z (I=8, O=14 present) + 2–7, so digits 0/1/8/9 are exactly the absent digits ✓; §3.3 "Implementations MUST reject the encoded data if it contains characters outside the base alphabet" ✓; §3.4 "where 0 (zero) and 1 (one) are not present, a decoder may interpret 0 as O, and 1 as I or L … by default it should not" ✓. Section numbers, alphabet, and rationale all correct; the contradiction is gone. |
| F3 — wrong threat-model section for "Revocation scope" | MINOR | **CLOSED** | Line 218 now cites `(section 5, "Revocation scope")`. threat-model.md:111 holds the "**Revocation scope.**" paragraph under `## 5. Assumptions and out-of-scope risks` (heading line 82; next heading line 121) ✓. Old "section 10, Revocation scope" phrasing: zero residue (grep). |
| F4 — RFC 6482 title misquoted | MINOR | **CLOSED** | Line 341: "A Profile for Route Origin Authorizations (ROAs)" — exact match to the RFC 6482 header fetched from rfc-editor.org (February 2012) ✓. |
| F5 — OPAQUE gloss overstates RFC 9807 | MINOR | **CLOSED** | Line 328: "Hides the password from the server even during registration; resists precomputation attacks on server compromise; future password-recovery candidate." Matches RFC 9807 abstract verbatim in substance ("hide the password from the server, even during password registration"; "security against pre-computation attacks upon server compromise") ✓. No immunity/offline-attack-denial claim remains ✓. |
| F6 — SLH-DSA size range understated | MINOR | **CLOSED** (sourcing note) | Line 115: "7.8-49.9 KB signatures" ✓. FIPS 205 final date Aug 13 2024 confirmed on csrc.nist.gov ✓. Size endpoints 7,856–49,856 B confirmed by multiple independent secondary quotations of FIPS 205's size table (search results: 7,856 / 49,856 B, 12 parameter sets); the NIST PDF is not machine-fetchable (re-confirmed: fetch returns `application/pdf` unsupported) — same limitation the author disclosed. **Certainty: STRONG INFERENCE** (multi-source agreement, endpoints match the T3 reading of Table 11). |
| F7 — SP 800-186 in §5 table but absent from §17 | MINOR | **CLOSED** | Line 332 added: exact NIST title "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters", February 2023 — confirmed on csrc.nist.gov (Date Published: February 2023) ✓. All standards cited in the §5 table (RFC 8032, FIPS 186-5, SP 800-186, SECG SEC 2, BLS draft, FIPS 204/205, RFC 6979) now have §17 entries ✓. |
| F8 — present-tense implementation claim | MINOR (follow-up) | **CLOSED** | Line 26: "**Accepted.** Established, reviewed primitives only — no invented primitives" — "are used" gone ✓. Supported by protocol README:26 ("Prefer established, reviewed cryptographic protocols and libraries. Do not invent cryptographic primitives") and threat-model.md:88 ("custom primitives are forbidden") / :174 (SR-2 "cryptography MUST use established algorithms"). |
| F9 — two citation attributions | MINOR (follow-up) | **CLOSED** | Line 25/179 now cite architecture notes heading "Identity is not authorization" (docs/architecture/README.md:23, exact heading ✓) plus root README principle 2 (README.md:22 ✓); line 58 now cites root README principle 7 (README.md:27 "No mandatory global authority" ✓) + threat model section 5 (threat-model.md:90, exact wording match ✓) + ROADMAP ✓. |
| F10 — "fully specified now" overstated | MINOR (follow-up) | **CLOSED** | Line 137: "their structure is fixed now and independent of statement serialization; the tag value and suite-identifier encoding ship with the Stage 2 test vectors (section 15)" ✓ — and the canonical-encoding open question stays open (§15 line 283) ✓. |
| F11 — markdown table vs observed convention | MINOR (follow-up) | **LEFT DELIBERATELY — ruled acceptable (see Step 3)** | Table remains at lines 108–115. |
| F12 — no RFC 2119 note for MUST usages | MINOR (follow-up) | **CLOSED** | Line 14: "**Normative terms.** RFC 2119 keywords are used as in the threat model and impose no current obligation on this repository." ✓; MUST now appears on 12 lines, matching the author's claim ✓. |

**All BLOCKING/MAJOR findings and all same-change minors (F1–F7) are resolved. F8–F10, F12 also resolved. Only F11 remains deliberately open, ruled acceptable below.**

## Step 2: Regression re-read — [PASS]

Re-read of the full revised document (351 lines) for defects introduced by the fixes:

- **Decision-label integrity: legitimate.** ROADMAP exclusions at line 299 satisfy the legend (line 8: Accepted = merged-repository position; ROADMAP is tracked and merged at HEAD, list verified at ROADMAP.md:50–56) and restore the truth of line 12. Author exclusions at line 300 are **Proposed**, consistent with §10 (line 227/233 posture), §11 line 233, §12 line 242, §14. PQ at line 301 is **Deferred**, matching line 125. One coherence check: line 300's "revocation propagation beyond local knowledge" as a *Proposed MVP exclusion* does not answer §15's propagation open question — §15 line 284 records the *mechanism* as open ("post-MVP per SR-7") and threat-model.md:111 states propagation "is post-MVP and OPEN"; exclusion and open mechanism coexist without contradiction ✓.
- **No newly answered open question.** All 9 §15 entries re-checked against their cross-referencing sections: encoding (line 137 keeps framework open), propagation (§10 defers), recovery (line 233 "nothing here answers it"), multi-device (line 246 "does not answer it"), agent delegation (line 287), trust anchors (line 175 "selects none"), PQ policy (line 125 "project policy is open"), storage (§11 defers), external dependencies (line 291). Zero answers added.
- **No new unsupported claim.** Every factual correction re-verified against a primary source (Step 1). Two NOTE-level observations only (Step 4). No "Open UPP uses/implements/adopts" statement anywhere; line 325 explicitly disclaims implementation, line 321 disclaims compatibility.
- **No threat-model contradiction.** F3 now points at the correct section; §9/§10 residual citations at line 225 verified against threat-model.md:191 ("Revocation latency", §9) and :209 ("Revocation and recovery", §10, "Propagation and offline behavior are post-MVP and OPEN") ✓. Four-scope taxonomy (line 218) matches threat-model.md:111 ✓; M-8 conditional Stage-4 status honored (lines 227, INV-7) ✓.

## Step 3: F11 decision — tables vs repo convention — [PASS]

**Ruling: acceptable for commit as-is; log a follow-up for maintainer sign-off on a table convention.**

Reasoning:
1. **No written rule forbids tables.** Grepped CONTRIBUTING.md, GOVERNANCE.md, docs/architecture/README.md, docs/protocol/README.md — no table prohibition (only substring false positives like "exploitable", "stable"). The repo's table avoidance is an observed pattern across existing docs, not a documented contract.
2. **The table is the right tool for the content.** Six suites × four comparison columns; converting to bullets would cost ~80 words against a 6,997/7,000 budget and reduce scanability of the §5 trade-off comparison.
3. **No downstream contract breaks.** The table is well-formed GitHub-flavored markdown, all standards named in it now appear in §17 (F7 closed), and nothing else in the repo parses docs mechanically in a way a table would break.
4. **Proportionality:** blocking a content-correct, standards-verified doc over an unwritten style pattern would be a style preference inflated into a blocker, which my review discipline forbids.

Follow-up: maintainer records whether tables are permitted in `docs/`; if ruled against, conversion of lines 108–115 to bold-lead bullets is mechanical and post-commit.

## Step 4: New findings — none blocking

**N1 (NOTE)** — `docs/architecture/identity-and-key-lifecycle.md:299`
- Problem: the **Accepted** line cites "ROADMAP.md and the root README" for the three non-goal items, but root README contains no "directory", "PKI", or "identity provider" text (grep exit 1); only principle 7 ("No mandatory global authority") is adjacent.
- Why it matters: attribution precision only. The **Accepted** label itself is fully legitimate — ROADMAP.md:50–56 lists all three items verbatim, and ROADMAP is a merged document. Roadmap-backed, not label-backed, risk: zero.
- Correction (optional): drop "and the root README" from line 299, or cite it as "root README principle 7 (no mandatory global authority)". Same class as T3's F9, which was follow-up-grade.

**N2 (NOTE)** — `docs/architecture/identity-and-key-lifecycle.md:26`
- Problem: "Established, reviewed primitives **only**" is marginally stronger than the cited protocol README's "**Prefer** established, reviewed…".
- Why it matters: the claim is independently true per threat-model.md:88 ("custom primitives are forbidden") and SR-2 (:174), so no factual defect; citation could add the threat-model source. No action required.

## Step 5: Baseline acceptance re-confirmation — [PASS]

| Check | Result | Evidence |
|---|---|---|
| 17 sections, required order | PASS | `grep '^## '` → lines 16, 31, 44, 65, 102, 127, 144, 177, 187, 216, 229, 240, 250, 265, 279, 293, 323 = 17, numbered 1–17 |
| Six Issue #2 questions answered with labeled decisions | PASS | 8 markers (Q5 has 3 parts): lines 94, 104, 119, 131, 167, 189, 218, 231 — each carries **Proposed** (Q5 part 3's decisions labeled in the bullets at 233–236) |
| Ten threats × mitigation AND residual | PASS | `grep -c '*Mitigation:*'` = 10; `grep -c '*Residual:*'` = 10; all ten required threats present (lines 254–263) |
| Testable invariants | PASS | INV-1…INV-10 all present, each labeled or naming its dependency (lines 305–314) |
| Migration considerations | PASS | §16 lines 316–321 (algorithm migration, PQ timeline, format versioning, no-compatibility claim) |
| Alternatives considered | PASS | §14, 11 entries (lines 267–277) |
| No scope creep into discovery/relay/handshake/wire formats | PASS | Line 3 and §1 lines 18–20 bound scope; diagrams marked "Logical structure, not a wire format" (lines 90, 204); encoding/transcript/propagation deferred to §15 |
| One H1, no H3+ | PASS | `grep -c '^# '` = 1; `grep -c '^#{3,}'` = 0 |
| Links resolve | PASS | 6 unique relative links (README, ../../README, ../../ROADMAP, ../protocol/README, ../security/README, ../security/threat-model) — all resolve from the doc's directory |
| No TODO/TBD/FIXME | PASS | grep: no matches |
| No secrets | PASS | private-key/api-key/password-literal pattern grep: no matches |
| Decision-label discipline | PASS | No two-label lines (regex exit 1); Open-question labels only in legend (10), §7 (175), §12 (246), §15; every **Accepted** line traces to a merged doc (lines 24–26, 54, 58–60, 92, 179–181, 258, 299) |
| US English / "Open UPP" / no front matter | PASS | British-spelling grep (18 patterns): no matches; 9× "Open UPP", no OpenUPP/Open-UPP variants; line 1 is the H1, no `---` front matter |
| Diagrams in ```text fences | PASS | 6 fences = 3 balanced blocks, all opened with ```text (69/88, 150/163, 191/202) |
| Only this file changed | PASS | `git status --short` → `?? .opencode/` and `?? docs/architecture/identity-and-key-lifecycle.md` only; `git diff --stat HEAD -- docs/` empty; HEAD `1e41417 docs: add Open UPP threat model`; nothing committed |
| Word count | PASS | `wc -w` = **6,997** (matches brief and author claim) |

## Validation evidence (commands run this review)

```
git status --short                    → only ?? .opencode/ and ?? docs/architecture/identity-and-key-lifecycle.md
git diff --stat HEAD -- docs/         → empty (no tracked file modified)
git log --oneline -2                  → 1e41417 (HEAD, threat model); no new commits
wc -w                                 → 6997
grep -c '^# ' / '^#{3,}' / '^## '    → 1 / 0 / 17 (in order, lines 16–323)
grep -c '*Mitigation:*'/'*Residual:*' → 10 / 10
grep -c 'Issue #2 question'           → 8
grep -o 'INV-[0-9]*' | sort -u        → INV-1 … INV-10
grep two-labels-per-line regex        → no matches (exit 1)
grep -c 'MUST'                        → 12 lines
grep '^```'                           → 6 fences, all ```text-opened, 3 balanced blocks
link-resolution loop (6 unique rel.)  → all OK
grep TODO/TBD/FIXME                   → no matches
grep British spellings (18 patterns)  → no matches
grep secrets patterns                 → no matches
grep 'OpenUPP|Open-UPP'               → no matches
```

Primary sources re-fetched this review: RFC 4648 full text (Table 3, §3.3, §3.4), RFC 6482 header (title/date), RFC 9807 abstract, csrc.nist.gov SP 800-186 page (title, February 2023), csrc.nist.gov FIPS 205 page (final Aug 13 2024), web search for FIPS 205 size endpoints (7,856–49,856 B, multi-source). Local: ROADMAP.md:50–56, threat-model.md:88/90/111/174/191/209, README.md:22/27, docs/architecture/README.md:23, docs/protocol/README.md:26, docs/security/README.md:36.

## Commit decision

**Commit now.** No BLOCKING, MAJOR, or REQUIRED findings remain. Every T3 must-fix and same-change finding is closed with verified evidence; the two NOTEs (N1 citation precision at line 299, N2 wording strength at line 26) are non-blocking and do not affect correctness of any claim or label.

Non-blocking follow-ups (may be logged, not required before commit):
1. **F11 (deferred by author, ruled acceptable):** maintainer records a tables-permitted/not rule in `docs/` conventions; mechanical conversion of lines 108–115 if ruled against.
2. **N1:** optionally tighten line 299's citation to ROADMAP only (root README contributes only the general no-mandatory-authority principle).
3. **N2:** optionally add threat-model.md §5/SR-2 as the source for "only" in line 26.

---

## Handoff

- **status:** ACCEPT (ready to commit)
- **objective/problem:** final pre-commit verification of `docs/architecture/identity-and-key-lifecycle.md` — closure of T3 findings F1–F12, regression re-read, baseline re-confirmation, F11 ruling
- **evidence/completed work:** this report; primary-source re-fetches (RFC 4648/6482/9807, SP 800-186, FIPS 205 page + size endpoints); local greps/structure audits listed above; full re-read of the 351-line deliverable and the architect's T4 revision report
- **affected areas:** none modified by reviewer — review only; doc lines cited as evidence (26, 94–231, 299–301, 332, 341)
- **scope/decision boundary:** verification and the F11 convention ruling; no design decisions, no file edits other than this report
- **verification performed:** finding-by-finding closure with line evidence, label/open-question/unsupported-claim/threat-model regression sweep, baseline acceptance matrix, validation command suite, F11 evidence check (grepped governance docs for table rules)
- **remaining uncertainty:** FIPS 205 size endpoints rest on multi-source secondary quotations (NIST PDF not machine-fetchable) — STRONG INFERENCE, disclosed identically by the author; nothing else material
- **recommended next agent:** **Orchestrator** — verdict is final; proceed to commit of `docs/architecture/identity-and-key-lifecycle.md`
- **reason:** all findings closed or ruled non-blocking; no Builder, Architect, or Maintainer action is required before commit; the three follow-ups can be tracked post-commit

**Changes made by Reviewer:** this report only (`.opencode/reports/identity-issue-2/reviewer-agent-T4-final-content-review.md`).
