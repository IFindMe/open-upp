# Reviewer report: final content review — Open UPP threat model (Issue #1)

## TL;DR

- **Status:** FINAL CONTENT REVIEW COMPLETE.
- **Verdict:** **ACCEPT (ready to commit as a draft).**
- **Prior findings:** 8/8 resolved — F1 BLOCKING, F2–F3 MAJOR, F4–F8 MINOR.
- **New findings:** 2 MINOR (non-blocking) and 1 NOTE; no BLOCKING or MAJOR findings.
- **Commit recommendation:** yes — commit `docs/security/threat-model.md` as the Issue #1 draft. The two MINOR items are follow-ups, not commit blockers.
- **Process gate:** Issue #1 is still OPEN; the required second-contributor review is not yet recorded. Do not close Issue #1.
- **Scope:** only `docs/security/threat-model.md` content plus untracked `.opencode/` reports/tooling; no tracked changes, secrets, or unrelated edits.

All line references below are to `docs/security/threat-model.md`.

## Step 1: Prior finding closure [PASS]

| Prior finding | Evidence in current file | Closure |
|---|---|---|
| **F1 BLOCKING** — individual `SR-x.y` IDs cited but undefined | `:151` now says requirement references use group IDs `SR-1`–`SR-11`; threats `:153-167` cite only those groups; §8 defines every group at `:173-183`; grep finds zero `SR-\d+\.\d+` citations; every cited group (1–11) is defined. | **Resolved.** Uses the reviewer-approved group-level alternative; the false individual-ID traceability claim is gone. |
| **F2 MAJOR** — §10 reopened global-directory/PKI and group-scope non-goals | `:203` scopes trust anchors to a local, organizational, or limited directory while restating that a global directory and production PKI remain non-goals; §5 non-goal at `:105` and §11 non-goal at `:238` remain; §10 has 16 questions and no group-scope question. | **Resolved.** The non-goals are no longer reopened. |
| **F3 MAJOR** — revocation under-specified; M-8 over-scoped MVP | `:111` defines identity-key, device, grant, and session scope; `:164` T12, `:179` SR-7, `:191` §9, `:209` §10, `:230` M-8, and `:235` M-13 are aligned; M-8 is explicitly conditional on a Stage 4 scope decision and moves post-MVP if Stage 4 is not extended; `ROADMAP.md:34-40` still does not list revocation. | **Resolved for the prior finding.** Residual enforcement/test wording is N1 below (non-blocking). |
| **F4 MINOR** — RFC 9420 and TLS 1.3 descriptions imprecise | `:115` conditions TLS endpoint authentication on credential validation; `:244` notes MLS supports two-member groups and that no MLS use is selected; `:248` matches the corrected TLS description. | **Resolved.** Descriptions are accurate and do not imply implementation. |
| **F5 MINOR** — “physical attacks” non-goal conflicted with T2 device theft | `:99` narrows the non-goal to physical side-channel, tampering, and hardware-implant attacks; `:109` treats device theft as endpoint compromise in §5 and T2; `:145` aligns the §6 excluded list. | **Resolved.** N3 below is only an editorial placement note. |
| **F6 MINOR** — discovery “not identity” imprecise | `:18` now says discovery returns “untrusted identity claims and reachability hints, not verified identity or trust.” | **Resolved.** |
| **F7 MINOR** — normative keywords and “testable” process requirements ambiguous | `:7` defines RFC 2119/BCP 14 normative terms and states they impose no current obligation; `:171` replaces “testable requirements” with requirements including design/process requirements and adds acceptance criteria; `:251` adds RFC 2119. | **Resolved.** N2 below concerns a new overbroad sentence in the same paragraph. |
| **F8 MINOR** — threats did not identify trust boundaries | Every T1–T15 entry at `:153-167` now has `Assets/boundaries:` naming the relevant §3 boundary or boundaries. | **Resolved.** |

## Step 2: Original Issue #1 and brief requirements [PASS]

- **Structure:** one H1, 13 H2 (`Status`, §§1–11, `References`), no H3 or deeper; all required sections present in order.
- **Threat coverage:** T1–T15 cover the 13 required categories plus Sybil and supply chain: impersonation, key theft, replay, MITM, unauthorized peers, malicious discovery, relay compromise, DoS, metadata/traffic analysis, malicious transport backends, downgrade, revocation, malicious apps/agents, Sybil, supply chain.
- **Issue #1 questions:** attacker scope in §4/§6 and T4/T7; device/key compromise in §5 (`:109`), T2/T5/T12; discovery/relay visibility in T6/T7/T9 and SR-9 (`:181`); replay/downgrade/substitution/Sybil/DoS in T1/T3/T8/T11/T14 and SR-1/SR-4–SR-6/SR-8; MVP exclusions in §5 (`:96-107`) and §11 (`:238`).
- **Separation of concerns:** authentication vs authorization vs discovery vs transport is explicit at `:18`; stable identity vs ephemeral session keys at `:32` and M-1 (`:223`); transport success is not trust at `:18`, `:54`, `:115`, `:147`; relays/NAT/backends are untrusted at `:51`, `:54`, `:87`.
- **No implemented claims:** `:6`, `:20`, `:43`, `:151`, and `:171` all state that nothing is implemented. No positive Open UPP protection claim was found.
- **RFC references:** `:242-251` are accurate and explicitly non-implying; all eight RFC URLs resolve. F4 corrections verified.
- **OPEN decisions:** §10 (`:200-217`) has 16 open questions; §8 marks OPEN items; no unresolved decision is presented as a guarantee.
- **MVP/ROADMAP alignment:** M-1–M-14 are present (`:223-236`); non-goals at `:238` cover the `ROADMAP.md:50-57` not-in-MVP list; M-8 is conditional on a Stage 4 scope decision, consistent with Stage 4 (`ROADMAP.md:34-40`) not listing revocation.
- **Draft/review gate:** `:5` states the document is a draft and Issue #1 requires at least two contributor reviews; GitHub Issue #1 is OPEN. Honest.

## Step 3: New findings and follow-ups [PASS]

No BLOCKING or MAJOR findings. The following are non-blocking.

### N1 — MINOR (non-blocking) — Revocation enforcement/test semantics remain ambiguous

- **Evidence:** `:111`, `:179`, `:209`, and `:230` rely on “locally known” revocation without defining what counts as locally known. SR-7 at `:179` says “a locally known revoked identity,” while M-8 at `:230` and §5 at `:111` say “revoked identity key or device.” The termination requirement at `:111` and `:230` does not state which revocation scopes require session termination; grant revocation is separately enforced “at the next authorization decision,” so it is unclear whether grant revocation also terminates sessions. `:209` asks how identity-key, device, grant, and session revocation are distinguished even though §5 at `:111` already defines those distinctions.
- **Why it matters:** If Stage 4 is extended to include revocation, M-8’s test condition depends on a clear definition of “locally known.” The wording could also imply that device revocation revokes the whole principal identity, contradicting the §5 taxonomy in which the principal may continue on another device.
- **Correction:** Define “locally known” (for example, local policy/configuration or a local revocation list) and state per-scope enforcement and termination behavior; use “revoked identity key or device” in SR-7; reword §10 to ask how the mechanism represents and propagates the four scopes, not how the concepts are distinguished.

### N2 — MINOR (non-blocking) — “OPEN means blocked on section 10, not optional” is overbroad

- **Evidence:** `:171` says “OPEN means blocked on section 10, not optional.” But SR-7 at `:179` marks cache freshness and false-revocation resistance “OPEN, post-MVP,” and SR-8 at `:180` marks relay quotas OPEN; §10 does not explicitly ask about cache freshness, false-revocation resistance, or relay quotas (`:209`, `:214`). The document also says at `:151` that OPEN means a requirement depends on an undecided design, which is broader than “blocked on section 10.”
- **Why it matters:** The sentence conflicts with the document’s own post-MVP/conditional language and weakens the claim that every OPEN item has a §10 owner. A reader cannot mechanically trace all OPEN items to §10.
- **Correction:** Say “OPEN means an unresolved decision in §10 or an explicitly deferred post-MVP dependency; it is not optional for the full design, but it may be out of MVP scope.” Add the missing §10 questions or soften the claim.

### N3 — NOTE — §6 “Excluded” placement of device theft is easy to misread

- **Evidence:** `:145` includes “device theft is treated as endpoint compromise” inside the “Excluded” paragraph, while `:99` narrows the physical-attacks non-goal and `:109` plus T2 (`:154`) treat device theft as endpoint compromise, not as an excluded category.
- **Why it matters:** A reader could read the clause as excluding device theft, even though the intended treatment is “covered as endpoint compromise.”
- **Correction (optional):** Move the clause out of the excluded list or reword to “Device theft is not separately modeled; it is covered by endpoint compromise.” This is editorial and does not block commit.

## Step 4: Lightweight validation [PASS]

- `git status --porcelain` → `?? .opencode/` and `?? docs/security/threat-model.md`; no tracked modifications, staged changes, commits, or branch actions.
- `wc -l -w docs/security/threat-model.md` → **251 lines, 5,725 words**; UTF-8, LF, final newline, no trailing whitespace or tabs.
- Headings → **1 H1, 13 H2, 0 H3+**.
- Threat audit → **T1–T15**, sequential and unique; all five fields (`Scenario`, `Assets/boundaries`, `Impact`, `Required`, `Residual`) present in every entry.
- Requirement audit → **SR-1–SR-11** all defined at `:173-183`; **0** `SR-x.y` citations; every cited group is defined; **M-1–M-14** present; **16** §10 questions.
- Link audit → **23 link occurrences, 15 unique** (7 relative files, 8 RFC URLs); all relative targets exist; all eight RFC URLs returned HTTP 200.
- Content hygiene → no `TODO`/`TBD`/`FIXME`/`XXX`, placeholders, front matter, tables, British spellings, `OpenUPP`/`Open-UPP` variants, or secrets/credentials in the document or the Issue #1 reports.
- Issue/roadmap audit → Issue #1 is OPEN and contains all five questions plus the two-contributor review requirement; `ROADMAP.md:34-40` and `:50-57` checked against §11.
- MVP testability → M-1–M-14 are testable/documentable in principle; M-8 remains conditional, and its “locally known” condition is the subject of N1.

## Step 5: Scope and repository state [PASS]

- Only `docs/security/threat-model.md` is new content. `.opencode/` contains the permitted untracked agent/tooling files and Issue #1 reports.
- No tracked file was modified; no code, ROADMAP, security README, or configuration was changed.
- No secrets or unrelated changes found. No commit, branch, push, or PR action was performed.

## Remaining uncertainty

- **Two-contributor review:** only this reviewer has recorded a review; the required second contributor is outstanding. Issue #1 must remain OPEN until that review is recorded.
- **Stage 1 traceability:** the document covers Stage 1 topics narratively and says it “feeds Stage 1” (`:24`), but there is no explicit Stage 1-to-section mapping matrix. The acceptance reviewers should confirm narrative coverage satisfies the `Status` gate at `:8`; this is not a content defect for commit.
- **N1/N2:** the two MINOR wording issues remain in the current file; they are non-blocking follow-ups.
- **Security properties:** design-stage only; no empirical verification is possible without an implementation.

## Verdict and handoff

- **Status: ACCEPT (ready to commit as a draft).** All prior BLOCKING/MAJOR findings are resolved; no new BLOCKING/MAJOR findings.
- **Commit:** yes — commit the threat model as the Issue #1 draft. N1/N2 are non-blocking follow-ups; N3 is an optional editorial note.
- **Do not close Issue #1:** the second-contributor review is still required.
- **Recommended next agent:** **Orchestrator** — coordinate the draft commit, record N1/N2 as follow-ups, and obtain the second-contributor review. Route the two MINOR wording fixes to Builder only if the team prefers them in the same commit.
- **Reviewer changes:** none to project files; this report only.

```text
Status: ACCEPT
Reviewed work: docs/security/threat-model.md (revised draft, Issue #1)
Approved scope / contract: GitHub Issue #1 threat-model requirements; repository docs/conventions
Findings: prior 8/8 resolved; new 2 MINOR (non-blocking), 1 NOTE; no BLOCKING/MAJOR
Verification verified: F1-F8 closure, structure, coverage, links, scope, RFC accuracy, ROADMAP alignment
Verification unverified: second-contributor review; explicit Stage 1 matrix; N1/N2 fixes
Scope compliance: in-scope confirmed; no out-of-scope changes
Remaining uncertainty: Stage 1 acceptance gate; second reviewer; local revocation semantics
Recommended next agent: Orchestrator
Reason: draft is ready to commit; coordinate the required second review and optional follow-ups
Changes made by Reviewer: none to project files; this report only
```
