# Writer revision report: Open UPP threat model (Issue #1)

## TL;DR

- **Status:** DOCS_READY — revision complete and ready for independent re-review; the document remains a draft, not an accepted security guarantee.
- **Document revised:** `docs/security/threat-model.md`.
- **Findings addressed:** 8/8 — F1 BLOCKING, F2–F3 MAJOR, F4–F8 MINOR.
- **Key changes:** group-level `SR-1`–`SR-11` traceability, scoped §10 questions, revocation taxonomy plus conditional MVP boundary, corrected RFC wording, narrowed physical non-goal, explicit discovery wording, normative terms, and per-threat boundary mapping.
- **Verification:** 1 H1, 13 H2, 0 H3+; 15/15 threats with all five fields; 11/11 requirement groups defined; zero `SR-x.y` citations; all links resolve; no placeholders.
- **Size:** 251 lines, 5,725 words.
- **Residual dependency:** M-8 is intentionally conditional on an explicit Stage 4 scope decision; if Stage 4 is not extended, M-8 moves to post-MVP.
- **Scope:** no commit, branch, push, or PR.
- **Report path:** `.opencode/reports/threat-model-issue-1/writer-agent-T3-revision.md`.

## Step 1: Inputs and revision boundary [DONE]

Read in full:

- `.opencode/reports/threat-model-issue-1/reviewer-agent-T2-draft-review.md` — source of F1–F8, line references, and required corrections.
- `docs/security/threat-model.md` — document under revision.
- `ROADMAP.md` — Stage 4 MVP scope and “Not in the initial MVP” constraints.
- `docs/security/README.md` — existing security direction and open topics.

Only `docs/security/threat-model.md` was edited. This report was created under `.opencode/` as the required revision artifact. No production code, existing report, roadmap, or security README was changed.

## Step 2: Finding-by-finding disposition [DONE]

| Finding | Severity | Action taken | Evidence |
|---|---|---|---|
| **F1** — individual `SR-x.y` IDs cited but never defined | BLOCKING | Removed every individual-ID citation and standardized traceability on the defined group IDs `SR-1`–`SR-11`. Each threat now cites only defined groups; §8 defines each group once. The `SR-x.y` enumeration is intentionally not used. | `docs/security/threat-model.md:151`, threats `:153-167`, requirement groups `:173-183` |
| **F2** — §10 reopens explicit non-goals | MAJOR | Removed the group-scope open question. Scoped trust anchors to a local, organizational, or limited directory while restating that a global public-key directory and production PKI remain non-goals. Clarified that metadata minimization does not imply anonymity. | `:203`, `:210`; §5 non-goals `:105`; §11 non-goals `:238` |
| **F3** — revocation under-specified and M-8 over-scopes MVP | MAJOR | Added a four-part revocation taxonomy: identity-key, device, grant, and session. Aligned T12, SR-7, §9, §10, and M-8. MVP enforcement is limited to locally known revocation at session boundaries; propagation, offline behavior, cache freshness, and global revocation are explicitly post-MVP/OPEN. M-8 is conditional on a Stage 4 scope decision and moves post-MVP if Stage 4 is not extended. | taxonomy `:111`; T12 `:164`; SR-7 `:179`; §9 `:191`; §10 `:209`; M-8 `:230`; M-13 `:235` |
| **F4** — RFC 9420 and TLS 1.3 descriptions imprecise | MINOR | RFC 9420 now notes MLS supports two-member groups while confirming no MLS use is selected for the MVP. TLS 1.3 wording now conditions endpoint authentication on credential validation; the RFC 8446 reference was refined to match. | `:115`; references `:244`, `:248` |
| **F5** — “physical attacks” non-goal conflicts with T2 device theft | MINOR | Narrowed the non-goal to physical side-channel, tampering, and hardware-implant attacks. Added that device theft is treated as endpoint compromise in §5 and T2, and aligned the §6 excluded list. | non-goal `:99`; key-theft paragraph `:109`; §6 excluded `:145` |
| **F6** — “discovery returns … not identity” imprecise | MINOR | Reworded to “untrusted identity claims and reachability hints, not verified identity or trust.” | `:18` |
| **F7** — normative keywords and “testable” process requirements ambiguous | MINOR | Added the RFC 2119/BCP 14 normative-terms status bullet, added RFC 2119 to References, replaced “testable requirements” with “requirements, including design and process requirements,” and added acceptance criteria for “MUST be defined/documented” items. | `:7`; §8 intro `:171`; reference `:251` |
| **F8** — threats do not identify the boundary crossed | MINOR | Added `Assets/boundaries:` to every T1–T15 entry, naming the relevant boundary or boundaries. This replaces a separate field without losing the required mapping. | threats `:153-167`; boundaries defined in §3 `:41-54` |

No reviewer finding was intentionally omitted.

## Step 3: Verification [DONE]

- **Structure:** exactly 1 H1 (`# Open UPP threat model`); 13 H2 sections; 0 H3 or deeper.
- **Required sections:** Status, §§1–11, and References are all present in the established order.
- **Threats:** 15/15 (`T1`–`T15`), sequential and unique. Each has Scenario, Assets/boundaries, Impact, Required, and Residual.
- **Requirement traceability:** cited groups `[1..11]` exactly match defined groups `[1..11]`; zero `SR-\d+\.\d+` citations remain; every threat’s **Required** field resolves to at least one defined group.
- **Scope coverage:** all reviewer-required categories remain covered — active network/malicious relay, impersonation/replay/downgrade/substitution, compromised peers/endpoints, unauthorized access/confused deputy, malicious discovery/stale data, DoS/exhaustion, metadata/traffic analysis, and supply chain.
- **§10:** 16 open questions; the group-scope question is removed; no global-directory or production-PKI question remains; no anonymity claim is introduced.
- **Revocation:** no full-propagation promise; local session-boundary enforcement is defined; propagation, offline revocation, cache freshness, and global revocation are marked post-MVP/OPEN.
- **Links:** all 23 Markdown links resolve. All relative targets exist; all 8 unique external RFC URLs returned HTTP 200.
- **Placeholders and language:** no `TBD`, `TODO`, `FIXME`, `XXX`, placeholder text, or British spellings found. No positive implemented-protection claim was added; “No security property is implemented” remains explicit.
- **Final size:** 251 lines, 5,725 words.
- **Repository state:** only untracked `.opencode/` reports and `docs/security/threat-model.md` are shown by `git status --short`; no commit, branch, push, or PR was made.

## Step 4: Residual issues and handoff [DONE]

- **Residual reviewer disagreement:** none. F1–F8 are all addressed.
- **Intentional scope choice:** M-8 remains in §11 as a conditional item rather than being moved wholesale to a post-MVP section. This follows the reviewer’s permitted “mark M-8 conditional” option and preserves the brief’s requirement to define session-establishment and termination behavior if revocation is in scope. The condition and fallback are explicit at `:230`.
- **Open dependency:** Stage 4 of `ROADMAP.md` does not list revocation. Adding M-8 to the MVP requires an explicit scope decision; otherwise it is post-MVP. This is now stated in §5 and M-8.
- **No implementation claim:** the document remains a design-stage draft. The two-contributor acceptance gate in the Status section is unchanged.
- **Recommended next agent:** Reviewer — independent re-review of the revised document against F1–F8 and the Issue #1 acceptance gate.
- **Reason:** the revision is complete, but the document is explicitly “Draft for review; not accepted”; the next step is verification, not further writing.

```text
Status: DOCS_READY
Documentation objective: Revise the Open UPP threat model to resolve all reviewer findings.
Documents created/updated:
  - Threat model revision: docs/security/threat-model.md
  - Revision report: .opencode/reports/threat-model-issue-1/writer-agent-T3-revision.md
Target audience: Protocol designers, implementers, security reviewers, discovery/relay operators, and application/agent developers.
Source of truth: Reviewer report, ROADMAP.md Stage 4 scope, docs/security/README.md, and the existing threat-model text.
Accuracy verification: Structural checks, requirement-ID resolution, link checks, placeholder checks, and line-by-line finding disposition.
Clarity verification: Finding-by-finding table plus scoped open questions and explicit conditional language.
Open documentation questions: M-8 Stage 4 scope confirmation remains OPEN by design.
Risks: The document is still a draft and does not establish implemented security.
Recommended next agent: Reviewer
Reason: Independent re-review of the revised draft and acceptance-gate verification.
Changes made by Writer: Documentation artifacts only; no commit, branch, push, or PR.
```
