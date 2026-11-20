# Writer report: Open UPP threat model draft

## TL;DR

- **Status:** DOCS_PROVISIONAL — draft complete and self-checked; not accepted, not reviewed by two contributors, and not a security guarantee.
- **Deliverable:** `docs/security/threat-model.md` — new file, 249 lines, 5,329 words, one H1 and 13 H2 sections.
- **Coverage:** all required sections, threats T1–T15, requirement groups SR-1–SR-11, MVP requirements M-1–M-14, 17 open questions, and all five Issue #1 questions mapped.
- **Design boundary:** no algorithm, key format, handshake, discovery mechanism, policy language, relay architecture, version number, trust anchor, PKI, global directory, NAT technique, or relay authentication model is selected.
- **Open gaps:** first contact, revocation propagation, and end-to-end protection through relays remain OPEN; length is about 6.6% above the 5,000-word upper target; two-contributor review remains outstanding.
- **Self-check:** no H3+, no TODO/TBD, all relative links resolve, all 15 threats state a residual "not guaranteed" item, and no implemented protection is claimed.

## Step 1: Evidence and constraints [DONE]

Read-only evidence used: `docs/security/README.md`, `docs/architecture/README.md`, `docs/protocol/README.md`, `ROADMAP.md`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `docs/development/README.md`, and `CHANGELOG.md`.

Constraints applied: repository is docs-only and pre-implementation; documentation must not imply current behavior; MUST/SHOULD/MAY are future specification requirements; transport success must not be equated with UPP trust; no anonymity claim; no other repository file modified.

## Step 2: Document structure [DONE]

`docs/security/threat-model.md` contains:

- H1: `# Open UPP threat model`.
- H2: `## Status`; `## 1. Purpose and scope` through `## 11. Security requirements for the MVP`; `## References`.
- No H3 or deeper headings.
- Section 7 uses stable IDs T1–T15, each with Scenario, Assets, Impact, Required, and Residual fields.
- Section 8 groups requirements as SR-1 through SR-11.
- Section 11 lists MVP requirements M-1 through M-14 and explicit MVP non-goals.

## Step 3: Threat and Issue #1 coverage [DONE]

Threat coverage: T1 identity impersonation; T2 private key theft; T3 replay; T4 MITM; T5 unauthorized or over-privileged peers; T6 malicious discovery; T7 rendezvous/relay compromise; T8 DoS/exhaustion; T9 metadata/traffic analysis; T10 malicious transport backends; T11 downgrade/version attacks; T12 revocation/stale authorization; T13 malicious apps/agents; T14 Sybil/identity churn; T15 supply chain.

Issue #1 answers:

- **Attacker scope:** sections 4 and 6 define principals, roles, adversary phases, and classes.
- **Compromised device or long-term key:** T2, T5, T12 and section 5 define containment, revocation, and residual risk.
- **Operator visibility:** T6, T7, T9 and SR-9 define discovery, relay, and metadata exposure.
- **Replay, downgrade, substitution, Sybil, DoS:** T1, T3, T8, T11, T14 and SR-1, SR-4–SR-6, SR-8.
- **MVP exclusions:** section 5 non-goals and section 11 MVP non-goals.

## Step 4: Self-checks [DONE]

- Heading structure: 1 H1; 13 H2; 0 H3 or deeper.
- Threat IDs: T1–T15 each appears once as a threat entry.
- Threat fields: every T1–T15 entry contains Scenario, Assets, Impact, Required, and Residual.
- Residual statements: every T1–T15 entry includes an explicit "not guaranteed" statement.
- Relative links: all 12 occurrences resolve to existing repository files.
- Placeholders: no TODO, TBD, FIXME, or XXX.
- Terminology: no `OpenUPP`, `Open upp`, or British-spelling variants found in the scan.
- Claims: no implemented-protection claim; the only matches for "is implemented" are explicit negations.
- Repository state: `git status --short` shows only untracked `.opencode/` and the new `docs/security/threat-model.md`; no commit, branch, push, or pull request.

## Step 5: Gaps and handoff [PENDING]

- Two-contributor review required by Issue #1 has not occurred; the document remains draft and not accepted.
- Length is 5,329 words against a 3,000–5,000 target; compression prioritized required traceability, so the upper target is slightly exceeded.
- First contact, revocation propagation, end-to-end termination through relays, relay authentication, policy model, discovery authenticity, and version policy remain OPEN by design.
- Independent accuracy and clarity review is recommended next.

**Recommended next agent:** Reviewer — verify the draft against Issue #1, repository conventions, and the evidence sources before accepting it as the Stage 1 threat model.
