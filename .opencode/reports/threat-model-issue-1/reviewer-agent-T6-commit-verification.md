# Reviewer report: post-commit verification — Open UPP threat model (Issue #1)

## TL;DR

- **Status:** POST-COMMIT VERIFICATION COMPLETE.
- **Verdict:** **ACCEPT FOR HANDOFF.**
- **Commit:** `1e414177d2b45e54af4f5462ee5e8d043317981d` on `docs/threat-model`; base `main` @ `a0e5de1`; exactly one added file, `docs/security/threat-model.md` (251 insertions).
- **Content:** committed blob is byte-identical to the T4-reviewed file; 251 lines / 5,725 words; 1 H1, 13 H2, 0 H3+; T1–T15; SR-1–SR-11; M-1–M-14.
- **Hygiene:** tracked tree clean; `.opencode/` untracked and uncommitted; branch has no upstream or remote ref; no PR; Issue #1 remains OPEN with no comments.
- **Follow-ups:** N1/N2 remain non-blocking and are **not fixed**; N3 remains optional. This report makes no content or git changes.

## Step 1: Repository and commit state [PASS]

- `git rev-parse --abbrev-ref HEAD` → `docs/threat-model`.
- `git rev-parse HEAD` → `1e414177d2b45e54af4f5462ee5e8d043317981d`.
- `git rev-parse main` → `a0e5de1a046d35305530d05f265cd9fc25128f3a`; `HEAD^` is the same base.
- `git rev-list --count main..HEAD` → `1`; `git rev-list --count HEAD..main` → `0`.
- Commit subject/body:
  - Subject: `docs: add Open UPP threat model`
  - Body: “Add the design-stage Stage 1 threat model covering assets, trust boundaries, actors, assumptions, adversary capabilities, threat analysis, mitigation requirements, residual risks, open questions, and MVP security requirements.”
  - Trailer: `Refs #1` (does not close the issue).
- `git show --stat --oneline HEAD` and `git diff --stat main...HEAD` both show exactly one file, `docs/security/threat-model.md | 251 ++++++++++++++++++++++++++++++++++++++++++`, 1 file changed, 251 insertions.
- `git diff --name-status main...HEAD` and `git show --name-status --format='' HEAD` both show only `A docs/security/threat-model.md`.
- `git status --short --branch` → `## docs/threat-model` plus `?? .opencode/`; no other tracked changes.

## Step 2: Committed content matches the reviewed document [PASS]

- Worktree and committed blob are byte-identical:
  - `sha256sum docs/security/threat-model.md` and `git show HEAD:docs/security/threat-model.md | sha256sum` both → `3f614e23c6363d0de443aa8b18a5c18ba1c528f78ed7b9c9aec10ed6437511f4`.
  - `git hash-object docs/security/threat-model.md` equals `git rev-parse HEAD:docs/security/threat-model.md` → `584a63de905a4ec43468dedc79340a271a3fa9e6`.
- Committed blob: **251 lines, 5,725 words**; UTF-8, final newline, no trailing whitespace.
- Structure: **1 H1; 13 H2; 0 H3+**. Required sections present in order: `Status`, §§1–11, `References`.
- Threat coverage: **T1–T15**, all 15 present, sequential, each with `Scenario`, `Assets/boundaries`, `Impact`, `Required`, and `Residual`.
- Requirement coverage: **SR-1–SR-11** all defined; **zero** `SR-x.y` citations; **M-1–M-14** all present; **16** §10 open questions.
- Hygiene: no `TODO`/`TBD`/`FIXME`/`XXX`, no placeholders, no private-key/password/token/API-key patterns, no front matter, no tables.
- Links: 23 occurrences (12 relative, 11 external); all 7 unique relative targets resolve in the committed tree; all 8 unique RFC URLs return HTTP 200.
- `git diff --check main...HEAD` → no whitespace errors.

## Step 3: Branch hygiene and remote state [PASS]

- `git status --short --branch` → `## docs/threat-model`; only `?? .opencode/` is untracked; tracked tree is clean.
- `git rev-parse --abbrev-ref --symbolic-full-name '@{u}'` → no upstream configured.
- `git branch -r --list 'origin/docs/threat-model'` and `git for-each-ref refs/remotes/origin/docs/threat-model` → no remote-tracking ref.
- `git ls-remote --heads origin docs/threat-model main` → only `refs/heads/main` at `a0e5de1a046d35305530d05f265cd9fc25128f3a`; `docs/threat-model` was not pushed.
- Local `main` is still `a0e5de1a046d35305530d05f265cd9fc25128f3a`.
- `gh pr list --head docs/threat-model --state all --json number,title,state,headRefName,baseRefName` → `[]` (no PR).
- `.opencode/` is not tracked (`git ls-files .opencode` is empty) and is not in the commit tree.

## Step 4: Follow-ups remain open and non-blocking [PASS]

N1 and N2 remain in the committed file and are not fixed:

- **N1 — revocation enforcement/test wording:** “locally known” remains undefined; SR-7 (`:179`) says “revoked identity” while M-8 (`:230`) says “revoked identity key or device”; per-scope termination behavior remains ambiguous. Non-blocking because M-8 is conditional and current Stage 4 does not include revocation; fix before any Stage 4 extension is implemented.
- **N2 — “OPEN means blocked on section 10, not optional”** (`:171`): still overbroad relative to SR-7’s “OPEN, post-MVP” items (`:179`) and SR-8’s relay quotas (`:180`), which lack explicit §10 questions. Non-blocking traceability/editorial follow-up.
- **N3 — optional:** §6 “Excluded” placement of device theft (`:145`) remains an editorial note only.

These are explicit follow-ups, not release blockers. The commit is a draft; Issue #1 acceptance still depends on the second review.

## Step 5: Issue review gate [PASS]

- `gh issue view 1 --json number,title,state,comments` → `{"number":1,"title":"[Design] Define the Open UPP threat model","state":"OPEN","comments":[]}`.
- The internal Reviewer T4 independent content review is complete and recorded at `.opencode/reports/threat-model-issue-1/reviewer-agent-T4-final-content-review.md` (ACCEPT; N1/N2 non-blocking).
- No second-contributor/human review is recorded in Issue #1 (0 comments), and no other reviewer report exists beyond the internal T2/T4 Reviewer reports. The required second review is **outstanding**.
- Issue #1 is **not accepted and not closed**. The commit trailer is `Refs #1`, not a closing reference.

## Step 6: Orchestrator final user report — key content

### Key security decisions/requirements stated

- **Stable identity, ephemeral sessions:** long-term identity keys are stable; session keys are distinct and ephemeral; long-term, session, and transport keys are distinct (SR-1, SR-2, M-1).
- **Concept separation:** authentication, authorization, discovery, and transport are distinct; discovery success, transport success, relay acceptance, and key lookup are not trust (SR-1; §1).
- **Deny-by-default authorization:** no access without an explicit scoped grant; enforcement per operation at the resource (SR-3, M-3).
- **Untrusted discovery:** discovery returns identity claims and reachability hints, not verified identity; verify peer identity independently before protected data (SR-4, M-4).
- **Authenticated sessions:** prove possession; bind identities, versions, algorithms, and parameters; reject replayed handshake/authorization/application messages; reject unacceptable versions and unknown critical extensions (SR-5, SR-6, M-2, M-6, M-7).
- **Transport independence:** protection must not depend on transport or relay trust; state and test where protection terminates and what a relay sees; no end-to-end claim for a relayed path unless tested (SR-5, M-5).
- **Revocation taxonomy and scope:** identity-key, device, grant, and session revocation; M-8 enforces locally known revocation at session boundaries only if Stage 4 scope is extended, otherwise it moves post-MVP (SR-7, M-8).
- **Bounded resources:** bound connections, handshakes, memory, CPU, messages, sessions, queues, and retries; reject over-limit input safely; rate-limit cryptography; avoid amplification (SR-8, M-9).
- **Privacy limits:** document what peers, relays, rendezvous, and observers see per path; minimize metadata; no anonymity, unlinkability, or metadata-free claim (SR-9, M-11).
- **Least authority for apps/agents:** explicit scoped authority; no inherited keys or grants; policy-mediated signing; external content treated as data (SR-10).
- **Supply-chain and log hygiene:** pin/review dependencies with provenance; signed or reproducible artifacts; authenticated updates; no secrets in logs or test output (SR-11, M-10).
- **Evidence-bounded claims:** document first-contact trust decisions and wrong-identity risk; negative tests; no security or compatibility claim beyond demonstrated tests and documentation (SR-1, M-12, M-13, M-14).

### Main unresolved security questions

1. Identity representation, encoding, algorithms, sizes, rotation, and storage.
2. Trust anchors and first contact (manual, organizational, provider, transparency, or TOFU; local/limited directory; failure modes).
3. Handshake, identity binding, key derivation, and forward secrecy.
4. End-to-end termination, relay trust, relay visibility, and relay architecture.
5. Discovery record binding, freshness, conflict handling, and metadata exposure.
6. Policy model, grant expression, delegation, and audit.
7. Agent identity, delegation, scope, revocation, and attribution.
8. Revocation mechanism, identity-key/device/grant/session distinctions, recovery, propagation, and offline behavior.
9. Metadata minimization, audit logging, access, and retention.
10. Versioning/deprecation/fallback, transport-layer selection, relay authentication, NAT traversal, Sybil controls, clock/freshness, and post-quantum policy (no choices made).

### Main residual risks

1. First contact: users can approve the wrong identity under pressure or social engineering.
2. Endpoint compromise: stolen keys/data and misuse; detection is not guaranteed.
3. Revocation latency: no global/offline revocation promise; M-8 covers local revocation only if in scope.
4. Metadata and traffic analysis: content protection does not hide who communicates, when, or how much; no anonymity/unlinkability claim.
5. Sybil and DoS: cheap identities pollute discovery; local bounds cannot defeat a global flood.
6. Implementation and supply chain: parser, memory-safety, dependency, build, and algorithm compromise can bypass requirements; post-quantum policy is open.
7. Misconfiguration/authorized actors: wildcard grants, shared keys, exposed services, or disabled checks.
8. Relay collusion: relays can retain data, deny service, disappear, or reveal interactions the analysis misses.

### Commit/handoff facts

- Branch: `docs/threat-model`
- Commit: `1e414177d2b45e54af4f5462ee5e8d043317981d` — `docs: add Open UPP threat model`
- Base: `main` @ `a0e5de1`
- Changed file: `docs/security/threat-model.md` (one file, 251 insertions)
- Remote/PR: no upstream, no remote branch, no PR
- Issue #1: OPEN; second-contributor/human review outstanding

## Step 7: Validation summary [PASS]

| Check | Result |
|---|---|
| Branch / HEAD | `docs/threat-model` / `1e414177...` |
| Parent / base | `a0e5de1...`; `main` local and remote at same commit |
| Commit diff | one added file, 251 insertions; no other tracked changes |
| Tracked tree | clean; only `?? .opencode/` untracked |
| Remote branch | none; only remote `main` exists |
| PR | none (`[]`) |
| Issue #1 | OPEN, 0 comments |
| Committed file | 251 lines, 5,725 words; 1 H1, 13 H2, 0 H3+ |
| Threat IDs | T1–T15 present |
| Requirement IDs | SR-1–SR-11 defined; M-1–M-14 present; zero `SR-x.y` |
| Placeholders | none |
| Secrets | none found |
| Links | 23 occurrences; 12 relative, 11 external; all resolve; RFCs HTTP 200 |
| Whitespace | `git diff --check` clean; no trailing whitespace |
| Content identity | worktree SHA-256 equals committed blob SHA-256 (`3f614e...`) |

No git mutations were performed: no commit, amend, push, checkout, branch change, or PR creation. No project files were edited; this report is the only write.

## Final verdict

**ACCEPT FOR HANDOFF.**

The commit is correct, contains exactly the reviewed threat-model file, and passes the requested content, scope, and branch-hygiene checks. N1/N2 and optional N3 remain explicit non-blocking follow-ups; they are not fixed and do not block handoff. Issue #1 must remain OPEN until a second contributor/human review is recorded; this report does not accept or close it.
