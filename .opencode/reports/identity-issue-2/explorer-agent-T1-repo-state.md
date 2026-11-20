# Exploration Report — Repo state for Issue #2 (peer identity & key lifecycle)

TL;DR
- Repo is a docs-only design repo (20 tracked files, no code, no CI). Current session branch is `docs/threat-model` at `1e41417`.
- Threat model IS merged to remote `main`: PR #5 merged 2026-11-07, remote `main` = `c6ad7fd` (merge commit) containing `1e41417`. Local `main` branch is stale at `a0e5de1` (2 behind).
- No identity/key/lifecycle work has started: no matching branches, commits, or files; Issues #1–#4 all OPEN with 0 comments; only PR is the merged threat-model PR.
- `AGENTS.md` does not exist anywhere; `.opencode/` is untracked local tooling (agent defs + prior threat-model task reports).
- Threat model status: "Draft for review; not accepted" — acceptance needs 2 recorded reviews + section 10 resolution (issue #1 still OPEN, 0 comments).
- No algorithm is selected anywhere; explicit statements say X25519/Ed25519 etc. are "not selected". Identity design must not contradict: no global directory / mandatory identity provider / production PKI; identity ≠ authorization; discovery untrusted; transport independence.
- Docs conventions: 1×H1 + H2 only (no H3 in docs/), no tables, no front matter, relative markdown links, "Open UPP" spelling; topic files live next to `README.md` (`docs/security/threat-model.md` precedent → `docs/architecture/identity-and-key-lifecycle.md` fits).

## 1. Git state

Observed (via `git branch -a`, `git status`, `git log`, `git tag`, `git ls-remote --heads origin`, one `git fetch origin main` to refresh remote-tracking refs — no branch/working-tree changes):

- Current branch: `docs/threat-model` @ `1e41417`, up to date with `origin/docs/threat-model`. Status: clean except untracked `.opencode/` (report tooling).
- Local branches: `docs/threat-model` (1e41417), `main` (a0e5de1).
- Remote heads: `origin/main` = `c6ad7fd`, `origin/docs/threat-model` = `1e41417`, `origin/HEAD -> origin/main`. Both remote branches exist locally; before the fetch, local `origin/main` was stale at `a0e5de1`. No remote-only branch missing locally.
- Tags: none.
- Log (`git log --oneline -10` on HEAD):
  ```
  1e41417 docs: add Open UPP threat model
  a0e5de1 legal: include complete Apache License 2.0 text
  f963494 fix: avoid undefined labels in proposal template
  7d4262c fix: avoid undefined labels in bug report template
  618b6f1 docs: restore project overview in root tree
  10641f0 docs: add project foundation and contributor guidelines
  25df244 docs: initialize Open UPP project
  ```
- **Merge status (FACT):** `main` (local) is at `a0e5de1`; `origin/main` is at `c6ad7fd` = "Merge pull request #5 from IFindMe/docs/threat-model". `git merge-base --is-ancestor 1e41417 FETCH_HEAD` confirms the threat-model commit **is on remote main**. PR #5 merged 2026-11-07 (only PR in repo). Local `main` is 2 commits behind `origin/main` (checkout not performed — not authorized/needed).
- Identity/key/lifecycle search (FACT, negative): no branch matches `ident|key|life|trust|auth`; `git log --all --grep` for identity/key/lifecycle/revocation/fingerprint returns nothing; no tracked file matches `ident|key|lifecycle|revoc`.
- Issue #2 work started? **No.** No `docs/architecture/identity*` file; `docs/architecture/` contains only `README.md`; no commit mentions identity. GitHub Issues #1–#4 all OPEN, 0 comments, no labels/assignees; only PR is #5 (merged threat model).

## 2. New/existing files

Full tracked tree (20 files):
```
.editorconfig  .github/FUNDING.yml  .github/ISSUE_TEMPLATE/bug_report.yml
.github/ISSUE_TEMPLATE/feature_request.yml  .github/pull_request_template.md
.gitignore  CHANGELOG.md  CODE_OF_CONDUCT.md  CONTRIBUTING.md  GOVERNANCE.md
LICENSE  NOTICE  README.md  ROADMAP.md  SECURITY.md
docs/architecture/README.md  docs/development/README.md
docs/protocol/README.md  docs/security/README.md  docs/security/threat-model.md
```
- `docs/security/threat-model.md` exists: 251 lines. H1/H2 headings: `# Open UPP threat model`; `## Status`, `## 1. Purpose and scope`, `## 2. System assets`, `## 3. Trust boundaries`, `## 4. Actors and security roles`, `## 5. Assumptions and out-of-scope risks`, `## 6. Adversary capabilities`, `## 7. Threat analysis`, `## 8. Mitigations and security requirements`, `## 9. Residual risks`, `## 10. Open security questions`, `## 11. Security requirements for the MVP`, `## References`. No H3 anywhere.
- `docs/architecture/identity-and-key-lifecycle.md`: **does not exist**.
- `AGENTS.md`: **does not exist** (root or docs; `find -iname "AGENTS*"` only matches the untracked directory `.opencode/agents/` containing OpenCode agent role definitions — local tooling, not repo docs; no repo workflow instructions there). No agent/workflow conventions exist in tracked files to follow beyond CONTRIBUTING/GOVERNANCE below.
- New files since threat-model work: only `docs/security/threat-model.md` (commit `1e41417`). Untracked `.opencode/` holds prior Issue-1 task reports (`.opencode/reports/threat-model-issue-1/*.md`) — evidence artifacts, not repo content. No new CI, configs, or docs.

## 3. Threat model constraints (docs/security/threat-model.md)

### Status / decision marking (lines 3–8)
- "**Draft for review; not accepted.** Issue #1 requires review by at least two contributors before acceptance."
- "MUST, SHOULD, and MAY are used in the RFC 2119/BCP 14 sense for future specifications; they impose no current obligation on this repository."
- "**Review gate.** Acceptance requires recorded review by two contributors, resolution or explicit deferral of section 10, and traceability to Stage 1 in ROADMAP.md."
- No "Proposed/Accepted/Deferred" label convention exists anywhere in the repo. The only status tokens are **OPEN** ("OPEN means blocked on section 10, not optional", line 171; "OPEN means the requirement depends on an undecided design", line 151) and the bolded doc-status line. Roadmap uses `- [ ]` / `- [x]` checkboxes.

### Exact terminology (quote these, don't paraphrase differently)
- **principal / identity / role / authorization** (line 58): "A **principal** is the entity on whose behalf authority is exercised; one principal may control several identities. An **identity** is a cryptographic, key-bound representation of a principal, device, service, or agent; it is not a name, address, role, or permission. A **role** is a context-specific function; it grants no authority by itself. **Authorization** is permission for an operation on a resource under policy, not identity, role, reachability, or discovery."
- **Key classes** (lines 30–32): "**Long-term identity keys** — authenticity, integrity; compromise enables impersonation until revocation." / "**Ephemeral session keys and state** — confidentiality, integrity, freshness; must not become identity keys; past-session impact is OPEN." SR-2 adds transport keys: "Long-term, session, and transport keys MUST be distinct."
- **peer** (line 63): "**Peer or endpoint** — holds an identity and establishes sessions; may be honest, compromised, malicious, or misconfigured."
- **fingerprint / trust material** (line 31): "**Trust material** (public keys, pins, fingerprints, first-contact decisions) — integrity; tampering silently redirects trust." T1 (line 153) mentions "a truncated fingerprint" and "names are not authoritative and comparison is OPEN".
- **First contact** (line 189): "Users can approve the wrong identity under pressure or social engineering; protocol requirements do not solve verification UX." Line 92: "first-contact verification is unresolved".
- **Revocation is four distinct properties** (line 111): "**Identity-key revocation** withdraws a compromised or rotated key from future authentication. **Device revocation** removes one device's authority while the principal may continue. **Grant revocation** withdraws a scoped authorization. **Session termination** ends existing sessions."
- **Authentication vs authorization** (line 18): "Authentication identifies the principal controlling the key and what was negotiated, not intent or permission. Authorization decides whether that principal may perform this operation on this resource now…"

### Requirement IDs relevant to identity/key lifecycle (exact text)
- **SR-1 Authentication and identity** (line 173): "Peers MUST prove possession and bind identity to session parameters; canonical encoding, display, comparison, first contact, and trust-on-first-use MUST be defined; discovery, transport success, relay acceptance, and key possession MUST NOT be authentication or authorization."
- **SR-2 Key lifecycle** (line 174): "Long-term, session, and transport keys MUST be distinct; rotation and revocation MUST preserve continuity; secrets MUST NOT appear in logs, dumps, telemetry, or diagnostics; storage and isolation MUST be defined (OPEN); cryptography MUST use established algorithms; historical confidentiality without forward secrecy is not guaranteed."
- **SR-7 Revocation** (line 179): "Revocation MUST distinguish identity-key, device, grant, and session scope. A locally known revoked identity MUST be denied at session establishment, and termination of an existing session on locally known revocation MUST be defined and tested. Propagation, offline behavior, cache freshness, and false-revocation resistance MUST be defined (OPEN, post-MVP)."
- **SR-4 (discovery clause, identity-relevant)** (line 176): "Discovery MUST NOT be identity proof or authorization; … revocation through discovery MUST be authenticated…"
- Also touch identity: SR-3 (authorization distinct from identity), SR-5 ("protection MUST NOT rely on transport identity"), SR-6 (algorithm downgrade), SR-10 ("Apps and agents MUST receive explicit, scoped authority and MUST NOT inherit keys or grants").
- **MVP items (M-1, M-2, M-4, M-12)**: M-1 "Each peer MUST have a stable identity key and distinct ephemeral session keys; storage and destruction MUST be documented." M-2 "Both peers MUST prove possession and bind identities, versions, algorithms, and parameters; a peer MUST NOT complete as a different identity." M-4 "Peer identity MUST be verified independently of the discovery record before protected data is exchanged." M-12 "The MVP MUST document first-contact trust decisions and the risk of the wrong identity."
- Threat IDs tied to identity: T1 (impersonation), T2 (private key theft), T4 (MITM / identity binding), T12 (revocation & stale authorization), T14 (Sybil/identity churn).

### Open security questions relevant to identity (section 10, line 200: "must not be silently chosen or presented as guarantees")
- "**Identity and keys.** What is an identity, how is it encoded and displayed, and which algorithms, sizes, rotation, and storage apply? No algorithm or key format is selected."
- "**Trust anchors.** Is trust manual, organizational, provider-based, transparency-based, or trust-on-first-use, and what is the failure mode? A global public-key directory and production PKI remain non-goals; may a deployment use a local, organizational, or limited directory?"
- "**Handshake.** What establishes the session, binds identities, derives keys, and yields forward secrecy?"
- "**Revocation and recovery.** What mechanism carries revocation (list, status service, signed statement, or peer-to-peer), how are identity-key, device, grant, and session revocation distinguished, and does recovery preserve identity? Propagation and offline behavior are post-MVP and OPEN."
- Also relevant: "**Versioning.** … No version number exists." / "**Clock and freshness.** … replay windows…" / "**Post-quantum policy.** When, if ever, are post-quantum algorithms required, and how would migration work?" / "**Agent delegation.** How does an agent authenticate…?"

### Statements the identity design MUST NOT contradict (exact)
- Line 90: "There is no mandatory global authority, directory, or production PKI; the MVP must not require one."
- Line 105 (non-goal): "A global public-key directory, mandatory centralized identity provider, or production decentralized PKI."
- Line 20: "Identity is cryptographic and stable; location and routes are ephemeral hints. … First contact, revocation propagation, and end-to-end protection through relays are OPEN."
- Line 18: "Discovery returns untrusted identity claims and reachability hints, not verified identity or trust. … authentication MUST NOT be treated as authorization, and transport security MUST NOT substitute for UPP identity binding."
- Line 88: "custom primitives are forbidden. Algorithms, encodings, and handshake are OPEN."
- Line 91: "No anonymity or metadata-free operation is claimed…" (identity doc must not claim anonymity/unlinkability).
- Line 80: "Agent identity, delegation, service naming, and user/device/service identity relationships are undefined; this document does not assume a model."
- MVP non-goals (line 238): "No global directory, mandatory identity provider, or production PKI…"
- Architecture README lines 21/25: "A peer identity must remain stable when its IP address, network interface, relay, or transport changes." / "Possession of a peer's public key proves control of a corresponding private key during an authenticated exchange. It does not grant permission…"
- References disclaimer (line 242): "They do not select algorithms or protocols." RFC 7748: "no algorithm is selected"; RFC 8032 (Ed25519/Ed448): "relevant if selected for identity proofs; not selected…"

## 4. Architecture and protocol context

- **`docs/architecture/README.md`** — five concerns (lines 11–15): "**Identity:** Stable cryptographic identity and key lifecycle." / "**Discovery:** Finding candidate peers and current connection information." / "**Authorization:** Deciding which authenticated peer may perform which action." / "**Session:** Negotiating, establishing, monitoring, and closing authenticated sessions." / "**Transport:** Moving encrypted bytes through direct paths or relays." Sections "Identity is not location" and "Identity is not authorization" (quotes above). Stage-2 roadmap is not referenced here; the doc is "exploratory and is not a finalized specification."
- **`ROADMAP.md`** exact relevant items (all unchecked `- [ ]`):
  - Stage 1: "- [ ] Define entities, identity lifecycle, and key rotation." and "- [ ] Define trust, authorization, revocation, and recovery requirements."
  - Stage 2: "- [ ] Specify peer identity format and fingerprint representation." (also "- [ ] Define session establishment and state machines.", "- [ ] Select encoding and canonicalization rules.")
  - Stage 4: "- [ ] Implement identity creation and verification."
  - Stage 5/Not-in-MVP: "- A mandatory centralized account or identity provider." / "- A global public-key directory." / "- A production-grade decentralized PKI."
  - MVP criteria: "Two independently configured peers can identify one another using stable cryptographic identities…"
- **`docs/protocol/README.md`**: "A versioned specification must define: … - Peer identity and key lifecycle." Design constraints: "Prefer established, reviewed cryptographic protocols and libraries. Do not invent cryptographic primitives. Avoid ambiguous encodings and implicit trust. Make downgrade behavior, replay protection, key rotation, and revocation explicit." Proposals: "Discuss significant changes in an issue before adding a numbered specification."
- **`docs/security/README.md` open questions (lines 42–47)**: "How should users verify a first-contact identity? / How should identities be recovered after key loss? / What is the revocation propagation model? / How can discovery resist Sybil attacks without a mandatory authority? / … / How are compromised devices removed from groups and delegated capabilities?" Required properties include "Separate long-term identity keys from ephemeral session/transport keys." and "Support key rotation, revocation, and recovery procedures."
- **Algorithms anywhere in repo (FACT):** none selected. Only mentions are threat-model References RFC 7748 (X25519/X448) and RFC 8032 (Ed25519/Ed448), both explicitly "not selected"; section 10 "No algorithm or key format is selected." Issue #2 itself asks: "Is the identity key an Ed25519 signing key, or should the identity format abstract over algorithms?"

## 5. Conventions

- **Markdown:** exactly one H1 per file (verified across all tracked `.md`); H2 sections only — no `###` exists anywhere in `docs/`; no YAML front matter; **no tables** in any current doc (lists and bold-lead bullets instead); code fences rare (` ```sh ` in `docs/development/README.md`, ` ```text ` diagram in root `README.md`); relative links with descriptive text, e.g. `[ROADMAP.md](../../ROADMAP.md)`, `[security model](README.md)`; em-dash headings ("Stage 1 — Requirements and threat model"); **"Open UPP"** is the project name spelling (root README line 72: `"Open UPP" is the working project name`), with "UPP" used adjectivally ("UPP identity", "UPP API").
- **`docs/architecture/` structure:** currently only `README.md`. Precedent from `docs/security/`: a topic file (`threat-model.md`) sits next to the README, so `docs/architecture/identity-and-key-lifecycle.md` matches existing structure. The threat model's numbered-section style (## 1. … ## 11. … + ## References) is the only example of a long-form design doc.
- **Decision-status labels:** none repo-wide except the threat model's "**Draft for review; not accepted.**" status block and the token **OPEN**. No Proposed/Accepted/Deferred convention exists; if used, it would be new.
- **Contribution rules affecting a design doc** (`CONTRIBUTING.md`): "For substantial changes, open an issue first…"; PRs: "Keep changes focused", "Link related issues", "Document security and compatibility implications", "Do not introduce undocumented wire-format changes"; "Protocol design proposals — Include the problem, goals, non-goals, threat model, trust assumptions, message/state-machine changes, compatibility strategy, failure modes, resource limits, abuse considerations, and an interoperability plan."
- **`GOVERNANCE.md`:** "Protocol and security changes require written rationale and review." / "Significant changes should be discussed in an issue or design proposal before implementation." / "Decisions should record alternatives, trade-offs, and compatibility implications."
- **PR template** (`.github/pull_request_template.md`): Summary / Related issue / Change type (Documentation, Protocol design, …) / Validation / Security and compatibility / Checklist (focused, tests, no secrets, read CONTRIBUTING).
- **CI / doc checks (FACT, negative):** no `.github/workflows/`, no markdownlint/vale/lychee/pre-commit configs; `.editorconfig` only (2-space indent, UTF-8, LF, `trim_trailing_whitespace=false` for `*.md`). Issue templates exist (`feature_request.yml` = "[Proposal]:" with required Security/privacy/abuse section; `bug_report.yml`).
- Prior-task artifact convention (untracked): reports under `.opencode/reports/<issue-topic>/agent-role-task.md`.

## 6. Related issues (fetched read-only via `gh`)

- **Issue #2** (OPEN, 0 comments) — "[Design] Define peer identity and key lifecycle". Objective: "Define what an Open UPP identity represents and how it is created, verified, rotated, revoked, and recovered." Questions: device/user/service/application/agent representation; Ed25519 vs algorithm-abstract identity format; fingerprint encoding/comparison; separation of long-term identity vs ephemeral session/transport keys; rotation/revocation/backup/recovery semantics; how first-contact verification prevents key substitution. Constraints: "Identity must be independent of IP addresses, transport endpoints, and Tailcat-specific identifiers. Possession of a public key must not itself grant service authorization." Deliverable: "A proposed identity model and lifecycle document with testable invariants and migration considerations."
- **Issue #3** (OPEN, 0 comments) — "[Research] Compare peer discovery architectures". Objective: "Evaluate how a peer can be discovered from a stable cryptographic identity without requiring one mandatory global directory." Models: manual out-of-band, local network, federated rendezvous, DHT, multiple providers/cached hints. Deliverable: "A comparison matrix and a recommended MVP discovery strategy. Clearly separate identity verification from endpoint discovery: discovery data is untrusted until authenticated." → identity doc should treat discovery as a downstream consumer of identity, not define it.
- **Issue #4** (OPEN, 0 comments) — "[Research] Evaluate Tailcat as an optional transport backend". Objective: evaluate Tailcat as first transport adapter "without making Open UPP depend on Tailcat-specific identities or wire formats." Deliverable: technical report + PoC + risks. "Tailcat is an experimental candidate backend, not a normative dependency or an official UPP component." → identity doc must keep identity format transport-agnostic.
- Issue #1 (threat model) still OPEN with 0 comments — the doc's own two-review acceptance gate is not yet satisfied.

## Facts still unknown
- Whether anyone has begun reviewing Issue #1 offline (0 public comments recorded; no other review artifacts in repo besides `.opencode/reports/threat-model-issue-1/`).
- Whether the Orchestrator intends the identity doc to also satisfy ROADMAP Stage 1 items 1–2 (checkbox state unchanged; no repo evidence either way).
- Whether local `main` will be fast-forwarded to `c6ad7fd` before new work branches (not done here — checkout not authorized/needed; new work should branch from `origin/main`, which contains the threat model).
- Whether a decision-status label scheme (Proposed/Accepted/Deferred) will be introduced — none exists today.
