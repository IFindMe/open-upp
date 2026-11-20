# Reviewer report: Open UPP threat model draft (Issue #1)

## TL;DR

- **Status:** REVIEW COMPLETE — the draft is broadly sound, honest about status, and unusually careful about not overclaiming.
- **Verdict:** **ACCEPT WITH CHANGES**.
- **Findings:** 1 BLOCKING, 2 MAJOR, 5 MINOR (8 total).
- **Blocking:** requirement IDs such as `SR-5.6` are cited but never individually defined; §7's traceability claim is therefore false and section 8 cannot be used as a requirement catalogue.
- **Major:** §10 reopens explicit §5/§11 non-goals (global directory/PKI; group scope); revocation is under-specified while `M-8` makes it an MVP requirement that Stage 4/ROADMAP does not contain.
- **Coverage:** all 15 required threat categories and all five Issue #1 questions are covered. First contact and insider are covered indirectly, not as standalone threats.
- **Standards:** RFC 9420 and RFC 8446 descriptions need two precision fixes; the other RFC descriptions are accurate and none implies implementation.
- **Scope:** only `docs/security/threat-model.md` was added; no unrelated tracked changes.
- **Commit:** fix F1–F3 (and preferably the MINOR items) before accepting/committing as the Issue #1 deliverable; re-review §5, §7, §8, §10, §11, and References. Do not close Issue #1 before the two-contributor review.

## Step 1: Inputs and review boundary [DONE]

Reviewed `docs/security/threat-model.md` (249 lines, 5,329 words) against:

- GitHub Issue #1, read with `gh issue view 1 --json title,body,state`.
- `README.md`, `docs/architecture/README.md`, `docs/security/README.md`, `docs/protocol/README.md`, `docs/development/README.md`.
- `ROADMAP.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SECURITY.md`, `CHANGELOG.md`.
- The writer handoff `.opencode/reports/threat-model-issue-1/writer-agent-T1-threat-model-draft.md`.

No project file was modified. This report is the only artifact written.

[PASS]

## Step 2: Scope and repository state [DONE]

`git status --porcelain` shows exactly:

```text
?? .opencode/
?? docs/security/threat-model.md
```

There are no tracked modifications, no staged changes, and no branch/commit actions. The only content change is the new threat-model document; `.opencode/` is the permitted untracked tooling/reports tree. No unrelated modifications were found.

[PASS]

## Step 3: Structure and repository conventions [DONE]

- Exactly one H1: `# Open UPP threat model` (`docs/security/threat-model.md:1`).
- 13 H2 sections, no H3 or deeper: `Status`, sections 1–11, `References`.
- All required sections are present: purpose/scope, assets, trust boundaries, actors/roles, assumptions/out-of-scope, adversary capabilities, threat analysis, mitigations/security requirements, residual risks, open security questions, MVP security requirements.
- No front matter, no tables, no `TODO`/`TBD`/`FIXME`/`XXX`, no placeholders.
- “Open UPP” spelling is consistent; no `OpenUPP`, `Open-UPP`, or `Open Upp` variants.
- US English: no British-spelling variants found in the scan.
- File is LF, ends with a newline, and has no trailing whitespace.
- All 11 relative links resolve to existing repository files. All 11 external links point to `rfc-editor.org` and were fetched successfully.
- No credentials, private keys, tokens, or secrets appear in the document.

[PASS]

## Step 4: Required threat-category coverage [DONE]

All required categories are present, each with a concrete scenario, assets, impact, required properties, and residual risk.

| Required category | Evidence | Status |
|---|---|---|
| Identity impersonation | T1 (`:150`) | Covered |
| Private key theft/compromise | T2 (`:151`), §5 (`:108`), T12 (`:161`) | Covered |
| Replay | T3 (`:152`), T6 (`:155`) | Covered |
| MITM | T4 (`:153`) | Covered |
| Unauthorized peer connections | T5 (`:154`) | Covered |
| Malicious discovery responses | T6 (`:155`) | Covered |
| Rendezvous/relay compromise | T7 (`:156`) | Covered |
| DoS/resource exhaustion | T8 (`:157`) | Covered |
| Metadata leakage/traffic analysis | T9 (`:158`) | Covered |
| Malicious/compromised transport backends | T10 (`:159`) | Covered |
| Downgrade/version attacks | T11 (`:160`) | Covered |
| Revocation/stale authorization | T12 (`:161`) | Covered (see F3) |
| Malicious apps/agents | T13 (`:162`) | Covered |
| Sybil | T14 (`:163`) | Covered |
| Supply chain | T15 (`:164`) | Covered |

Additional attack surfaces from the review checklist:

| Surface | Evidence | Status |
|---|---|---|
| First contact | T1 residual (`:150`), §9 (`:186`), §10 (`:200`), M-12 (`:232`) | Covered as residual/open; no standalone threat entry (note) |
| Key substitution | T1 (`:150`), T6 (`:155`) | Covered |
| Replay of discovery | T3 (`:152`), T6 (`:155`) | Covered |
| Eclipse | T6 (`:155`), T14 (`:163`) | Covered |
| Relay collusion | T7 (`:156`), §9 (`:193`) | Covered |
| Pre-auth DoS | T8 (`:157`) | Covered |
| Cross-protocol | T11 (`:160`) | Covered |
| Agent delegation/confused deputy | T13 (`:162`) | Covered |
| Insider | §4 (`:76`), §6 (`:140`), T5 (`:154`), §9 (`:192`) | Covered indirectly; no standalone threat entry (note) |

Overlaps (T1/T4 impersonation vs MITM; T5/T13 peer vs app over-privilege; T6/T14 discovery poisoning vs Sybil; T2/T12 key theft vs revocation) are complementary and do not create contradictions.

[PASS]

## Step 5: GitHub Issue #1 questions [DONE]

| Issue #1 question | Where answered | Status |
|---|---|---|
| Which network attackers are in scope (passive, active, on-path, malicious relay)? | §4 (`:55-79`), §6 (`:118-144`), T4 (`:153`), T7 (`:156`) | Covered explicitly; all four named |
| What happens when a peer device or long-term key is compromised? | T2 (`:151`), T5 (`:154`), T12 (`:161`), §5 (`:108`) | Covered: impersonation until revocation, containment, detection limits, historical confidentiality limits |
| What can discovery and relay operators observe? | T6 (`:155`), T7 (`:156`), T9 (`:158`), SR-9 (`:178`) | Covered: queries, relationships, timing, service names, possible content depending on termination |
| How are replay, downgrade, identity substitution, Sybil attacks, and denial of service handled? | T1 (`:150`), T3 (`:152`), T8 (`:157`), T11 (`:160`), T14 (`:163`); SR-1/4–6/8 | Covered at requirement/residual level; mechanisms are correctly marked OPEN |
| What security properties are explicitly out of scope for the MVP? | §5 (`:95-106`), §11 (`:237`) | Covered |

Issue #1 also requires two-contributor review before acceptance. The document handles this honestly in `Status` (`:5-7`) and does not claim acceptance; the review itself remains outstanding (UNVERIFIED).

[PASS]

## Step 6: Technical accuracy and architecture boundary [DONE]

Confirmed:

- Authentication, authorization, discovery, and transport security are explicitly separated in `Do not conflate` (`:17`) and repeated throughout §3 and §5.
- Stable identity keys are distinguished from ephemeral session/transport keys (`:31`, `:171`, M-1 at `:221`).
- Transport success is repeatedly rejected as trust: `:17`, `:46`, `:49`, `:53`, `:144`.
- Rendezvous, relays, transport backends, and NAT helpers are treated as potentially untrusted (`:50-53`, `:69-71`, `:86`).
- Forward secrecy is a requirement, not a current property (`:115`, `:171`, `:174`); `T2` correctly conditions historical confidentiality on its presence.
- No anonymity, metadata-free operation, relay blindness, or complete Sybil/DoS protection is claimed.
- No identity algorithm, key format, handshake, discovery mechanism, policy language, relay architecture, trust anchor, PKI, global directory, version number, NAT technique, or relay authentication model is selected; §10 marks them OPEN.
- The open questions otherwise align with `docs/security/README.md:40-47` (first contact, recovery, revocation, Sybil, metadata, compromised devices), and no alternative trust model is invented.
- Revocation distinctions are listed in T12 (key, grant, device, session), but not defined as a taxonomy; see F3.
- The document does not claim any protection is implemented (`:6`, `:19`, `:148`, `:168`).

Defects found in this step: F1 (requirement IDs), F2 (non-goal/open-question contradiction), F3 (revocation), F5 (physical attacks/device theft), F6 (discovery wording).

[FAIL]

## Step 7: Standards accuracy [DONE]

Fetched and checked the RFC abstracts/text for RFC 9420, 9380, 7748, 8032, 8446, 7258, and 3552.

| Reference | Accuracy | Finding |
|---|---|---|
| RFC 9420 (MLS) | Title and “group key agreement and member authentication” are accurate. “Relevant only if multi-party sessions are considered” is imprecise: RFC 9420 explicitly supports groups “ranging from two to thousands,” so MLS is applicable to two-party sessions too. | F4 |
| RFC 9380 (hash-to-curve) | Accurate; described only as a possible future primitive, with no current requirement. | None |
| RFC 7748 (X25519/X448) | Accurate; correctly notes that key agreement alone does not authenticate peers. | None |
| RFC 8032 (EdDSA) | Accurate; correctly notes Ed25519/Ed448 are signature schemes, not encryption/key agreement by themselves. | None |
| RFC 8446 (TLS 1.3) | Title and transcript-binding/downgrade description are accurate. “TLS 1.3 is authenticated” overgeneralizes: RFC 8446 Appendix C.5 describes unauthenticated operation when credentials are not validated. | F4 |
| RFC 7258 (pervasive monitoring) | Accurate; correctly avoids implying an Open UPP anonymity property. | None |
| RFC 3552 (security considerations) | Accurate as a methodology reference; correctly disclaims compliance. | None |
| Implementation implication | References (`:241`) explicitly say Open UPP does not implement these unless a later specification says so; no algorithm selection is implied. | None |

[FAIL] (two precision defects, both MINOR)

## Step 8: Requirements quality and traceability [DONE]

Confirmed:

- Requirement groups SR-1–SR-11 and MVP requirements M-1–M-14 exist and are grouped.
- Every threat cites requirement groups or IDs.
- OPEN decisions are marked in §8 and §10.
- MVP requirements are mostly testable in principle.

Defects found:

- Individual `SR-x.y` IDs are cited but never defined; §8 only gives ranges. This is F1 and is the reason this step fails.
- Many requirements are “MUST be defined/documented” process requirements rather than testable protocol properties, while §8 calls them “testable requirements.” This is F7.
- Threat entries list assets but not an explicit trust-boundary field. This is F8.
- Revocation is under-specified and `M-8` over-scopes the MVP. This is F3.
- The §8 introduction distinguishes “restates the security model” from “adds” at a high level, but does not tag each requirement group as existing direction vs new requirement vs OPEN. Acceptable for a draft; a per-group source tag would improve auditability.

[FAIL]

## Step 9: Editorial and maintainability [DONE]

- The document is dense but structured; no filler paragraphs or broken links.
- 5,329 words is 6.6% above the writer’s own 5,000-word upper target. The length is justified by 15 threats and 11 requirement groups; no material repetitive filler was found, though the “not guaranteed”/“OPEN” caveats recur across §1, §5, §7, §8, §9, and §11. Optional consolidation only.
- Long paragraphs (several threat entries exceed 500 characters per line) make diff review harder, but this does not rise to a defect.
- No tables, no front matter, no secrets, no placeholders, consistent “Open UPP” spelling and US English.

[PASS]

## Step 10: Scope check [DONE]

In scope confirmed: `docs/security/threat-model.md` is the only new content file. `.opencode/` is untracked tooling/reports and is permitted by the brief. No tracked file was modified, and no commit/branch/push action was performed.

Out of scope found: none.

Note: `CHANGELOG.md` has no entry for the new threat model. The brief restricts changes to the threat model, so this is not a finding; the Maintainer may decide whether a follow-up changelog entry is required by repository convention.

[PASS]

## Findings

### F1 — BLOCKING — Individual requirement IDs are cited but never defined

- **Evidence:** `docs/security/threat-model.md:148` says “IDs are stable for specifications, tests, and reviews; … requirement references point to section 8.” Threats then cite individual IDs, e.g. T2 at `:151` cites `SR-5.6`, `SR-7.1–SR-7.2`, `SR-10.4`, `SR-11.3`; T4 at `:153` cites `SR-5.3` and `SR-5.5`; T10 at `:159` cites `SR-6.5`. Section 8 (`:170-180`) only defines ranges, e.g. “SR-5.1–SR-5.8: negotiation and messages MUST be authenticated…”, with no per-ID mapping. There is no definition anywhere for `SR-5.6`, `SR-10.4`, or `SR-6.5`.
- **Exact problem:** The document’s core traceability claim is false. A reader can see that `SR-5.6` belongs to the SR-5 group but cannot tell which clause it is; several groups have more cited IDs than prose clauses (e.g. SR-2.1–SR-2.7 has about six clauses; SR-3.1–SR-3.8 has about five; SR-7.1–SR-7.6 has three). The inconsistency is visible even within T1/T14: T1 cites `SR-1.1–SR-1.5` while T14 cites `SR-1.6 (OPEN)`, but neither `SR-1.5` nor `SR-1.6` is individually defined.
- **Why it matters:** The task requires required properties mapped to requirement IDs; the document promises stable IDs for specifications, tests, and reviews. Implementers and test authors cannot resolve the IDs, reviewers cannot verify threat coverage, and the acceptance gate cannot be audited. This is not a cosmetic numbering issue; it defeats the document’s main traceability mechanism.
- **Recommended correction:** Enumerate every `SR-x.y` with a one-sentence, testable statement (for example, a sub-bullet list under each SR group), and make every threat citation point to an existing ID. If enumeration is intentionally deferred, replace all individual-ID citations with group-level references (`SR-1`, `SR-5`) and remove the “IDs are stable” claim. Add a mechanical check that every cited `SR-x.y` has a definition.
- **Certainty:** FACT.

### F2 — MAJOR — §10 open questions contradict explicit non-goals

- **Evidence:** `docs/security/threat-model.md:104` lists “A global public-key directory, mandatory centralized identity provider, or production decentralized PKI” as an explicit non-goal; `:237` repeats “No global directory, mandatory identity provider, or production PKI.” But `:200` asks, “Is any PKI or global directory used?” Similarly, `:101` lists “Multi-party and group semantics” as a non-goal, while `:214` asks whether “group sessions and authorization [are] in scope after the MVP.”
- **Exact problem:** The document says unresolved decisions must not be silently chosen (`:197`), but §5/§11 already answer the global-directory/PKI and group-scope questions as non-goals. A reader cannot tell whether the global directory is forbidden, optional, or merely deferred, or whether group semantics are permanently out of scope or only out of scope for this document/MVP.
- **Why it matters:** Scope contradictions undermine the assumptions that later protocol decisions must respect. An implementer could read §10 as authorization to consider a global directory after all, despite §5/§11 saying it is a non-goal. This is exactly the kind of ambiguity a threat model is supposed to remove.
- **Recommended correction:** Scope §10 precisely: ask whether a *non-global, local, organizational, or limited* PKI/directory is used, and state that a global public-key directory remains out of scope. Rephrase group scope as “deferred beyond the MVP; not a commitment,” or remove it from open questions. If the intent is to reconsider these non-goals, label them “non-goals for this document and MVP, not permanent.”
- **Certainty:** FACT.

### F3 — MAJOR — Revocation is under-specified and M-8 over-scopes the MVP

- **Evidence:** `docs/security/threat-model.md:161` (T12) lists revoked key, revoked grant, revoked device, and revoked session, but never distinguishes their semantics. `:176` (SR-7) treats revocation as one group; `:206` asks only what mechanism is used (“list, status service, signed statement, or peer-to-peer”), not how key/device/grant/session revocation differ. `:228` (M-8) makes revocation an MVP requirement: “Keys and sessions MUST support revocation; a revoked identity MUST be denied at establishment.” But `ROADMAP.md:34-40` (Stage 4) does not list revocation, and `docs/security/threat-model.md:206` says the revocation model is OPEN. (`ROADMAP.md:16` does require revocation *requirements* in Stage 1, so the gap is MVP scope, not the existence of the requirement.)
- **Exact problem:** M-8 requires an MVP capability whose design is explicitly unresolved, and the document does not define whether revoking an identity key, a device, a grant, or a live session means the same thing. The four objects have different scopes, authorities, and failure modes; treating them as one “revocation” requirement makes M-8 untestable and leaves T12’s scenarios only partly addressed.
- **Why it matters:** MVP acceptance would either require an unspecified mechanism or quietly expand Stage 4 beyond ROADMAP. The task specifically asks for revocation distinctions (identity key/device/grant/session), and this is the place where the document is weakest.
- **Recommended correction:** Add a short taxonomy: identity-key revocation (compromise/rotation), device revocation (a device loses authority while the principal/identity may continue), grant/capability revocation (scope/time), and session termination (existing sessions). State which are in scope for the MVP. Either move M-8 to post-MVP or add revocation to Stage 4/ROADMAP via a separate scope decision and mark M-8 conditional on that decision. Cross-reference T12, SR-7, §10, and ROADMAP.
- **Certainty:** FACT for the textual mismatch; STRONG INFERENCE for the scope-expansion risk.

### F4 — MINOR — Two RFC descriptions need precision

- **Evidence:** `docs/security/threat-model.md:243` says RFC 9420 is “relevant only if multi-party sessions are considered.” RFC 9420’s abstract says MLS supports groups “ranging from two to thousands,” so MLS is applicable to two-party sessions too. `:112` says “TLS 1.3 is authenticated and transcript-bound.” RFC 8446 Appendix C.5 (“Unauthenticated Operation”) describes TLS 1.3 negotiation without verifiable server authentication when credentials are not validated; authentication depends on credential validation.
- **Exact problem:** Both statements are overgeneralizations. The RFC 9420 sentence wrongly narrows MLS to multi-party only; the TLS sentence wrongly treats authentication as inherent to TLS 1.3 rather than dependent on certificate/PSK validation. Neither error implies that Open UPP implements these protocols, but both weaken the document’s standards accuracy.
- **Why it matters:** The task requires accurate RFC references and no overclaiming. A standards-literate reviewer will notice these, and the TLS wording could obscure the very point the document is making (a TLS endpoint may be a relay, not the intended peer).
- **Recommended correction:** RFC 9420: “Relevant if group/multi-party sessions are considered; MLS also supports two-member groups, but no MLS use is selected for the MVP.” RFC 8446: “TLS 1.3 provides transcript-bound channel protection and, when credentials are validated, endpoint authentication; the endpoint may still be a relay or unrelated service.”
- **Certainty:** FACT.

### F5 — MINOR — “Physical attacks” non-goal conflicts with T2 device theft

- **Evidence:** `docs/security/threat-model.md:98` excludes “Physical attacks and side channels, including power, timing, electromagnetic, acoustic, fault-injection, and hardware implants.” T2 at `:151` includes “device theft exposes a long-term key,” and §5 at `:108` discusses compromised devices.
- **Exact problem:** Device theft is a physical attack, yet it is a key-theft scenario the document analyzes. The likely intent is to exclude physical side-channel/tampering/hardware attacks, not theft or endpoint compromise.
- **Why it matters:** A reader cannot tell whether device theft is in scope as endpoint compromise or excluded by the non-goal. This is a small but real contradiction in scope.
- **Recommended correction:** Narrow the non-goal to “physical side-channel, tampering, and hardware-implant attacks,” and add: “Device theft is treated as endpoint compromise under §5 and T2; the protocol cannot prevent it.”
- **Certainty:** FACT.

### F6 — MINOR — “Discovery returns … not identity” is imprecise

- **Evidence:** `docs/security/threat-model.md:17` says “Discovery returns untrusted reachability hints, not identity or trust.” But `:47` says results are hints “until verified against the claimed identity,” and `:67` says discovery “publishes or resolves identity-to-endpoint records.”
- **Exact problem:** Discovery records do carry identity claims (keys, names, records); they are simply untrusted until verified. Saying “not identity” conflates “unverified identity claim” with “no identity data,” and conflicts with the document’s own description of discovery records.
- **Why it matters:** An implementer could read this as permission to ignore identity binding in discovery records, which would make T1/T6 worse. The correct distinction is verified vs unverified, not identity vs no identity.
- **Recommended correction:** Reword to: “Discovery returns untrusted identity claims and reachability hints, not verified identity or trust.”
- **Certainty:** FACT.

### F7 — MINOR — Requirement semantics are ambiguous: undefined normative keywords and “testable” process requirements

- **Evidence:** `docs/security/threat-model.md:6` says “MUST, SHOULD, and MAY describe future specifications” but never cites RFC 2119/BCP 14 or defines their normative force. `:168` calls section 8 “testable requirements,” yet many requirements are process/meta requirements: `:170` “canonical encoding, display, comparison, first contact, and trust-on-first-use MUST be defined”; `:171` “storage and isolation MUST be defined (OPEN)”; `:173` “provider retention MUST be documented”; `:178` “the project MUST document what … observers see”; `:180` “dependencies MUST be pinned, reviewed, and recorded with provenance.”
- **Exact problem:** The document uses uppercase normative keywords without defining them, and calls a set of “MUST be defined/documented” process requirements “testable.” Readers cannot tell whether MUST is a current obligation, a future specification requirement, or an aspirational design goal, and many requirements cannot be tested without first defining the underlying decision.
- **Why it matters:** The document’s credibility depends on readers understanding that nothing is implemented. Ambiguous normative force can be misread as a current security claim, and calling process requirements “testable” overstates the maturity of the requirement set.
- **Recommended correction:** Add a status bullet: “MUST/SHOULD/MAY are used in the RFC 2119/BCP 14 sense for future specifications; they impose no current obligation.” Add RFC 2119 to References if used normatively. Rename “testable requirements” to “requirements, including design/process requirements,” and add acceptance criteria for the “MUST be defined/documented” items.
- **Certainty:** FACT.

### F8 — MINOR — Threat entries do not identify the trust boundary they cross

- **Evidence:** Each T1–T15 entry (`docs/security/threat-model.md:150-164`) has Scenario, Assets, Impact, Required, and Residual, but no Boundary field. §3 (`:40-53`) defines the boundaries separately.
- **Exact problem:** The task asks for assets/boundaries per threat. The scenarios imply a boundary (discovery, relay, local app, transport), but the mapping is implicit, so a reviewer cannot mechanically check that every boundary has threat coverage.
- **Why it matters:** Explicit boundary mapping improves traceability and would have made contradictions like F2/F5 easier to spot. It is a quality gap, not a correctness defect.
- **Recommended correction:** Add a short “Boundary” field to each threat (local device/app, identity/key use, network, discovery, authorization/enforcement, session/transport, infrastructure, supply chain/observability) or a compact mapping table after §7.
- **Certainty:** FACT.

## Verification verified

- Writer handoff claims: 1 H1, 13 H2, 0 H3; T1–T15 each with all five fields; M-1–M-14; 17 open questions; relative links resolve; no placeholders; no British spellings; no implemented-protection claim; only untracked `.opencode/` plus the new document. All verified. (The writer said “12 relative links”; the actual count is 11 relative plus 11 external, all resolving. This is a harmless handoff miscount.)
- Issue #1 text fetched with `gh issue view 1`; all five questions and the two-contributor review requirement are present.
- RFC 9420, 9380, 7748, 8032, 8446, 7258, and 3552 abstracts/text fetched; titles and descriptions are broadly accurate except F4.
- “No security property is implemented” is consistent with the repository (docs-only, no code).
- No broken internal links; external RFC links resolve.
- Document contains no secrets/credentials.

## Verification unverified

- **Two-contributor review:** not performed; `Status` (`:5-7`) says the document is a draft and not accepted. This is an outstanding process gate, not a document defect.
- **Whether M-8 is intended as a Stage 4 security acceptance criterion** or a post-MVP requirement: the document is ambiguous (F3).
- **Whether the global-directory/PKI and group-scope non-goals are permanent** or only for this document/MVP: the document is ambiguous (F2).
- **Whether first-contact and insider require standalone threat entries** under the project’s review standard: currently covered indirectly (T1/§9/§10/M-12; §4/T5/§9).
- **Explicit Stage 1 traceability:** `Status` (`:7`) makes it an acceptance requirement, but the document only says it “feeds Stage 1” (`:23`) and covers the Stage 1 topics; there is no mapping matrix. The acceptance review should confirm whether narrative coverage satisfies the gate.

## Scope compliance

- **In-scope confirmed:** `docs/security/threat-model.md` is the only new content file; all required sections and threat categories are present.
- **Out-of-scope found:** none.
- **Repository state:** no tracked modifications, no commit/branch changes.
- **Note:** `CHANGELOG.md` has no entry for the threat model; not required by the brief, but worth a Maintainer decision if repository convention expects one.

## Commit and re-review recommendation

- **Can it be committed as-is?** No. F1 is a blocking traceability defect for the document as the Issue #1 deliverable. A draft commit would still carry a false “requirement references point to section 8” claim unless that sentence is qualified.
- **After fixes:** Yes, commit as a draft after F1–F3 and the MINOR corrections. Do not mark Issue #1 complete until the two-contributor review is recorded.
- **Must be re-reviewed:** §7 and §8 after requirement enumeration (F1); §5, §10, §11 after non-goal/revocation alignment (F2/F3); References and §5 after standards wording (F4); §1 and §5/§3 after discovery and physical-attack wording (F5/F6); §8 after requirement semantics (F7); §7 after boundary mapping (F8).
- **Recommended next agent:** **Builder** for the documentation fixes within the approved scope. After the fixes, **Reviewer** re-review; **Orchestrator** coordinates the two-contributor gate and Issue #1 closure.

## Review verdict record

```text
Status: ACCEPT WITH CHANGES
Reviewed work: docs/security/threat-model.md (draft, Issue #1)
Approved scope / contract: Issue #1 threat-model requirements; repo docs and conventions
Findings: 1 BLOCKING, 2 MAJOR, 5 MINOR
Verification verified: structure, coverage, links, scope, RFC titles, writer claims
Verification unverified: two-contributor review; intent behind M-8 and the non-goal scope
Scope compliance: in-scope confirmed; no out-of-scope changes
Remaining uncertainty: whether non-goals are permanent or MVP-only; whether M-8 is Stage 4 or post-MVP; whether narrative coverage satisfies the Stage 1 traceability gate
Recommended next agent: Builder
Reason: defects are documentation fixes within the approved scope
Changes made by Reviewer: none to project files; this report only
```
