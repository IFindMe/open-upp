# Open UPP threat model

## Status

- **Draft for review; not accepted.** Issue #1 requires review by at least two contributors before acceptance.
- **Design-stage analysis, not a security guarantee.** No wire protocol or implementation exists; MUST, SHOULD, and MAY describe future specifications, not current behavior.
- **Normative terms.** MUST, SHOULD, and MAY are used in the RFC 2119/BCP 14 sense for future specifications; they impose no current obligation on this repository.
- **Review gate.** Acceptance requires recorded review by two contributors, resolution or explicit deferral of section 10, and traceability to Stage 1 in [ROADMAP.md](../../ROADMAP.md). Security reports follow [SECURITY.md](../../SECURITY.md).

## 1. Purpose and scope

This document gives contributors a shared, implementation-independent analysis of what Open UPP must protect, from whom, and under which assumptions. It supports protocol design and the MVP in section 11. The audience is protocol designers, implementers, security reviewers, discovery and relay operators, and application or agent developers.

The method is asset inventory, trust-boundary analysis, adversary capabilities, and threat enumeration with required properties, residual risk, and open dependencies. It follows [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html) but is not a formal proof, cryptographic analysis, penetration test, or risk-scoring exercise; impact is qualitative because no implementation or exploit evidence exists.

**In scope.** Identity (creation, representation, possession, rotation, revocation, recovery); discovery (records, resolution, freshness, providers, privacy); authorization (policy, grants, delegation, enforcement); session (negotiation, authentication, key establishment, protection, teardown); transport (direct paths, relays, adapters). The initial target is two-party application streams; multi-party, IP-layer, and datagram semantics are deferred.

**Do not conflate.** Authentication identifies the principal controlling the key and what was negotiated, not intent or permission. Authorization decides whether that principal may perform this operation on this resource now; it is not identity, reachability, or channel security. Discovery returns untrusted identity claims and reachability hints, not verified identity or trust. Transport security protects a channel between endpoints that may be relays; it does not establish UPP identity or authorization. Discovery success, TCP or TLS connections, relay acceptance, key lookup, and shared local networks MUST NOT be treated as peer trust; authentication MUST NOT be treated as authorization, and transport security MUST NOT substitute for UPP identity binding.

**Key conclusions.** No security property is implemented. Identity is cryptographic and stable; location and routes are ephemeral hints. Authorization must be explicit, scoped, revocable, resource-enforced, and deny-by-default. Rendezvous, relays, backends, and NAT helpers are potentially untrusted and may observe metadata, deny service, or manipulate traffic; no anonymity is claimed. Endpoint compromise cannot be prevented; limit blast radius, support revocation, and state what remains unprotected. First contact, revocation propagation, and end-to-end protection through relays are OPEN.

**Issue #1.** Attacker scope: sections 4 and 6. Compromised devices and keys: T2, T5, T12, section 5. Operator visibility: T6, T7, T9, SR-9. Replay, downgrade, substitution, Sybil, DoS: T1, T3, T8, T11, T14 and SR-1, SR-4–SR-6, SR-8. MVP exclusions: sections 5 and 11.

This expands the [security model](README.md), applies the [architecture](../architecture/README.md) and [protocol design](../protocol/README.md), and feeds Stage 1 and Stage 4 of [ROADMAP.md](../../ROADMAP.md). Review follows [CONTRIBUTING.md](../../CONTRIBUTING.md) and [GOVERNANCE.md](../../GOVERNANCE.md).

## 2. System assets

An asset is anything whose compromise reduces a security property; metadata, policy, patterns, or a stolen key can cause harm without content disclosure.

- **Long-term identity keys** — authenticity, integrity; compromise enables impersonation until revocation.
- **Trust material** (public keys, pins, fingerprints, first-contact decisions) — integrity; tampering silently redirects trust.
- **Ephemeral session keys and state** — confidentiality, integrity, freshness; must not become identity keys; past-session impact is OPEN.
- **Authorization policies, grants, delegations, capabilities** — integrity, authenticity, confidentiality, availability; policy reveals relationships, modification grants access.
- **Application data and peer identity binding** — confidentiality, integrity, authenticity in transit; the session principal must be the identity the application intended; protection after receipt is outside protocol control unless specified (OPEN).
- **Discovery metadata and relationship graphs** — privacy, integrity, freshness, availability; endpoints, presence, contacts, and timestamps reveal intent and relationships.
- **Availability of peers, rendezvous, and relays** — exhaustion, quotas, blocking, or provider failure can make reachable peers unreachable.
- **Security logs, diagnostics, and audit records** — integrity, confidentiality, availability; logs leak secrets, tampering hides attacks, deletion destroys accountability.
- **Build artifacts, dependencies, and update channel** — integrity, authenticity; a compromised artifact bypasses every protocol control.
- **User privacy and local key-store integrity** — confidentiality and authenticity of key use; a key usable only through policy differs from one available to every local process (OPEN).

## 3. Trust boundaries

Each boundary is where data or authority crosses domains. Ask what may be malicious or compromised and what must not be trusted. **No boundary currently has implemented enforcement.**

- **Local device, application, and key store.** Users, other apps, malware, backups, crash dumps, and shared files may be malicious or compromised. No app should have unrestricted long-term key use, and local storage is not automatically confidential; storage, memory handling, and key-use mediation are OPEN.
- **Identity and key use.** An app or agent requesting a signature, decryption, or identity assertion may be malicious or manipulated. A signature proves key use, not authorized use; proof and authorization must be separate, with policy-mediated key use (OPEN).
- **Network.** Passive observers, on-path attackers, middleboxes, hostile local networks, DNS, routing, and address translation may be malicious. Source addresses, reachability, ordering, and transport success must not be trusted; blocking direct paths to force relays is in scope.
- **Discovery.** Providers, caches, peer hints, and stale records may be malicious, compromised, or wrong. Results are hints until verified against the claimed identity; a provider must never redefine identity or act as an authorization authority.
- **Authorization decision and enforcement.** Policy stores, delegated apps, admin interfaces, and enforcement points may be compromised or misconfigured. Caller claims, names, roles, and discovery metadata are not authorization; enforcement must occur at the resource, not only at connection setup, and no enforcement point exists.
- **Session and transport.** Either endpoint, a replayed message, a compromised key, or a local process may inject or alter messages; messages require authentication, freshness, and binding to negotiated context. A backend, relay, adapter, or fallback may lie about status, terminate encryption, inject or drop data, leak metadata, or expose backend identifiers; transport identity and encryption are not UPP identity or authorization, and whether protection survives a relay is OPEN.
- **Rendezvous, relay, and infrastructure operators.** Providers, hosts, insiders, or colluding providers may observe who connects to whom, when, how often, from where, and possibly service names or content depending on termination; they may deny, delay, redirect, block, or retain logs. NAT helpers may learn addresses and manipulate mappings. Infrastructure is potentially untrusted even when operated by a trusted organization.
- **Supply chain and observability.** Dependencies, builds, CI, signing, registries, and updates may be malicious or compromised; artifacts are not trustworthy merely because the usual process produced them. Logs, telemetry, and operators may be malicious, compromised, or over-collecting; telemetry must not become an exfiltration channel, and retention, access, and redaction are OPEN.

**Relay and NAT caution.** Relays and rendezvous are potentially untrusted even when necessary. NAT traversal may expose addresses and relationships and may be manipulated. A successful relayed connection proves only that some relay forwarded bytes; it proves nothing about identity, authorization, or relay behavior. Whether UPP protection is end-to-end through relays, where it terminates, and what a relay can read or modify must be specified, implemented, and tested per path; transport encryption does not settle this because transport endpoints may be relays.

## 4. Actors and security roles

**Definitions.** A **principal** is the entity on whose behalf authority is exercised; one principal may control several identities. An **identity** is a cryptographic, key-bound representation of a principal, device, service, or agent; it is not a name, address, role, or permission. A **role** is a context-specific function; it grants no authority by itself. **Authorization** is permission for an operation on a resource under policy, not identity, role, reachability, or discovery.

**Actors.**

- **Identity owner or principal** — controls keys, trust, recovery, and revocation; usable security and consent are requirements.
- **Peer or endpoint** — holds an identity and establishes sessions; may be honest, compromised, malicious, or misconfigured.
- **Service or resource owner** — defines resources and policy; the source of authorization, not discovery.
- **Application** — consumes the UPP API; may be buggy, over-privileged, or malicious; must not inherit ambient authority.
- **Autonomous agent** — acts with delegated authority and limited oversight; identity, delegation, and accountability are undefined.
- **Authorization authority or policy owner** — evaluates policy; whether local, organizational, or delegated is OPEN.
- **Discovery provider** — publishes or resolves identity-to-endpoint records; may access queries and metadata; not an identity or authorization authority.
- **Discovery operator** — runs discovery infrastructure; may read logs, retain queries, deny service, or collude; potentially untrusted.
- **Relay provider** — forwards traffic when direct paths fail; may observe metadata and possibly content depending on termination.
- **Relay operator** — runs relay infrastructure; may observe, log, deny, delay, redirect, or collude; potentially untrusted.
- **Transport backend provider** — supplies a transport implementation or network; stability and security are not assumed.
- **Passive network observer** — observes without modifying, including ISPs and metadata collectors.
- **Active on-path attacker** — modifies, drops, reorders, injects, or replays; may control DNS, routing, or address translation.
- **Malicious or compromised peer** — holds a valid identity and possibly a grant but exceeds authorization or abuses resources.
- **Malicious or compromised app or agent** — misuses delegated authority, exfiltrates data, manipulates a user, or becomes a confused deputy.
- **Insider or operator** — has administrative access to infrastructure, policy, keys, or logs; may be malicious, coerced, or mistaken.
- **Supply-chain attacker** — compromises a dependency, build, artifact, or update channel to affect many deployments.

Agent identity, delegation, service naming, and user/device/service identity relationships are undefined; this document does not assume a model.

## 5. Assumptions and out-of-scope risks

**Assumptions.**

- The network is hostile; local networks are not trusted merely because they are local.
- Discovery, rendezvous, relays, NAT traversal, and transport backends are potentially untrusted, compromised, malicious, or colluding; availability and correctness are not guaranteed.
- Cryptography, if used, comes from established algorithms and libraries; custom primitives are forbidden. Algorithms, encodings, and handshake are OPEN.
- Endpoints may be compromised. A protocol cannot prevent an attacker controlling an endpoint from using its keys, reading its data, or lying to its user; it can limit blast radius, require revocation, and avoid making compromise worse.
- There is no mandatory global authority, directory, or production PKI; the MVP must not require one.
- No anonymity or metadata-free operation is claimed; unlinkability and resistance to a global passive adversary are not promised.
- Clock and freshness behavior are unresolved, and first-contact verification is unresolved; implementations must not assume synchronized clocks.
- NAT is normal; direct paths may be blocked, and the MVP must not depend on manually configured public addresses.
- Two-party application streams are the initial target; group, IP-layer, and datagram behavior are deferred.

**Explicit non-goals.**

- Full endpoint or operating-system compromise as a preventable event.
- Physical side-channel, tampering, and hardware-implant attacks, including power, timing, electromagnetic, acoustic, and fault-injection.
- Global volumetric denial of service and ISP-level censorship; local bounds do not defeat a global flood.
- Anonymity, unlinkability, resistance to a global passive adversary, and traffic-analysis resistance.
- Multi-party and group semantics, including group key agreement and authorization.
- IP-layer VPN or kernel networking, TUN devices, routing, and replacement of the public Internet.
- UDP and datagram semantics until stream semantics are validated.
- A global public-key directory, mandatory centralized identity provider, or production decentralized PKI.
- Legal, regulatory, content-moderation, coercion, and social-engineering outcomes, although user trust decisions are in scope.
- Protecting data after an authorized peer receives it.

**Key theft and compromised devices.** A compromised endpoint is not preventable, but the design must limit a stolen key's blast radius, support revocation, avoid leaking keys through logs or ambient access, define what can be detected, and state whether historical data remains protected. Authenticating a stolen key correctly still authenticates the attacker; compromise is a containment and recovery problem. Device theft is treated as endpoint compromise here and in T2; the protocol cannot prevent it.

**Revocation scope.** Revocation is not one property. **Identity-key revocation** withdraws a compromised or rotated key from future authentication. **Device revocation** removes one device's authority while the principal may continue. **Grant revocation** withdraws a scoped authorization. **Session termination** ends existing sessions. If revocation is included in the MVP, the MVP MUST deny a locally known revoked identity key or device at session establishment, MUST enforce locally known grant revocation at the next authorization decision, and MUST define termination for locally known revocation of an existing session; propagation to offline peers, caches, relays, and discovery is post-MVP and OPEN. Stage 4 of [ROADMAP.md](../../ROADMAP.md) as written does not list revocation, so M-8 is conditional on an explicit Stage 4 scope decision; otherwise M-8 is post-MVP.

**Challenged assumptions.**

- **"Transport security means the peer is trusted by Open UPP."** False. TLS 1.3 provides transcript-bound channel protection and, when credentials are validated, endpoint authentication ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)); its endpoint may still be a relay or unrelated service.
- **"If discovery returns a key, it is the right key."** A provider can substitute keys or endpoints, replay stale records, or return a colluding relay; verification must target the intended identity.
- **"Encryption hides metadata."** It hides content, not who connects, when, how often, or how much; pervasive monitoring treats metadata as an attack surface ([RFC 7258](https://www.rfc-editor.org/rfc/rfc7258.html)).
- **"Forward secrecy solves key compromise."** It protects past sessions only if correctly implemented; it does not stop future impersonation before revocation.
- **"Rate limiting solves Sybil attacks."** Rate limits raise cost but do not establish that distinct identities represent distinct principals.

## 6. Adversary capabilities

This defines the attacker envelope later decisions must respect; it does not claim every attacker has every capability at once.

**By phase.**

- **Before authentication:** observe discovery; enumerate endpoints and services; claim names; poison records; block direct paths to force relays; open many connections; consume pre-auth state; socially engineer identity choice.
- **During the handshake:** observe, modify, drop, reorder, inject, and replay; strip versions and algorithms; relay a handshake; substitute identity or keys; exploit parsing and state-machine bugs; force retries; exhaust CPU or memory.
- **After authentication:** replay requests or authorization material; exceed scope; tamper with or drop data; observe patterns; attempt hijacking if keys leak; request unintended operations; exploit an app or agent.
- **During discovery and at infrastructure:** poison records; return stale endpoints; publish false revocation; eclipse with attacker providers; collude; infer relationships; create many identities; deny or degrade service; manipulate NAT; alter logs.

**Adversary classes.**

- **Passive observer:** sees addresses, timing, volume, frequency, and cleartext metadata; can correlate behavior but not read end-to-end protected content.
- **Active on-path attacker:** modifies, drops, reorders, injects, replays; controls DNS, routing, or paths; blocks direct routes; tampers with discovery; attempts downgrade or relay attacks.
- **Malicious or compromised rendezvous or relay:** observes metadata, refuses or delays service, manipulates forwarding, redirects, retains logs, targets users, colludes; content access depends on the unresolved end-to-end design.
- **Malicious authenticated peer:** holds a valid identity and possibly a grant but exceeds authorization, abuses resources, replays, or attacks other peers.
- **Compromised peer with long-term keys:** impersonates until revocation, signs what the key may sign, reads endpoint data, and may decrypt sessions if forward secrecy is absent.
- **Malicious app or agent with delegated access:** exceeds delegated authority, acts as a confused deputy, exfiltrates data, manipulates its user, or is manipulated through content.
- **Sybil or identity-churn adversary:** creates many cheap identities, pollutes discovery, consumes quotas, evades blocks, and distorts trust signals.
- **Resource-exhaustion adversary:** floods connections, opens partial sessions, triggers expensive cryptography, sends oversized input, holds sessions open, and amplifies through discovery or relays.
- **Supply-chain adversary:** compromises a dependency, build runner, release credential, artifact repository, or update channel, influencing many deployments.
- **Insider or misconfiguration adversary:** reads logs, changes policy, grants broad access, disables checks, exposes services, or deploys test keys, maliciously or by mistake.

**Excluded.** Breaking vetted cryptography; compromising every endpoint, operator, and dependency simultaneously; a cryptographically relevant quantum adversary (post-quantum policy OPEN); guaranteed anonymity or defeating a global passive adversary; physical side-channel, tampering, and hardware-implant attacks; device theft is treated as endpoint compromise; coercion through legal, regulatory, or social means.

**Not trust anchors.** No capability becomes less dangerous because a lookup or connection succeeded; those events are preconditions for communication, not evidence of identity or permission.

## 7. Threat analysis

Threat IDs T1–T15 are stable for specifications, tests, and reviews; requirement references use the defined group IDs SR-1 through SR-11. Impact is qualitative, and **OPEN** means the requirement depends on an undecided design. No threat is mitigated by the current repository.

- **T1 Identity impersonation.** **Scenario:** a discovery record, lookalike name, truncated fingerprint, or relay presentation causes the wrong key to be accepted. **Assets/boundaries:** identity, trust; discovery and session boundaries. **Impact:** wrong peer, disclosure, unauthorized access, corrupted audit. **Required:** SR-1, SR-3, SR-4; names are not authoritative and comparison is OPEN. **Residual:** first contact OPEN, human error, provider lies; undetected impersonation is not guaranteed to be prevented.
- **T2 Private key theft.** **Scenario:** malware, backup, crash dump, log, or device theft exposes a long-term key; stolen use is undetected; recorded sessions may be decrypted if forward secrecy is absent. **Assets/boundaries:** identity keys, sessions, data, grants; local device and key-use boundaries. **Impact:** impersonation until revocation, unauthorized access, forged grants. **Required:** SR-2, SR-5, SR-7, SR-10, SR-11. **Residual:** compromise is unpreventable; detection, timely revocation, and historical confidentiality are not guaranteed.
- **T3 Replay attacks.** **Scenario:** replay of a handshake, grant, command, discovery record, or signed message in another session. **Assets/boundaries:** session state, grants, integrity, freshness; session and discovery boundaries. **Impact:** duplicate operations, unauthorized action, session confusion. **Required:** SR-3, SR-4, SR-5, SR-7, SR-8; mechanism OPEN. **Residual:** clock skew, offline windows, long-lived tokens; replay rejection is not guaranteed until tested.
- **T4 Man-in-the-middle attacks.** **Scenario:** an on-path attacker terminates TLS; a relay terminates and re-originates; a handshake is relayed; a certificate is not bound to the UPP identity. **Assets/boundaries:** session keys, identity binding, data, authorization; session, transport, and relay boundaries. **Impact:** eavesdropping, tampering, impersonation, false audit. **Required:** SR-1, SR-5, SR-6, SR-11. **Residual:** relay termination is in the middle by design; channel binding and end-to-end termination are OPEN; end-to-end protection is not guaranteed.
- **T5 Unauthorized connections and over-privileged peers.** **Scenario:** an authenticated peer requests an ungranted service; default allow; wildcard grant; compromised peer; insider lateral movement; role treated as permission. **Assets/boundaries:** policy, grants, data, availability; authorization and session boundaries. **Impact:** unauthorized access, lateral movement, persistent over-privilege. **Required:** SR-3, SR-10, SR-11. **Residual:** misconfiguration, OPEN policy model, enforcement bugs; a valid identity is not guaranteed benign and enforcement is not guaranteed.
- **T6 Malicious discovery responses.** **Scenario:** a provider returns an attacker endpoint, stale address, false revocation, eclipse, collusion, replayed record, or name collision. **Assets/boundaries:** discovery metadata, identity, availability, privacy; discovery boundary. **Impact:** redirection, denial of service, false revocation, privacy leak. **Required:** SR-1, SR-3, SR-4. **Residual:** no authenticity or conflict design, providers can lie or collude; correctness, freshness, and availability are not guaranteed.
- **T7 Rendezvous and relay compromise.** **Scenario:** a relay logs who connects to whom, when, and which service; denies, injects, drops, reorders, manipulates NAT, colludes, or retains logs. **Assets/boundaries:** metadata, privacy, availability, data if termination occurs; relay and infrastructure boundaries. **Impact:** surveillance, denial of service, censorship, privacy loss. **Required:** SR-4, SR-5, SR-8, SR-9, SR-11; relay authentication OPEN. **Residual:** metadata is partly visible, providers may collude, termination is OPEN; relay metadata confidentiality and content protection are not guaranteed.
- **T8 Denial of service and resource exhaustion.** **Scenario:** pre-auth flood; expensive cryptography; oversized or deeply nested messages; slowloris; half-open sessions; amplification; identity churn; replay-cache flooding. **Assets/boundaries:** availability, CPU/memory/session state, audit; network, discovery, and relay boundaries. **Impact:** outage, cost, degraded service, state exhaustion. **Required:** SR-4, SR-8, SR-11. **Residual:** volumetric attacks are out of scope, distributed exhaustion can exceed local limits; availability under attack is not guaranteed.
- **T9 Metadata leakage and traffic analysis.** **Scenario:** an observer sees addresses, timing, volume, and frequency; discovery queries reveal interest; relay logs reveal relationships; retries and sizes reveal behavior. **Assets/boundaries:** privacy, relationship graphs, discovery metadata, logs; network, discovery, relay, and observability boundaries. **Impact:** surveillance, correlation, targeting, chilling effects. **Required:** SR-4, SR-5, SR-9, SR-11. **Residual:** traffic analysis remains, no padding is required, IPs are visible; minimization, unlinkability, and relationship hiding are not guaranteed.
- **T10 Malicious or compromised transport backends.** **Scenario:** a backend lies about status, injects or drops data, leaks metadata, ignores the session layer, bypasses encryption, exposes identifiers, or falls back to a weaker path. **Assets/boundaries:** session integrity, identity binding, metadata, data; transport and supply-chain boundaries. **Impact:** eavesdropping, tampering, identity confusion, privacy leak. **Required:** SR-1, SR-5, SR-6, SR-8, SR-11. **Residual:** APIs are unstable, adapter bugs may leak semantics, end-to-end is OPEN; backend honesty and protection are not guaranteed.
- **T11 Downgrade and protocol-version attacks.** **Scenario:** an attacker strips version or algorithm offers; a peer accepts an old weak mode; extension confusion; cross-protocol acceptance; silent fallback; an unknown critical extension is ignored. **Assets/boundaries:** session security, authentication, data, protocol state; session boundary. **Impact:** weakened cryptography, authentication bypass, impersonation, MITM. **Required:** SR-5, SR-6. **Residual:** OPEN version policy, no version number; downgrade resistance and cross-protocol isolation are not guaranteed.
- **T12 Revocation and stale authorization.** **Scenario:** a revoked key is accepted from cache; a revoked grant remains valid; a revoked device keeps a session; revocation is not propagated; false revocation; recovery reuses identity. **Assets/boundaries:** grants, policy, identity, session state; authorization, identity/key-use, and session boundaries. **Impact:** unauthorized access persists, over-privilege survives revocation, denial of service. **Required:** SR-2, SR-3, SR-7, SR-11. **Residual:** MVP scope, if M-8 is included, is local revocation at session boundaries; propagation, offline behavior, and recovery are post-MVP or OPEN; timely global revocation and termination are not guaranteed.
- **T13 Malicious applications and agents.** **Scenario:** an app uses the identity key with ambient authority; an agent exceeds scope; a service is a confused deputy; content manipulates an agent; a long-lived grant survives its task. **Assets/boundaries:** keys, grants, data, policy, audit; local, key-use, and authorization boundaries. **Impact:** unauthorized actions, exfiltration, privilege escalation, consent violation. **Required:** SR-2, SR-3, SR-9, SR-10, SR-11. **Residual:** agent identity is undefined, prompt injection cannot be fully prevented, OS access bypasses controls; containment and meaningful consent are not guaranteed.
- **T14 Sybil and identity churn.** **Scenario:** an attacker creates many cheap identities, floods discovery, consumes quotas, evades blocks, inflates presence, eclipses a victim, or sends rotating spam. **Assets/boundaries:** discovery integrity, resources, trust signals, authorization state; discovery and infrastructure boundaries. **Impact:** denial of service, poisoning, abuse, increased cost. **Required:** SR-1, SR-4, SR-8, SR-11; rate limits are not proof of uniqueness. **Residual:** no reputation system, identity cost conflicts with privacy; Sybil resistance is not guaranteed.
- **T15 Supply-chain and implementation compromise.** **Scenario:** a malicious dependency, compromised build runner, unsigned artifact, hijacked update channel, telemetry leak, shipped test keys, or parser vulnerability. **Assets/boundaries:** artifacts, keys, data, trust, logs; supply-chain and observability boundaries. **Impact:** mass compromise, key theft, backdoors, malware through trusted updates. **Required:** SR-2, SR-10, SR-11. **Residual:** builds and signing are not set up, CI is a target, malicious behavior is hard to detect; build integrity, dependency trust, and update authenticity are not guaranteed.

## 8. Mitigations and security requirements

The [security model](README.md) sets design direction. This section states requirements, including design and process requirements, and adds deny-by-default enforcement, transcript and channel binding, authenticated version negotiation, replay rejection, local revocation at session boundaries, first-contact decisions, Sybil limits, key-use isolation, supply-chain integrity, and negative tests. **No requirement is implemented.** Requirement IDs are group-level SR-1 through SR-11; each group is defined below, and threat entries cite only these IDs. OPEN means blocked on section 10, not optional. For "MUST be defined/documented" items, acceptance is the named decision or document; protocol behavior requires a reproducible test.

- **SR-1 Authentication and identity.** Peers MUST prove possession and bind identity to session parameters; canonical encoding, display, comparison, first contact, and trust-on-first-use MUST be defined; discovery, transport success, relay acceptance, and key possession MUST NOT be authentication or authorization.
- **SR-2 Key lifecycle.** Long-term, session, and transport keys MUST be distinct; rotation and revocation MUST preserve continuity; secrets MUST NOT appear in logs, dumps, telemetry, or diagnostics; storage and isolation MUST be defined (OPEN); cryptography MUST use established algorithms; historical confidentiality without forward secrecy is not guaranteed.
- **SR-3 Authorization.** Access MUST be denied without an explicit scoped grant; authorization MUST be enforced per operation at the resource and SHOULD be auditable; delegation MUST be scoped, time-bounded, revocable, and attributable (OPEN); administrative access MUST require roles and audit.
- **SR-4 Discovery.** Discovery MUST NOT be identity proof or authorization; records MUST be verifiable and stale records rejected (OPEN); conflicts MUST NOT silently override; revocation through discovery MUST be authenticated; metadata MUST be minimized; provider retention MUST be documented without claiming full Sybil resistance.
- **SR-5 Session and transport.** Negotiation and messages MUST be authenticated, transcript-bound, and replay-protected (OPEN); protection MUST NOT rely on transport identity; the specification MUST state and test where protection terminates and what a relay sees (OPEN); key establishment SHOULD provide forward secrecy; failures MUST deny or terminate.
- **SR-6 Versioning.** Negotiation MUST be transcript-protected; unacceptable versions or algorithms MUST fail; unknown critical extensions MUST be rejected; supported versions and deprecation MUST be defined (OPEN).
- **SR-7 Revocation.** Revocation MUST distinguish identity-key, device, grant, and session scope. A locally known revoked identity MUST be denied at session establishment, and termination of an existing session on locally known revocation MUST be defined and tested. Propagation, offline behavior, cache freshness, and false-revocation resistance MUST be defined (OPEN, post-MVP).
- **SR-8 Resource bounds.** Connections, handshakes, memory, CPU, messages, sessions, queues, and retries MUST be bounded; over-limit input MUST be rejected safely; cryptography MUST be rate-limited; timeouts MUST be defined; responses MUST NOT amplify; relay quotas MUST be defined (OPEN).
- **SR-9 Privacy.** The project MUST document what peers, relays, rendezvous, and observers see per path; minimize metadata; define retention without secrets; MUST NOT claim anonymity, unlinkability, or traffic-analysis resistance.
- **SR-10 Applications and agents.** Apps and agents MUST receive explicit, scoped authority and MUST NOT inherit keys or grants; delegation MUST be scoped and revocable (OPEN); sensitive operations SHOULD require approval; signing SHOULD be policy-mediated; external content MUST be data.
- **SR-11 Operations and supply chain.** Dependencies MUST be pinned, reviewed, and recorded with provenance; artifacts SHOULD be reproducible or signed; no secret may appear in logs or test output; security events SHOULD be audited; updates MUST be authenticated; disclosure MUST follow [SECURITY.md](../../SECURITY.md); defaults MUST be secure.

## 9. Residual risks

Residual risk remains even after every requirement is met.

- **First contact.** Users can approve the wrong identity under pressure or social engineering; protocol requirements do not solve verification UX.
- **Endpoint compromise.** A compromised endpoint can act as the principal, read data, and misuse keys; detection is not guaranteed.
- **Revocation latency.** The MVP does not promise global or offline revocation; if M-8 is included, locally known revocation is enforced at session boundaries, and revoked keys or cached grants may remain usable elsewhere until expiry or reconnection.
- **Metadata and traffic analysis.** Content protection does not hide who communicates, when, or how much; no anonymity or unlinkability is claimed.
- **Sybil resistance and denial of service.** Cheap identities can pollute discovery and evade blocks, and local bounds cannot defeat a global flood.
- **Implementation and supply chain.** Parser, memory-safety, dependency, build, and algorithm compromises can bypass requirements; post-quantum policy is OPEN.
- **Misconfiguration and authorized actors.** Operators can expose services, grant wildcards, share keys, or disable checks; authorization limits blast radius without making an authorized actor benign.
- **Relay collusion.** Relays and rendezvous can collude, retain data, deny service, or disappear; concrete designs may reveal interactions this analysis misses.

## 10. Open security questions

These decisions are unresolved and must not be silently chosen or presented as guarantees.

- **Identity and keys.** What is an identity, how is it encoded and displayed, and which algorithms, sizes, rotation, and storage apply? No algorithm or key format is selected.
- **Trust anchors.** Is trust manual, organizational, provider-based, transparency-based, or trust-on-first-use, and what is the failure mode? A global public-key directory and production PKI remain non-goals; may a deployment use a local, organizational, or limited directory?
- **Handshake.** What establishes the session, binds identities, derives keys, and yields forward secrecy?
- **End-to-end termination.** Does protection terminate at peers or relays, what can a relay read, and what relay architecture is allowed?
- **Discovery.** How are records bound, freshness enforced, conflicts handled, and metadata exposed?
- **Policy model.** Is policy local, organizational, capability-based, attribute-based, or federated, and how are grants expressed, delegated, and audited?
- **Agent delegation.** How does an agent authenticate, how is authority scoped and revoked, and how are actions attributed?
- **Revocation and recovery.** What mechanism carries revocation (list, status service, signed statement, or peer-to-peer), how are identity-key, device, grant, and session revocation distinguished, and does recovery preserve identity? Propagation and offline behavior are post-MVP and OPEN.
- **Metadata and audit.** What metadata can be minimized, and what is logged, accessed, and retained? No anonymity or metadata-free claim is implied.
- **Versioning.** What versions exist, how long are they supported, and when is fallback allowed? No version number exists.
- **Relay trust.** Are relays authenticated, by whom, and what does that mean for user trust and authorization? No model is defined.
- **NAT traversal.** Which techniques are allowed, what do helpers see, and how are mappings protected?
- **Sybil resistance.** Which controls are quotas, cryptographic costs, or uniqueness proofs? No mechanism is selected.
- **Clock and freshness.** What synchronization is assumed, how are skew and offline operation handled, and what replay windows are acceptable?
- **Post-quantum policy.** When, if ever, are post-quantum algorithms required, and how would migration work?
- **Transport security.** Is TLS 1.3 or another transport layer required, optional, or forbidden, and where does it terminate?

## 11. Security requirements for the MVP

The MVP follows Stage 4 of [ROADMAP.md](../../ROADMAP.md): two independently configured peers identify one another with stable identities, discover a usable route, authenticate a session, enforce explicit authorization, and exchange data without manually configured public IPs or inbound port forwarding. These are minimum requirements; meeting them does not satisfy the full threat model.

- **M-1 Distinct keys.** Each peer MUST have a stable identity key and distinct ephemeral session keys; storage and destruction MUST be documented.
- **M-2 Authenticated session.** Both peers MUST prove possession and bind identities, versions, algorithms, and parameters; a peer MUST NOT complete as a different identity.
- **M-3 Deny by default.** At least one resource-level authorization decision MUST be enforced per protected operation; without a grant, access MUST be denied.
- **M-4 Untrusted discovery.** Peer identity MUST be verified independently of the discovery record before protected data is exchanged.
- **M-5 Transport independence.** Protection MUST NOT depend on a transport or relay trust; the MVP MUST state and test where it terminates and what a relay sees, and MUST NOT call a relayed path end-to-end unless tested.
- **M-6 Replay rejection.** Replayed handshake, authorization, and application messages MUST fail with no duplicate effect; replay state MUST be bounded.
- **M-7 Authenticated negotiation.** Negotiation MUST be authenticated; tampering and unacceptable versions or algorithms MUST fail, without silent fallback.
- **M-8 Local revocation at session boundaries (conditional).** If Stage 4 scope is extended to include revocation, the MVP MUST deny a locally known revoked identity key or device at session establishment, MUST enforce locally known grant revocation at the next authorization decision, and MUST define and test termination for locally known revocation of an existing session. Propagation, offline revocation, and global revocation are post-MVP and OPEN. Stage 4 scope confirmation is required; if not extended, M-8 moves to post-MVP.
- **M-9 Bounded resources.** Documented limits on handshakes, connections, messages, sessions, timeouts, and retries MUST be enforced.
- **M-10 No secrets in logs.** Private keys, session keys, tokens, and authorization material MUST NOT be logged; failures SHOULD be logged without secrets.
- **M-11 Documented visibility.** The MVP MUST document what rendezvous, relays, and observers see and MUST NOT claim anonymity or metadata-free operation.
- **M-12 Documented trust decision.** The MVP MUST document first-contact trust decisions and the risk of the wrong identity.
- **M-13 Negative tests.** Tests MUST cover impersonation, replay, MITM, unauthorized access, downgrade, malicious discovery, exhaustion, revocation (if M-8 is in scope), and log leakage.
- **M-14 Evidence-bounded claims.** The MVP MUST NOT claim security or compatibility beyond demonstrated tests and documentation; missing coverage MUST be listed.

**MVP non-goals.** No global directory, mandatory identity provider, or production PKI; no anonymity; no VPN, kernel networking, group sessions, or datagram transport; no post-quantum, formal, Sybil, volumetric-availability, or global-adversary guarantee.

## References

These are background references, not dependencies. Open UPP does not implement them unless a later specification says so. They do not select algorithms or protocols.

- **[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), The Messaging Layer Security (MLS) Protocol.** Group key agreement and member authentication; relevant if group or multi-party sessions are considered. MLS also supports two-member groups, but no MLS use is selected for the MVP, and nothing is implemented.
- **[RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html), Hashing to Elliptic Curves.** Hash-to-curve constructions; relevant only if a future design needs one, such as certain PAKE or VRF-style mechanisms; no current requirement.
- **[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), Elliptic Curves for Security.** Defines X25519 and X448 key agreement; relevant if an ephemeral ECDH design is selected; key agreement alone does not authenticate peers, and no algorithm is selected.
- **[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), Edwards-Curve Digital Signature Algorithm (EdDSA).** Defines Ed25519 and Ed448 signatures; relevant if selected for identity proofs; not selected, and not an encryption or key-agreement scheme by itself.
- **[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), The Transport Layer Security (TLS) Protocol Version 1.3.** A mature transcript-bound key exchange and record-protection design with downgrade protections; it authenticates endpoints only when credentials are validated, and transport security alone does not establish UPP identity or authorization.
- **[RFC 7258](https://www.rfc-editor.org/rfc/rfc7258.html), Pervasive Monitoring Is an Attack.** Frames pervasive surveillance as a security concern; it does not imply an Open UPP anonymity property.
- **[RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html), Guidelines for Writing RFC Text on Security Considerations.** Methodology for assets, threats, and residual risk; used as a structural reference, not a compliance claim.
- **[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html), Key words for use in RFCs to Indicate Requirement Levels.** Defines MUST, SHOULD, and MAY as used for future specifications; it does not make any requirement implemented.
