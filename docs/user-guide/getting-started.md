# Getting started: two peers, one authorized stream

> **Status: USABLE GUIDE — the two-peer v1 slice is implemented and verified.** This guide covers the two-peer
> experience in W4 for both shipped tools: `uppid` (local identity) and `upp` (pairing, verification, grants,
> stream). The wire protocol, discovery, handshake, session, grants, and stream API are implemented and verified
> by W6/W7 and the independent W8 review (builds, full test suite including race, and the two-process demo pass).
> Follow the steps below as written.
>
> **Still out of scope / not shipped:** Stage 5/ecosystem work, a relay service or discovery directory,
> revocation propagation, post-quantum suites, and any operator-reachable TOFU/degraded path.
>
> **Audience:** a developer/operator comfortable with a terminal, running both peers on one machine.
> **Reader's goal:** go from two empty directories to one verified, authorized, closed byte stream — and know
> what an error means. Source: `.opencode/reports/product-ready/designer-agent-W4-ux.md` (W4) and the `main`
> code (`cmd/uppid/main.go`, `identity/identity.go`, `go.mod`).
>
> **Tailcat-core release (implemented and verified; [ADR-002](../architecture/adr-002-tailcat-core.md) landed):**
> Tailcat is now the default/primary transport, and the v2 two-peer flow over Tailcat is implemented and verified.
> The commands and loopback TCP flow below describe the **frozen v1 baseline** and remain valid as the explicit
> local-test fallback; there is no auto-downgrade. UPP identity, pairwise verification, explicit scoped grants,
> and the no-TOFU policy are unchanged. A Tailcat `tc...` address is a **secret bearer routing hint**: keep it in
> the 0600 hint file and never treat it as identity or authority. Tailcat API/wire instability and best-effort,
> rate-limited public DERP remain documented limitations.

## Before you begin

- **Go 1.27.1** installed (required by `go.mod`); `go version` works. The module `github.com/IFindMe/open-upp`
  depends on `github.com/tailscale/tailcat v0.7.0` for the default transport, so module downloads are needed on
  a fresh machine.
- **Two terminals** — Terminal A (the listener, "Alice") and Terminal B (the connector, "Bob"). The demo runs
  on loopback (`127.0.0.1`), so no public IP and no inbound port forwarding are required.
- **An independent channel** for the safety-number comparison (a phone call, chat, or in-person reading).
  The hint file and the peer's public record are exchanged out of band too; neither proves identity or
  authority.

| What you need | Available now? |
|---|---|
| `uppid` identity tool + `identity/` package | Yes — implemented and unit-tested |
| `upp` CLI, hint discovery, handshake, grants, stream | Yes — implemented and verified |
| `scripts/two-peer-demo.sh` (end-to-end reproduction) | Yes — runs the flow end to end (demo passes) |

## 1. Build with local Go

```sh
cd /path/to/open-upp
go version                 # expect go1.27.1 (required by go.mod)
go test ./...              # full test suite passes
go build ./cmd/uppid       # produces ./uppid
```

For a local install instead of a repo-local binary:

```sh
go install ./cmd/uppid     # installs uppid into $(go env GOPATH)/bin
```

Build the two-peer CLI the same way:

```sh
go build ./cmd/upp         # produces ./upp
```

Run the binaries from the working directory that holds your identity/state files, or pass explicit paths with
`-identity`, `-grants`, `-pins`, and `-hint`.

## 2. Create one identity per peer (`uppid`)

**Terminal A:**

```sh
./uppid generate -class device -out alice.json
```

Real output shape (from `identity.Display()`, `identity/identity.go:299-307`):

```text
suite:         Ed25519
class hint:    device
fingerprint:   <64 lowercase hex chars>
safety number: <13 groups of 4 characters>
current key:   <base32, no padding>
keys in log:   1
revoked keys:  0

saved: alice.json
```

**Terminal B:**

```sh
./uppid generate -class device -out bob.json
```

> **Important — that `safety number:` line is not the peer safety number.** It is a deprecated, display-only
> rendering of *one* identity's own fingerprint in 4-character groups. Never use it to verify a peer; the
> `upp` CLI does not accept it. The number you must compare is the **pairwise safety number** in
> 8-character groups, produced in step 4.

Identity files are written with mode `0600`. `uppid` never prints private key material. Other useful local
commands: `uppid show -in alice.json`, `uppid rotate -in alice.json`, `uppid revoke -in alice.json -key B64`,
`uppid sign` / `uppid verify` for local proof-of-possession. (There is no "import" command — copying an
existing identity JSON to a path and passing `-identity PATH` is the whole procedure.)

## 3. Advertise a route (Terminal A — `upp listen`)

```text
A$ upp listen -identity alice.json -hint alice.hint -addr 127.0.0.1:0
upp: listening: hint written to alice.hint
upp: waiting for peer; press Ctrl-C to stop
```

`upp listen` writes an endpoint hint to `-hint` (default `peer.hint`) and accepts one inbound stream. The hint
is an **untrusted** locator (address + port + subject fingerprint), not proof of identity. For the two-host
case, pass a reachable LAN address to `-addr`; no such flag is needed for the loopback demo.

Out of band, Alice sends `alice.hint` to Bob and each peer sends the other its **public record** (public-key
only, e.g. `bob.public.json` / `alice.public.json`). The `upp` demo script produces and exchanges these; a hint
or public record never authenticates or authorizes anyone.

## 4. Compare the pairwise safety number (both terminals — `upp verify`)

**Terminal B** (Bob renders the number over his identity and Alice's public record):

```text
B$ upp verify -identity bob.json -peer alice.public.json
upp: local fingerprint: <FP_B: 64 hex>
upp: peer  fingerprint: <FP_A: 64 hex>
upp: pairwise safety number (8-char groups):
upp:   JBSWY3DP EHPKJ5XQ NVSXG6ZF MFRGG43D NZQWY2TL O5SWI4ZY B7QX
upp: compare this number with the peer over an independent channel
```

**Terminal A** does the same with roles reversed:

```text
A$ upp verify -identity alice.json -peer bob.public.json
... same 52-character number, local/peer fingerprints swapped ...
```

The value is 52 base32 characters in **7 groups: six groups of 8, then a final group of 4**. Read every group
aloud over the independent channel; both sides must match exactly. To have the CLI compare a pasted value,
add `-sn "<the 52-character number>"`; it strips spaces, uppercases, and compares the **full digest** in
constant time. A legacy 4-char group code or the wrong length is a usage error (exit 2).

> This comparison is a human step. Confirming it is what moves the session from *authenticated* to *verified*.
> Authentication alone never grants access.

## 5. Grant the peer a scoped capability (both terminals — `upp grant add`)

Each operator grants the other peer permission for resource `stream`, ops `open,read,write`:

```text
A$ upp grant add -identity alice.json -grants alice.grants -peer-fp <FP_B_64_HEX> -resource stream -op open,read,write
Grant to peer <FP_B_64_HEX> for resource "stream", ops open,read,write.
Type yes to grant; anything else denies: yes
upp: granted: grant <ID_A> for <FP_B_64_HEX> stream open,read,write

B$ upp grant add -identity bob.json -grants bob.grants -peer-fp <FP_A_64_HEX> -resource stream -op open,read,write
... same prompt, answered yes ...
upp: granted: grant <ID_B> for <FP_A_64_HEX> stream open,read,write
```

`-peer-fp` requires the **full 64-character lowercase hex** fingerprint — no truncation. Prompts require the
literal answer `yes` (case-insensitive); empty input, `y`, `n`, Enter, or a timeout all deny. Grants are local,
signed files (`grants.json`, mode 0600). Use `upp grant list -grants bob.grants` to inspect metadata and
`upp grant revoke -grants bob.grants -grant-id <ID>` (or `-peer-fp <FP>`, not both) to revoke.

> Verification is **not** authority. A verified peer with no matching grant is denied.

## 6. Open, use, and close the stream (`upp connect` + listener confirmation)

**Terminal B** connects; both sides must answer the verification prompt:

```text
B$ upp connect -identity bob.json -hint alice.hint -grants bob.grants -pins bob.pins -resource stream -op open,read,write
upp: peer authenticated: <FP_A_64_HEX>
upp: pairwise safety number (8-char groups):
upp:   JBSWY3DP EHPKJ5XQ NVSXG6ZF MFRGG43D NZQWY2TL O5SWI4ZY B7QX
I compared the safety number above with the peer over an independent channel and it matches.
Type yes to continue; anything else denies: yes
upp: verified: pairwise safety number matched on both sides
upp: authorized: grant <ID_B> covers stream open,read,write
upp: session_open: stream ready (resource=stream); type a line to send, Ctrl-D to close
hello from Bob
```

**Terminal A** answers its own SN prompt (`yes`) and sees the echoed line, then closes:

```text
A$ (answer the pairwise-SN prompt: yes)
upp: verified: pairwise safety number matched on both sides
upp: authorized: grant <ID_A> covers stream open,read,write
upp: session_open: stream ready (resource=stream)
hello from Bob
upp: ended: session closed; session keys zeroized
```

Type lines to send over the stream; press **Ctrl-D** (EOF) to close gracefully. On close or failure, session
keys are zeroized and never reused; reconnecting re-runs the whole handshake and derives new keys.

`-op` on `connect` must be a subset of the grant's ops. There is exactly one stream API. There is **no**
`-yes`, `-confirm-oob`, fingerprint-allow, TOFU, or pin-reuse flag — consent is per session and per grant.
Even when a pin from an earlier session exists, the pairwise-SN confirmation above is still required **every
session**: the pin is change-detection state, not standing trust, and a stored pin never authorizes a session.

## 7. Exit codes

Both CLIs use these codes (W4 §1c; `uppid` currently uses 0/1/2 only):

| Code | Meaning |
|---|---|
| `0` | Success — command completed, SN matched, or session reached `ended` |
| `1` | Terminal failure — transport, handshake, verification mismatch, invalid/absent grant, session, replay, revocation |
| `2` | Usage/input error — unknown command, missing/extra flag, malformed file, bad hex/base64, unreadable path, wrong-length SN |
| `3` | Operator declined or cancelled — `no` at a prompt, Ctrl-C, or prompt timeout at the verification gate |

A missing or invalid grant is exit `1` (`authorization_denied`); an operator answering `no` to a grant or
verification prompt is exit `3`. Ctrl-C maps to `verification_aborted` (exit 3) at the verification gate and
`connection_lost` (exit 1) during a stream.

## 8. Common errors and what to do

All failures print one line to stderr: `upp: <token>: <plain sentence>.`, sometimes followed by a
`  Next: <action>.` line. No key material or transcript bytes are printed. Most common:

| stderr token | Typical cause | Exit | Next step |
|---|---|---|---|
| `route_failed` | Could not reach peer after 3 attempts (5 s timeout each) | 1 | Check the `-hint` file and network reachability |
| `unknown_peer` | No route or identity record matched the peer hint | 1 | Check `-hint` and `-identity`, then retry |
| `version_rejected` | Peer offered an unsupported version/suite/extension; no fallback | 1 | Use the same v1 build on both peers |
| `bad_proof` | Peer identity proof failed verification; no session created | 1 | Discard the attempt; check both identity files; fresh handshake |
| `stale_challenge` | Challenge reused or outside the 60 s window | 1 | Start a new handshake with a fresh challenge |
| `unverified_safety_number` | Numbers did not match, or peer root fingerprint changed | 1 | Repeat comparison over an independent channel; re-grant a new root |
| `verification_aborted` | Comparison timed out or was cancelled/declined | 1 / 3 | Restart and complete the out-of-band comparison |
| `authorization_denied` | No enabled scoped grant covers the peer/resource/op, or operator declined | 1 / 3 | Administrator runs `upp grant add`; verification alone is not a grant |
| `revoked` | Peer key is on the local deny list; session terminated | 1 | Rotate the peer identity key, then retry |
| `session_key_error` | Session keys could not be established; no stream opened | 1 | Restart; no state was written |
| `replay` | Duplicate/out-of-order session sequence number; session terminated | 1 | Restart; old keys are discarded, not reused |
| `connection_lost` | Peer disconnected; 3 re-handshake attempts failed | 1 | Restore connectivity and restart; new keys will be derived |
| `scope_violation` | Operation outside the authorized scope (non-terminal) | continues | Operation denied and audited; use an allowed op |
| `usage error` | Bad flag/path/hex/base64 or wrong-length SN | 2 | Run `upp help` |

Example:

```text
upp: authorization_denied: no enabled scoped grant covers peer <FP> for stream/write
  Next: an administrator must run upp grant add; verification alone is not a grant.
```

## 9. Rules to remember

- Verify the **pairwise** (8-char-group) number out of band; the `uppid` 4-group `safety number:` is deprecated display only.
- Verification never implies authorization; only an explicit scoped grant does.
- Prompts default to **deny** and require the literal `yes`; there is no bypass flag and no TOFU prompt — v1 has no trust-on-first-use path.
- A retained pin never skips verification: each session needs fresh proof of possession, a valid continuity chain, and a fresh out-of-band confirmation; any fingerprint/key change requires re-verification and a new grant.
- A hint file or public record is an untrusted locator/input, never identity evidence. In the landed Tailcat-core release, the `tc...` address is a secret bearer routing hint: protect it like a secret, but never treat it as identity or authority.
- Nothing prints private keys, passphrases, transcript bytes, or session material.
- Errors are one plain sentence plus a stable token; no stack traces or raw bytes.

## Traceability and open items

- This guide documents the shipped v1 (hint-over-TCP) baseline and the landed Tailcat-core release (Tailcat default/primary transport, implemented and verified); its ADR is at [ADR-002](../architecture/adr-002-tailcat-core.md).
- Commands, flags, prompt text, exit codes, and error lines follow W4 §1–§5 and §7; `uppid` output and module
  details were verified against `cmd/uppid/main.go`, `identity/identity.go:299-307`, and `go.mod`.
- Details not fixed by W4: the exact command that produces the peer public-record file consumed by
  `-peer` (the demo script supplies these), and the optional two-host LAN bind flow. The loopback path above is
  the documented, reproducible case.
- Trust policy is **resolved** (`philosopher-agent-W5c-trust-policy.md`): v1 ships strict pairwise verification only —
  no operator-reachable TOFU/degraded path, no `--allow-tofu`, no degraded state, no TOFU prompt or demo step. The
  degraded mechanism is deferred to a future version, not rejected forever. Pins may be reused across sessions only
  as change-detection state (fresh PoP, valid continuity, fresh per-session OOB confirmation, change alerts); root
  replacement forces re-verification and a new grant.

## Handoff record

```text
goal:                    Practical two-terminal getting-started guide for the two-peer slice.
evidence:                W4 §1-§5, §7; W5c resolved trust policy; cmd/uppid/main.go;
                         identity/identity.go:175-194,299-307; go.mod.
actions_taken:           Wrote build, identity creation, listen, pairwise-SN compare, grant, stream open/close,
                         exit codes, common errors, rules, traceability; synced policy to resolved no-TOFU,
                         conditional-pin-reuse decision (§6, §9, traceability).
result:                  docs/user-guide/getting-started.md (this file).
verification:            uppid flags/output copied from source; upp strings/tokens copied verbatim from W4;
                         trust-policy wording matches W5c Decisions 1-2.
confidence:              high (shipped uppid/upp behaviour and v1 policy, corroborated by W8); medium
                         (peer-public-record export detail).
remaining_unknowns:      Public-record production command and LAN bind flow not fixed by W4. No open
                         v1 trust-policy question; a future version may revisit shipping the TOFU mechanism.
recommended_next_action: None for v1 status — the guide describes the implemented, verified slice; remaining
                         items are W8's non-blocking UX notes and explicitly out-of-scope future work.
```
