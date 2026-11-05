# Protocol design

This directory will contain versioned, language-neutral protocol specifications.

## Current status

No UPP wire protocol has been finalized. No message format or implementation should currently claim UPP compatibility.

## Specification requirements

A versioned specification must define:

- Terms, identifiers, and canonical encodings.
- Peer identity and key lifecycle.
- Discovery records and their authenticity/freshness.
- Handshake and session state machines.
- Authentication and authorization semantics.
- Error handling, timeouts, retries, and resource limits.
- Version negotiation and extension rules.
- Privacy and metadata considerations.
- Security considerations and known limitations.
- Test vectors and conformance requirements.

## Design constraints

Prefer established, reviewed cryptographic protocols and libraries. Do not invent cryptographic primitives. Avoid ambiguous encodings and implicit trust. Make downgrade behavior, replay protection, key rotation, and revocation explicit.

## Proposals

Discuss significant changes in an issue before adding a numbered specification. A proposal is not normative until accepted and assigned a version.
