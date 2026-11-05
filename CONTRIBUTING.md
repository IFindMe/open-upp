# Contributing to Open UPP

Thank you for considering a contribution. Open UPP is at an early design stage; clear problem statements and careful review are more valuable than large unreviewed changes.

## Before you start

1. Read the README, architecture notes, and security model.
2. Search existing issues and discussions before opening a duplicate.
3. For substantial changes, open an issue first and describe the problem, alternatives, and compatibility impact.

## Ways to contribute

- Review protocol assumptions and identify missing requirements.
- Improve threat models and security documentation.
- Research peer discovery, NAT traversal, relays, and transport abstraction.
- Propose interoperability and conformance tests.
- Improve documentation, examples, and developer experience.
- Implement small, well-scoped changes once implementation work is approved.

## Pull requests

- Keep changes focused and explain the motivation.
- Link related issues.
- Document security and compatibility implications.
- Add tests for behavior changes.
- Do not introduce undocumented wire-format changes.
- Do not claim protocol compatibility without conformance tests.
- Be respectful and constructive.

## Protocol design proposals

Include the problem, goals, non-goals, threat model, trust assumptions, message/state-machine changes, compatibility strategy, failure modes, resource limits, abuse considerations, and an interoperability plan.

## Security reports

Do not disclose exploitable vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).

## License

By submitting a contribution, you agree that it is provided under the repository's Apache-2.0 license, subject to applicable law and any separate written agreement.
