# Development

The implementation language is expected to be Go, but implementation has not started.

## Engineering expectations

- Keep packages small and interfaces explicit.
- Prefer the Go standard library where practical.
- Use maintained, well-reviewed dependencies.
- Pin and review dependencies.
- Include unit, integration, fuzz, and interoperability tests as appropriate.
- Avoid logging private keys, tokens, or session secrets.
- Document platform limitations and resource requirements.
- Run formatting, static analysis, and tests in CI.

## Suggested initial commands (once Go modules are introduced)

```sh
gofmt -w .
go test ./...
go vet ./...
```

These commands are guidance for future Go code; this repository does not yet contain a Go module.
