# Changelog

All notable changes are documented here. HopWhy follows Semantic Versioning for
CLI and machine-contract compatibility.

## [Unreleased]

### Added

- Digest-pinned `hopwhy.report.v1` golden report with exact serialization,
  offline replay, forward-extension, and ten fail-closed mutation tests.
- Reproducible loopback redirect/body-pressure and network-free operation
  benchmark harness with raw runner metadata and 90-day workflow artifacts.

### Changed

- Upgraded `schemars` to 1.2 while explicitly retaining the published JSON
  Schema draft-07 machine contract.
- Defined measurable v1.0 compatibility, diagnostic-accuracy, SSRF and
  redaction safety, performance, delivery, maintenance, contribution, and
  repeat-adoption gates.
- Upgraded `sha2` to 0.11 with an explicit lowercase hexadecimal encoder that
  preserves report, body sample, certificate, and configuration digest
  contracts.

## [0.1.0] - 2026-07-28

### Added

- Bounded DNS, TCP, direct TLS, HTTP, and manually validated redirect phases.
- Deterministic Mozilla public-root validation for both direct TLS evidence and
  the bounded HTTP client.
- Public-address-only default policy with explicit private/local authorization.
- Deterministic redaction for query values, addresses, proxy configuration, and
  bounded response metadata.
- Integrity-sealed reports and network-free compare/replay commands.
- JSON, NDJSON, eight schema documents, stable exit-code classes, and five
  shell completions.
- Deterministic local fault fixtures and cross-platform release automation.
- OSS governance, support, security, contribution, and signed release policy.

[Unreleased]: https://github.com/yhay81/hopwhy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yhay81/hopwhy/releases/tag/v0.1.0
