# Changelog

All notable changes are documented here. HopWhy follows Semantic Versioning for
CLI and machine-contract compatibility.

## [Unreleased]

### Added

- Added platform-specific, checksum- and provenance-verified native
  installation, update, and removal guidance.
- Added weekly installation smoke tests on Linux x86_64, macOS Apple Silicon
  and Intel, and Windows x86_64 using the published instructions.
- Enforced the published v1.0 live-diagnostic, offline-operation, and bounded
  memory thresholds from 20-sample benchmark evidence on Ubuntu 24.04.

### Fixed

- Denied IANA non-global, local-translation, discard-only, benchmark,
  documentation, transition, and reserved IPv6 ranges before connecting to an
  initial target or proxy. IPv4 addresses embedded in the well-known
  translation prefix now inherit the IPv4 safety classification.
- Stopped hashing raw proxy environment values; configuration fingerprints now
  cover only the credential-free, query-redacted canonical endpoint.
- Rejected performance evidence with a non-canonical commit identity,
  incomplete runner metadata, a non-raw sample marker, or reused sample paths.

## [0.3.0] - 2026-07-29

### Compatibility

- Preserved the public v0.2 CLI, report, plan, compare, replay, schema, and
  error contracts. The digest-pinned v0.1 corpus and supported-platform tests
  continue to pass.

### Added

- Published downloadable SLSA provenance bundles beside every native archive
  and covered those bundles with `SHA256SUMS`.
- Added a privacy-conscious adoption report form that captures evaluation,
  repeat-use, limitations, evidence, and public-listing permission.
- Added a monthly maintainer-continuity drill that recovers the public Git
  mirror and verifies signed tags, release checksums, build/SBOM attestations,
  and the released native binary without repository write access.
- Added pull-request dependency review and weekly OpenSSF Scorecard analysis,
  with every action pinned to an immutable commit SHA.
- Enabled CodeQL default setup and restricted release and dependency-audit
  credentials to the minimum permissions required by each job.
- Added URL-policy and verified-report fuzzing with reproducible local
  `cargo-fuzz` execution, five-minute pull-request checks, and weekly
  ClusterFuzzLite AddressSanitizer batches.

## [0.2.0] - 2026-07-29

### Compatibility

- Preserved the public v0.1 CLI, report, plan, compare, replay, schema, and
  error contracts. The v0.2 offline reader accepts the digest-pinned v0.1
  report corpus unchanged; no migration is required.

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

[Unreleased]: https://github.com/yhay81/hopwhy/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/yhay81/hopwhy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yhay81/hopwhy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yhay81/hopwhy/releases/tag/v0.1.0
