# Architecture

HopWhy is a bounded active probe engine followed by integrity-sealed offline
analysis.

```text
target/spec
  -> input and option policy
  -> proxy/NO_PROXY selection
  -> system DNS + address policy
  -> bounded TCP attempts
  -> independent direct TLS handshake when observable
  -> bounded HTTP request
  -> manual redirect validation and repetition
  -> phase report + calibrated hypothesis + SHA-256 seal
  -> offline compare/replay
```

## Modules

- `cli`: strict argument/spec parsing, output formats, and completions.
- `policy`: URL normalization, query redaction, proxy selection, NO_PROXY
  matching, address classification, and display hashing.
- `engine`: global budget tracking and phase probes.
- `model`: versioned serializable documents.
- `offline`: report integrity verification, comparison, and replay.
- `contract`: capabilities and JSON Schema generation.

## Phase semantics

A phase is `passed`, `failed`, `skipped`, or `not_observed`.

- `passed` means the specific bounded observation succeeded.
- `failed` means observed progress stopped in that phase.
- `skipped` means the phase did not apply.
- `not_observed` means it applied but the platform or selected transport did not
  expose a safe independent observation.

The first `failed` phase becomes `failed_at`. A hypothesis cites that phase and
never replaces an observation. Prior passed phases can rule out only complete
failure of those specific observations.

## Probe accounting

DNS lookup, every TCP connection attempt, direct TLS handshake, and every HTTP
request consume a global probe slot. A single wall-clock deadline is shared by
the operation. Per-operation timeouts are capped by the remaining deadline.

HTTP redirects are disabled in the client. HopWhy parses each `Location`,
accepts only HTTP(S), re-evaluates proxy and address policy, and creates a new
bounded request.

## Endpoint pinning and limitations

The endpoint selected during policy evaluation is supplied to the HTTP client
resolver for the applicable connection host. This narrows, but cannot
universally eliminate, DNS rebinding and proxy-side resolution behavior. HTTP
proxies may resolve the target themselves. These limits are preserved in the
report instead of converted into claims.

Direct HTTPS targets receive a separate rustls handshake using the Mozilla
public root set. HTTPS through a proxy is marked `not_observed` as a separate
TLS phase; the HTTP client still validates TLS with the same public root set,
but CONNECT and target handshake details are not split.

## Report integrity

The report is serialized with `report_sha256: null`; SHA-256 of those bytes is
then stored as `report_sha256`. Offline commands recompute the same value before
using a report. The seal detects accidental or malicious edits but is not an
authenticity signature. Release artifacts separately use GitHub/Sigstore
attestations.

## Dependency boundary

HopWhy uses the standard resolver and TCP stack, rustls with Mozilla public
roots for both the independent TLS probe and reqwest's bounded HTTP/1.1/HTTP/2
requests. No native packet capture, shell command, process execution, unsafe
Rust, or writable network configuration API is used.
