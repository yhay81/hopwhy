# Security policy

## Supported versions

Until 1.0, only the latest published release receives security fixes.

| Version | Supported |
| --- | :---: |
| latest | yes |
| older | no |

## Private reporting

Do not open a public issue for a vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/yhay81/hopwhy/security/advisories/new).
Include the affected version and platform, target class, exact bounded options,
whether a proxy was involved, redacted reproduction steps, and expected impact.
Never attach credentials, complete internal URLs, private certificates, or
unredacted production reports unless explicitly requested in the private
advisory.

Maintainers aim to acknowledge reports within 7 days and provide an assessment
or follow-up plan within 14 days. Timelines may change with complexity.

## Security model

HopWhy is an active network client, not a sandbox.

- Non-public addresses, including IANA non-global IPv6 special-purpose and
  translation prefixes, are denied by default but may be explicitly
  authorized.
- DNS rebinding cannot be eliminated universally; the selected endpoint is
  pinned where the HTTP client permits and limitations remain documented.
- Public-root TLS validation is never silently disabled.
- Proxy and target credentials are not emitted.
- Body samples require explicit opt-in.
- Malicious endpoints can delay, fragment, redirect, or return adversarial
  protocol data; all supported reads and probe counts are bounded.
- HopWhy does not prove what happened inside an unobservable network segment.

Read [docs/SAFETY.md](docs/SAFETY.md) for operational guidance.

## Release and dependency policy

Dependabot monitors Rust and GitHub Actions dependencies. CI checks
`Cargo.lock` against RustSec advisories. Tagged releases use signed annotated
tags and include checksums, CycloneDX SBOMs, and GitHub/Sigstore attestations.
See [RELEASING.md](RELEASING.md).

Pull requests are checked with GitHub Dependency Review and fail when they
introduce a dependency with a known moderate-or-higher-severity vulnerability.
A weekly OpenSSF Scorecard analysis publishes authenticated results and uploads
SARIF findings to GitHub code scanning. CodeQL default setup analyzes Rust and
workflow sources with extended security queries. ClusterFuzzLite runs URL
policy and offline report verification on every code-changing pull request and
in a longer weekly AddressSanitizer batch; see [FUZZING.md](FUZZING.md).
