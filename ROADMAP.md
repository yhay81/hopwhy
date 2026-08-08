# Roadmap

The roadmap is capability- and evidence-driven, not a date promise.

## 0.1 — bounded causal request path

- public-only safety default and explicit private target authorization;
- proxy, DNS, TCP, direct TLS, HTTP, and redirect phases;
- evidence-calibrated hypotheses and ruled-out classes;
- integrity-sealed JSON reports and offline compare/replay;
- deterministic fixtures, schemas, completions, CI, SBOM, and attestations.

## 0.2 — stronger environment comparison

- [x] Publish a digest-pinned v0.1 report compatibility and mutation corpus.
- [x] Deny IANA non-global and reserved IPv6 special-purpose prefixes before
  connecting to an initial target, proxy, or redirect.
- explicit IPv4/IPv6 selection experiments;
- native trust-store capability alongside the public-root baseline;
- richer proxy CONNECT evidence;
- structured environment capability snapshots;
- corpus cases for resolver split-horizon, TLS identity, and redirect policy.
- define an integrity-bound extension envelope or new report schema before
  adding evidence fields outside the v0.1 model.

## 0.3 — opt-in application assertions

- status, header, content-type, and bounded body-digest assertions;
- signed fixture corpus and scorer for earliest-phase accuracy;
- machine-readable recommendation catalog;
- [x] reproducible live redirect/body-pressure and offline-operation
  performance baseline with raw hosted-runner measurements;
- false-cause benchmark publication.

## v1.0 quality criteria

HopWhy reaches v1.0 only when every gate below has published, reproducible
evidence. More phases, probes, downloads, or stars do not substitute for
accurate uncertainty, enforced safety defaults, or real diagnostic use.

### Product and compatibility

- CLI, JSON, NDJSON, report, plan, compare, replay, capabilities, schema, error,
  and exit-code contracts remain compatible across at least two released
  pre-1.0 minor versions.
- Golden documents from every supported contract version are accepted by the
  current offline verifier or have a tested migration command and guide.
- Each diagnostic phase declares observable evidence, unobservable causes,
  confidence limits, probe cost, and platform variation.
- A capability downgrade, unavailable phase, proxy limitation, or trust-root
  difference is explicit and never converted into a definitive causal claim.

Current evidence: v0.2 and v0.3 provide two released compatibility cycles. The
current v0.3 offline reader accepts and replays the digest-pinned v0.1 report
corpus unchanged on every CI operating system. The v0.2 and v0.3 release notes
record contract preservation; no migration is required. Future contract
versions must add golden documents and an explicit migration or no-migration
decision.

### Diagnostic accuracy and security

- A published corpus of at least 50 labeled DNS-to-HTTP scenarios achieves at
  least 95% accuracy for the earliest failing observable phase.
- The same corpus has zero definitive root-cause claims for cases whose cause
  is unobservable; those cases remain partial, ambiguous, or ruled-in only as a
  hypothesis.
- The adversarial policy corpus has 100% denial of unauthorized loopback,
  private, link-local, multicast, documentation, reserved, credential-bearing,
  redirect, and DNS-rebinding targets.
- The redaction corpus has zero query-value, credential, proxy-secret, private
  address, certificate-sensitive-field, or bounded-body disclosure for every
  supported redaction class.
- An independent security review covers SSRF boundaries, resolution races,
  redirects, proxies, TLS identity, trust roots, report integrity, replay,
  resource limits, and diagnostic disclosure; all critical and high findings
  are resolved.
- No known critical or high-severity vulnerability is open at release time.

Current diagnostic evidence publishes 60 deterministic labeled scenarios,
with ten each for DNS, TCP, TLS, HTTP, redirect, and observed-response
outcomes. The independent scorer exercises the production phase orchestration
and currently requires 100% earliest-phase accuracy, 100% short-circuit and
hypothesis-code agreement, and zero definitive claims across 38 scenarios with
unobservable hidden causes.

### Performance and bounds

- Default live diagnostics complete within the declared 15-second budget and
  never exceed configured address, redirect, probe, body, or wall-clock limits
  without explicit completeness evidence.
- Offline compare, replay, schema, and integrity operations complete below
  250 ms p95 on the published corpus.
- Peak resident memory remains below 256 MiB for every published bounded
  scenario, including redirect and response-body pressure fixtures.
- Corpus definitions, runner images, network topology, raw measurements,
  expected earliest phase, and regression thresholds are versioned with the
  repository.

### Delivery and maintenance

- Required CI and deterministic fixtures remain green on Linux, macOS, and
  Windows for 30 consecutive days before the v1.0 tag.
- Releases originate only from protected `main` and signed annotated tags; all
  native archives have verified checksums, GitHub-hosted provenance, and a
  CycloneDX SBOM attestation.
- The release and network-safety incident runbooks are exercised by two
  maintainers, or governance records the single-maintainer continuity risk and
  a tested recovery procedure.
- Security reports are acknowledged within 3 business days and receive an
  initial assessment within 7.

### Adoption evidence

- At least three independent real-world diagnostic workflows are recorded in
  [ADOPTERS.md](ADOPTERS.md), including whether the earliest failed phase was
  useful and accurate.
- At least two adopters report repeat use separated by 30 days.
- At least one public workflow demonstrates a remediation, escalation, or safe
  non-action improved by a sanitized HopWhy report.
- At least one non-maintainer issue, discussion, corpus scenario, documentation
  change, test, or code contribution is resolved and credited.

Maintainer-authored fixtures, automated downloads, stars, and synthetic
accounts cannot satisfy adoption gates.

The release workflow enforces these criteria for every v1 or later tag with
the reviewable [v1 evidence manifest](.github/v1-evidence.json). Its verifier
checks the exact release version, criterion-specific evidence, independent
review scope and findings, daily evidence for every required 30-day track,
maintainer continuity, distinct adopters, repeat-use dates, a public
integration, and a resolved non-maintainer contribution. The manifest remains
explicitly pending until real evidence satisfies every criterion.
