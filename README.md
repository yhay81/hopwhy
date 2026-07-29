# HopWhy

Bounded causal DNS-to-HTTP diagnostics for humans and agents.

> Status: HopWhy 0.2 is the current supported release. The diagnostic engine,
> offline comparison, machine contracts, deterministic fixtures, and signed
> release automation are implemented.

HopWhy follows one intended HTTP request through input policy, proxy selection,
DNS, TCP, TLS, HTTP, and redirects. It reports the earliest phase where observed
progress stopped, evidence supporting that classification, calibrated
hypotheses, and a next safe diagnostic step.

```bash
hopwhy inspect https://api.example.com/health
hopwhy --format json inspect https://api.example.com/health --budget 15s
hopwhy compare report-local.json report-ci.json
hopwhy replay report-local.json
```

The repository publishes a digest-pinned
[v0.1 report corpus](tests/fixtures/contracts/README.md) for offline
compatibility testing, including ten declared schema, type, enum, payload, and
integrity mutations that the current reader rejects.

The versioned [performance harness](benchmarks/README.md) publishes raw
loopback redirect/body-pressure and network-free compare, replay, integrity,
and schema baselines without turning one noisy hosted-runner sample into a
release threshold.

## Why

Network troubleshooting often means composing resolver, route, TLS, and HTTP
tools, then inferring causality from unrelated text. HopWhy keeps observations
and inferences separate in one versioned report. A successful DNS phase does
not prove TCP reachability; a successful TCP phase does not prove TLS identity;
an HTTP response does not imply application health without an assertion.

## Safety defaults

HopWhy performs network activity only for `inspect` without `--dry-run`.

- Only `http` and `https` targets are accepted.
- Loopback, private, link-local, multicast, documentation, and reserved
  addresses are denied unless `--allow-private` is supplied.
- URL credentials are denied.
- Query values and resolved addresses are redacted by default.
- Proxy credentials and credential-derived fingerprints are never emitted.
- Redirects are disabled in the HTTP client and followed manually only after
  target policy is re-evaluated.
- Duration, probe count, address attempts, redirect count, and body reads are
  bounded.
- Body bytes are omitted by default; only a bounded digest is retained.
- HopWhy never scans ports, captures packets, executes content, or changes
  resolver, route, proxy, firewall, or certificate configuration.

Preview the exact probe classes without network activity:

```bash
hopwhy --format json inspect https://example.com/health --dry-run
```

Read [docs/SAFETY.md](docs/SAFETY.md) before embedding HopWhy in an agent.

## Install

Download a native archive from
[GitHub Releases](https://github.com/yhay81/hopwhy/releases), or install from
source with Rust 1.85 or newer:

```bash
cargo install --path . --locked
```

See [INSTALL.md](INSTALL.md) for platform-specific, checksum- and
provenance-verified native installation, updating, and removal.

Generate completion scripts with `hopwhy completions bash` (also `zsh`, `fish`,
`powershell`, and `elvish`).

## Inspect

Human output is concise:

```text
target: https://api.example.com/health
failed at: Tls
probes: 4/12
- Dns: Passed 3ms
- Tcp: Passed 12ms
- Tls: Failed 21ms (tls_handshake_failed)
diagnosis: TCP connectivity succeeded, but TLS negotiation or identity validation did not.
next: Inspect certificate trust, server name, clock, and TLS policy without disabling validation.
```

Machine output preserves evidence:

```bash
hopwhy --format json inspect https://api.example.com/health \
  --budget 15s \
  --max-probes 12 \
  --max-addresses 4 \
  --max-redirects 5 \
  --max-body-bytes 4096 > report.json
```

A target failure is a successful diagnostic result and exits 0 when a valid
report was produced. Operational, usage, policy, budget, and contract failures
outside a completed report use distinct exit codes.

To inspect an internal or local target, authorization must be explicit:

```bash
hopwhy inspect http://127.0.0.1:8080/health \
  --allow-private \
  --disable-proxy
```

Use `--show-addresses`, `--show-query-values`, or `--include-body-sample` only
when the extra disclosure is intentional.

## Spec files

`--spec` accepts a strict, versioned input shape:

```json
{
  "target": "https://api.example.com/health",
  "options": {
    "budget_ms": 15000,
    "max_probes": 12,
    "max_addresses": 4,
    "max_redirects": 5,
    "max_body_bytes": 4096,
    "include_body_sample": false,
    "allow_private": false,
    "show_addresses": false,
    "show_query_values": false,
    "disable_proxy": false,
    "method": "get"
  }
}
```

```bash
hopwhy --format ndjson inspect --spec probe.json
```

Unknown fields are rejected instead of silently ignored.

## Compare and replay

`compare` and `replay` never perform network activity. Both require
`report_sha256` to match the modeled v0.1 report fields. Unknown report
extensions are ignored for forward compatibility and must not be treated as
integrity-protected evidence.

```bash
hopwhy --format json compare report-local.json report-ci.json
hopwhy --format json replay report-local.json
```

Comparison reports target, earliest-failed-phase, phase status, and HTTP status
sequence differences. Replay reconstructs the recorded explanation and next
safe steps without contacting the target.

## Machine contract

Every data command supports `--format human|json|ndjson`. NDJSON emits exactly
one compact JSON document per invocation.

```bash
hopwhy --format json schema --document brief
hopwhy --format json schema --document report
hopwhy --format json schema --document error
hopwhy --format json capabilities
```

Stable exit-code classes are:

| Code | Meaning |
| ---: | --- |
| 0 | Successful command, including a report whose target path failed |
| 1 | Local I/O or transport setup error outside a completed report |
| 2 | Invalid CLI usage, target, spec, or limit |
| 3 | Policy denial before a report can be produced |
| 4 | Local input or operation budget exceeded |
| 5 | Machine-contract or report-integrity failure |

See [docs/CONTRACT.md](docs/CONTRACT.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Format support

| Phase | 0.1 support |
| --- | --- |
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`; credentials excluded from endpoints and configuration fingerprints |
| DNS | System resolver answers and address-family visibility |
| TCP | Bounded IPv4/IPv6 attempts |
| TLS | Independent direct handshake, public-root validation, protocol/cipher/ALPN/certificate digest |
| HTTP | GET/HEAD, HTTP/1.1 and HTTP/2 client negotiation, safe header allowlist |
| Redirects | Manual following with policy and budget re-evaluation |
| Assertions | Not yet implemented; reachability is not called health |

Run `hopwhy --format json capabilities` for the authoritative machine-readable
matrix and limitations.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SUPPORT.md](SUPPORT.md)
- [SECURITY.md](SECURITY.md)
- [ROADMAP.md](ROADMAP.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/yhay81/hopwhy/security/advisories/new).

## License

MIT
