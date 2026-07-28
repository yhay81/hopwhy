# Safety model

HopWhy performs active DNS, TCP, TLS, and HTTP requests. Treat target selection
as a capability boundary.

## Default policy

The default address policy denies:

- loopback and unspecified addresses;
- RFC 1918 private IPv4 and unique-local IPv6;
- link-local, shared, multicast, broadcast, documentation, benchmark, and
  reserved ranges.

`--allow-private` authorizes all of those categories for the current command.
Use it only after the user or controlling policy has selected the target. Never
add it automatically merely because a target failed.

URL user information is rejected. Only HTTP(S) schemes are accepted.

## SSRF and DNS rebinding

The default policy reduces server-side request forgery risk when an agent
receives an untrusted URL. It is not a complete sandbox:

- public endpoints can proxy requests elsewhere;
- HTTP proxies may resolve target names themselves;
- DNS answers can change;
- a permitted public service can expose sensitive data.

Run HopWhy with OS/container network controls when targets originate from
untrusted input. Use `--dry-run` before granting private access.

## Disclosure

By default:

- query keys remain visible but values become `REDACTED`;
- addresses become stable 12-hex SHA-256 tokens with an address-family label;
- proxy endpoints omit credentials and query values;
- only a small response header allowlist is stored;
- response body bytes are omitted, while a bounded sample digest remains.

`--show-query-values`, `--show-addresses`, and `--include-body-sample` expand
disclosure. Reports preserve those option values. Review expanded reports
before sharing them.

Certificate bodies are not emitted. The direct TLS phase records the leaf
certificate SHA-256, certificate count, protocol, cipher suite, and ALPN.

## Resource bounds

Supported limits:

- wall-clock budget: 100 ms to 120 s;
- probes: 1 to 64;
- address attempts: 1 to 16;
- redirects: 0 to 10;
- response sample: 0 to 1 MiB per hop;
- spec input: 1 MiB;
- offline report input: 8 MiB.

The response reader asks for at most `max_body_bytes + 1` bytes to determine
truncation. The HTTP client has automatic decompression features disabled.

## Causal limits

HopWhy identifies the earliest observed failed phase, not necessarily the
ultimate root cause. A TCP timeout cannot identify which route or firewall
dropped traffic. A TLS validation failure does not prove the server was
misconfigured rather than the client trust context. Proxy tunnel details are
partially opaque.

The correct result can be `not_observed` or “insufficient evidence.”

## Incident handling

Stop probing if a target was not intended, a private target was enabled by
mistake, or a report contains sensitive data. Do not post the report publicly.
Follow [../SECURITY.md](../SECURITY.md) for vulnerabilities.
