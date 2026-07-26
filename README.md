# HopCause

Causal DNS-to-HTTP network diagnostics for humans and agents.

> Status: concept stage. No diagnostic engine is implemented yet.

HopCause follows a request through DNS, routing, TCP, TLS, HTTP, redirects, and the application response. It returns the first supported failure cause, the observations behind it, and the next safe diagnostic step.

```bash
hopcause inspect https://api.example.com
hopcause inspect https://api.example.com --phases dns,tcp,tls
hopcause compare report_a.json report_b.json
```

## Why

Network troubleshooting often means repeatedly composing `dig`, `traceroute`, `curl`, and `openssl`, then inferring which layer failed. That is expensive for humans and token-heavy for agents.

## Product principles

- Observations and inferences are separate fields.
- A failure phase is identified without overstating root cause.
- DNS, TCP, TLS, and HTTP share one timeline.
- Output has strict time, probe, and byte budgets.
- Sensitive headers and addresses can be redacted deterministically.
- A report can be replayed or compared without network access.

## Initial scope

Single-target diagnostics for DNS, TCP, TLS, HTTP/1.1, HTTP/2, redirects, proxy environment, and basic route information.

See [CONCEPT.md](CONCEPT.md) for the causal model and MVP.

## License

MIT
