# Testing and diagnosis corpus

Required tests are deterministic and use loopback fixture servers only after
explicit private-target authorization.

The 0.1 suite covers:

- schema, version, and shell completion contracts;
- network-free dry-run;
- default loopback/private denial after DNS evidence;
- local HTTP success and safe header filtering;
- explicit body sampling and truncation;
- manually validated redirects and query redaction;
- HTTP status sequence comparison;
- offline replay integrity;
- report tampering rejection;
- global probe exhaustion;
- strict spec parsing.

Hosted CI repeats the complete CLI fixture suite ten times on Linux, macOS, and
Windows. This catches platform differences in accepted-socket modes, process
execution, and bounded redirect handling. Public-network access is never
required for a merge.

## Corpus acceptance

A new diagnosis case should define:

1. intended request and explicit safety policy;
2. injected fault;
3. expected earliest failed phase;
4. required observation and forbidden overclaim;
5. expected next safe step;
6. maximum probes, duration, and bytes;
7. redaction assertions.

Cases that depend on uncontrollable external DNS, certificate, proxy, or
service state belong in manual dogfood, not required CI.
