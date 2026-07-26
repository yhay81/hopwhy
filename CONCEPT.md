# HopWhy concept

## One-line thesis

HopWhy diagnoses a network request from DNS through HTTP and returns the
earliest failed phase, supporting evidence, and bounded causal hypotheses.

## Problem

When a request fails, agents often run `dig`, `ping`, `traceroute`, `curl`, and
TLS tools independently. The resulting text is environment-dependent and easy
to misinterpret. Symptoms from one layer are routinely attributed to another:

- DNS resolution differs across resolvers and address families;
- a TCP timeout can be mislabeled as an application failure;
- TLS identity, trust, and protocol negotiation are conflated;
- proxies and redirects change the actual target;
- a single successful probe hides intermittent or family-specific failure.

## Target users and jobs

- Coding and operations agents debugging connectivity.
- Developers diagnosing local, CI, container, or remote environment differences.
- Support engineers collecting a reproducible evidence bundle.
- Test systems validating network policy and service readiness.

The primary job is: **probe a single intended request under a strict budget and
explain where observed progress stopped.**

## Product principles

1. Observations are separate from inferences.
2. The earliest failed phase anchors the explanation.
3. Confidence is reported; "root cause" is reserved for deterministic evidence.
4. Every network action is listed before or after execution.
5. Probe count, destinations, bytes, and duration are bounded.
6. Sensitive headers, query values, addresses, and certificates are redactable.
7. IPv4, IPv6, proxy, and redirect behavior remain visible.

## Proposed command contract

```text
hopwhy schema --brief --format json
hopwhy inspect https://api.example.com/health --budget 15s --format json
hopwhy inspect --spec probe.json --format ndjson
hopwhy compare report-local.json report-ci.json --format json
hopwhy replay report.json --confirm-targets --format json
```

`inspect` performs only the probes required by the declared request and enabled
diagnostic depth. It is not a port scanner.

## Diagnostic phases

The common phase model is:

1. input and policy validation;
2. proxy and environment resolution;
3. DNS query and address selection;
4. route/interface selection where observable;
5. TCP connection;
6. TLS handshake and identity validation;
7. HTTP request and response;
8. redirects;
9. bounded application-level assertions.

Each phase contains status, duration, attempts, observations, evidence
references, capability limitations, and redacted errors.

## Report model

A report includes:

- normalized intended and effective targets;
- probe budget and actual probe inventory;
- environment capability and proxy summary;
- a timestamped phase timeline;
- resolver answers, address-family choices, and connection attempts;
- TLS protocol, peer identity summary, and validation result;
- HTTP protocol, status, headers allowlist, and body digest/sample;
- `failed_at` for the earliest failed phase;
- ranked hypotheses with confidence and evidence links;
- ruled-out hypotheses and why;
- redactions, omissions, and non-observable layers.

The report never upgrades a hypothesis to a fact without supporting observation.

## Initial scope

Version 0.1 will support:

- macOS and Linux;
- DNS over the system resolver with answer visibility where available;
- IPv4 and IPv6 connection attempts;
- direct and common HTTP proxy environments;
- TCP, TLS, HTTP/1.1, and HTTP/2;
- redirect tracing;
- JSON comparison of two environment reports;
- deterministic local fixture networks for regression testing.

## Non-goals

- Continuous network monitoring.
- Broad port or vulnerability scanning.
- Packet capture by default.
- Fleet-wide topology mapping.
- Proving failures inside network segments the host cannot observe.
- Automatically changing DNS, proxy, firewall, or certificate settings.

## Differentiation and defensibility

HopWhy is not a faster `curl`. Its value is the causal report that preserves
layer boundaries and makes uncertainty explicit. A fixture-driven diagnosis
corpus, portable phase model, and integrations with agent runtimes can improve
accuracy over time.

## Success measures

- Correct earliest-failed-phase classification in a fault-injection lab.
- Hypothesis precision and false-cause rate.
- Probe count, elapsed time, and bytes per diagnosis.
- Tokens and commands required to diagnose benchmark incidents.
- Cross-environment comparison usefulness.
- Incidents resolved without escalating to packet capture.

## Key risks and open questions

- Operating systems expose different route and resolver details.
- Middleboxes can make causal attribution fundamentally incomplete.
- Diagnostics may leak internal hostnames, addresses, and certificate data.
- Retries can change intermittent failures and obscure the first observation.
- ICMP behavior is often misleading and should not dominate conclusions.

The project should be judged on calibrated explanations, including a willingness
to say "insufficient evidence."
