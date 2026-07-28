# HopWhy performance baseline

This directory defines the reproducible, observation-only baseline used to
calibrate HopWhy's v1.0 performance and resource thresholds. Timing and memory
are not yet required pull-request checks.

## Workloads

`http_fixture.py` binds an ephemeral IPv4 loopback port and serves two
deterministic HTTP/1.1 routes:

- `/start` redirects to `/body?token=fixture-secret`;
- `/body` declares and serves 65,536 `x` bytes.

The live measurement explicitly authorizes the loopback target, disables proxy
discovery, and retains the normal 15-second, 12-probe, 4-address, 5-redirect,
and 4,096-body-byte limits. The result must include two HTTP observations,
redact the redirect query, stop reading the final body at 4,096 bytes, and
carry a valid report digest.

The harness then measures three network-free operations in fresh processes:
integrity-checking replay of the live report, comparison of the published v0.1
golden report with the live report, and generation of the complete report JSON
Schema. Each workload runs once without warm-up. GNU `time` wall time and peak
resident memory, output size, runner identity, fixture identity, HopWhy's
internal usage, and semantic results are retained.

## Run

The supported measurement environment is the `ubuntu-latest` GitHub-hosted
runner selected by `.github/workflows/benchmark.yml`. Run it manually with the
**Benchmark** workflow, or on a compatible Linux machine:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

GNU `time`, GNU `stat`, `timeout`, `jq`, Python 3, Git, Cargo, and the locked
Rust dependency graph are required. Build time is excluded. The loopback
fixture, live report, and intermediate outputs are temporary and are not
uploaded.

The workflow retains raw JSON for 90 days. Shared hosted runners are noisy, so
pull requests gate only the semantic fixture assertions, not observed timing or
memory. A single run is not a regression and does not establish p95. Before
enabling v1.0 gates, publish the runner image, warm-up policy, sample count, p95
calculation, baseline window, and noise-aware regression rule with the raw
measurements.
