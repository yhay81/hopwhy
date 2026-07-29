# HopWhy performance baseline

This directory defines and enforces HopWhy's reproducible v1.0 performance and
resource thresholds on pull requests and in the weekly scheduled benchmark.

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
Schema. Each sample performs untimed build and fixture setup. The workflow
discards one warm-up and captures 20 samples. GNU `time` wall time and peak
resident memory, output size, runner identity, fixture identity, HopWhy's
internal usage, and semantic results are retained.

## Enforced thresholds

The versioned policy in `thresholds.json` enforces:

- the bounded live diagnostic below 15 seconds p95;
- the slowest offline replay, compare, or schema operation below 250 ms p95;
- peak RSS no greater than 256 MiB in every bounded sample.

Twenty samples make nearest-rank p95 the second-slowest observation. Once
`baseline-ubuntu24.json` is present, metrics must also remain within the
stricter of the absolute limit and the versioned noise allowance: 1.5 times
baseline or baseline plus 100 ms for live time, 50 ms for offline time, and
16 MiB for memory.

## Run

The supported measurement environment is the `ubuntu-24.04` x86_64
GitHub-hosted runner selected by `.github/workflows/benchmark.yml`. Run one raw
sample on a compatible Linux machine with:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

Run evaluator tests with:

```bash
python3 -m unittest benchmarks/test_evaluate.py
```

GNU `time`, GNU `stat`, `timeout`, `jq`, Python 3, Git, Cargo, and the locked
Rust dependency graph are required. Build time is excluded. The loopback
fixture, live report, and intermediate outputs are temporary and are not
uploaded.

The workflow uploads all 20 raw samples and the aggregate evaluation for 90
days, including raw samples from a failed threshold evaluation. The checked-in
baseline is refreshed only from a successful protected-runner evaluation.
