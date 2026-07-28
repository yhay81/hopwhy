# Fuzzing HopWhy

HopWhy continuously fuzzes its two offline untrusted-input boundaries with
AddressSanitizer. The `target_and_report` target exercises URL policy and
redaction for arbitrary UTF-8, plus the production report size bound, typed
JSON parser, schema check, and integrity digest.

Install a current nightly toolchain and the pinned local runner, then run:

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
mkdir -p fuzz/corpus/target_and_report
cp fuzz/seeds/target.txt fuzz/corpus/target_and_report/
cp tests/fixtures/contracts/v0.1/dns-failure.report.json \
  fuzz/corpus/target_and_report/
cargo +nightly fuzz run target_and_report
```

Pull requests receive a five-minute ClusterFuzzLite code-change run. A
15-minute batch run executes weekly on `main`, seeded by a redaction-sensitive
URL and the versioned report fixture, and publishes machine-readable findings
to GitHub code scanning.
Each code-changing `main` update also saves a comparison build so later pull
requests can distinguish newly introduced crashes. The accumulated corpus is
pruned after every weekly batch.

Reports and URLs can contain private topology or query data. Keep minimized
crashes private until reviewed, add a deterministic regression test, and use
[SECURITY.md](SECURITY.md) for security-relevant findings.
