# Diagnostic accuracy corpus

`v0.1/corpus.json` contains 60 deterministic, MIT-licensed DNS-to-HTTP
observation scenarios. Ten cases each cover DNS, TCP, TLS, HTTP, redirect, and
successful-response outcomes. The cases include later-stage failures that must
not be consulted after an earlier failure, HTTP error statuses that must not be
misclassified as transport failures, and hidden causes that the available
observations cannot prove.

`generate_corpus.py` builds the corpus and target metrics from explicit label
tables. It does not import, invoke, or inspect HopWhy. The independent Rust
scorer substitutes only the network I/O backend and sends every scenario
through the production `inspect` phase orchestration, report finalization, and
hypothesis generation.

The scorer requires:

- 100% earliest-failing-phase accuracy (the v1.0 minimum is 95%);
- 100% phase short-circuit and hypothesis-code agreement;
- zero definitive root-cause claims across all labeled unobservable causes.

A claim is treated as definitive when an unobservable-cause report assigns
confidence `1.0`, cites evidence outside the failed observable phase, names the
hidden cause, or uses explicit causal-proof language. The rubric is intentionally
stricter than checking the `failed_at` field alone.

`metrics.json` pins the expected results and the canonical parsed-JSON SHA-256
of the corpus, independent of checkout line endings.

Regenerate and verify with:

```bash
python3 tests/fixtures/diagnostic-accuracy/v0.1/generate_corpus.py
python3 tests/fixtures/diagnostic-accuracy/v0.1/generate_corpus.py --check
cargo test engine::accuracy_corpus_tests::published_diagnostic_accuracy_is_reproducible
```
