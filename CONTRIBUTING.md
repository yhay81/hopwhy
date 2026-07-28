# Contributing to HopWhy

Thank you for helping improve evidence-calibrated network diagnostics.

## Before opening a change

Use a GitHub issue for behavior changes, new probe classes, or contract changes.
Security reports must follow [SECURITY.md](SECURITY.md), not public issues.

Changes must preserve these boundaries:

- observations and hypotheses remain separate;
- no target failure is described as a root cause without deterministic evidence;
- no new network action occurs outside the declared probe inventory and budget;
- redirects and newly resolved addresses are re-authorized;
- sensitive values are redacted by default;
- offline commands remain network-free;
- public schema and exit-code changes are documented.

## Development

Rust 1.85 is the minimum supported version.

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo +1.85.0 check --all-targets --locked
cargo package --locked --allow-dirty
```

URL policy and offline report parsing are continuously fuzzed. See
[FUZZING.md](FUZZING.md) for the reproducible local command and crash-handling
rules.

Tests must use local deterministic fixtures. Do not make public-network tests a
required CI dependency. Fault tests should assert the earliest failed phase,
evidence, limits, redaction, and exit behavior.

## Pull requests

Keep changes focused. Include:

- user-visible behavior and safety impact;
- machine-contract or compatibility impact;
- exact verification commands;
- a fixture for new success and failure behavior;
- documentation updates where applicable.

By contributing, you agree that your contribution is licensed under MIT and
that you will follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
