# Releasing HopWhy

Only a release manager named in [GOVERNANCE.md](GOVERNANCE.md) may release.

## v1 evidence gate

Every release validates the checked-in evidence manifest structure:

```bash
python3 scripts/verify_v1_evidence.py \
  .github/v1-evidence.json --check-structure
```

For every v1 or later release, update the manifest with public, reviewable
evidence for the exact target version and run:

```bash
python3 scripts/verify_v1_evidence.py \
  .github/v1-evidence.json \
  --require-ready \
  --release-version 1.0.0
```

The verifier derives readiness from the evidence. Do not add a bypass, count
maintainer activity as adoption, suppress a failed gate, or move evidence dates
forward. The continuous window must end on `as_of` and include one public
successful-run URL for every required track on every date.

1. Confirm the version is unpublished and `CHANGELOG.md`, `Cargo.toml`, and
   `Cargo.lock` agree.
2. Confirm the release commit is on `main`, the worktree is clean, and all
   required checks pass.
3. Run:

   ```bash
   cargo fmt --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --all-targets --locked
   cargo +1.85.0 check --all-targets --locked
   cargo package --locked --allow-dirty
   cargo build --release --locked
   target/release/hopwhy --format json schema --document brief
   ```

4. Dogfood the release binary against deterministic local success, failure,
   redirect, truncation, private-policy, integrity, compare, and replay cases.
   Confirm dry-run/compare/replay make no network connection.
5. Review the current IANA IPv6 Special-Purpose Address Space registry against
   the dated snapshot in `src/policy.rs`. Update the classifier and table-driven
   policy tests before release when reachability assignments changed.
6. Confirm Linux, macOS, Windows, Rust 1.85, RustSec, schemas, documentation
   links, package contents, and repeated fixture cases in hosted CI.
7. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.3.0 -m "HopWhy 0.3.0"
   git push origin v0.3.0
   ```

8. The release workflow creates four native archives, completions, a CycloneDX
   SBOM, `SHA256SUMS`, a GitHub release, and GitHub/Sigstore build-provenance
   and SBOM attestations. Each archive includes a downloadable
   `.intoto.jsonl` provenance bundle for local verification.
9. Download all assets into a clean directory. Verify checksums and both
   attestation predicates:

   ```bash
   sha256sum --check SHA256SUMS
   gh attestation verify hopwhy-v0.3.0-linux-x86_64.tar.gz \
     --repo yhay81/hopwhy
   gh attestation verify hopwhy-v0.3.0-linux-x86_64.tar.gz \
     --repo yhay81/hopwhy \
     --bundle hopwhy-v0.3.0-linux-x86_64.tar.gz.intoto.jsonl \
     --signer-workflow yhay81/hopwhy/.github/workflows/release.yml
   gh attestation verify hopwhy-v0.3.0-linux-x86_64.tar.gz \
     --repo yhay81/hopwhy \
     --predicate-type https://cyclonedx.org/bom
   ```

10. Inspect every archive layout. On each native platform run `--version`,
   completion generation, brief schema emission, and a local fixture lifecycle.
11. Release notes must link installation, checksums, SBOM/provenance
    verification, changelog, platform guarantees, safety limits, and private
    security reporting.

## crates.io

The first crates.io release must be published manually because Trusted
Publishing can only be configured after the crate exists. From the exact signed
release commit, repeat `cargo publish --dry-run --locked`, review
`cargo package --list --locked`, then publish:

```bash
cargo publish --locked
```

Use a Cargo credential provider backed by the operating-system credential
store. Never put a crates.io token in Git, workflow YAML, logs, or a
repository-level Actions secret. If Cargo times out after upload, check the
crates.io page and index before retrying; an accepted version is immutable.

After the first manual release:

1. Add the crate's Trusted Publisher in crates.io, restricted to
   `yhay81/hopwhy`, the dedicated publish workflow filename, and the protected
   `crates-io` GitHub environment.
2. Add that workflow only after the mapping exists. Grant only
   `contents: read` and `id-token: write`, pin every action to an immutable
   commit, exchange OIDC with `rust-lang/crates-io-auth-action`, and run
   `cargo publish --locked`.
3. Remove any temporary API token, verify registry ownership and account
   recovery without recording secrets, and require environment approval for
   every publish.
4. Install the exact version from crates.io in a clean environment and repeat
   the CLI smoke checks.

Never move or reuse a published tag or version. Follow a failed release with a
documented patch release.
