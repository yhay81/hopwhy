# Releasing HopWhy

Only a release manager named in [GOVERNANCE.md](GOVERNANCE.md) may release.

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
5. Confirm Linux, macOS, Windows, Rust 1.85, RustSec, schemas, documentation
   links, package contents, and repeated fixture cases in hosted CI.
6. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.2.0 -m "HopWhy 0.2.0"
   git push origin v0.2.0
   ```

7. The release workflow creates four native archives, completions, a CycloneDX
   SBOM, `SHA256SUMS`, a GitHub release, and GitHub/Sigstore build-provenance
   and SBOM attestations.
8. Download all assets into a clean directory. Verify checksums and both
   attestation predicates:

   ```bash
   sha256sum --check SHA256SUMS
   gh attestation verify hopwhy-v0.2.0-linux-x86_64.tar.gz \
     --repo yhay81/hopwhy
   gh attestation verify hopwhy-v0.2.0-linux-x86_64.tar.gz \
     --repo yhay81/hopwhy \
     --predicate-type https://cyclonedx.org/bom
   ```

9. Inspect every archive layout. On each native platform run `--version`,
   completion generation, brief schema emission, and a local fixture lifecycle.
10. Release notes must link installation, checksums, SBOM/provenance
    verification, changelog, platform guarantees, safety limits, and private
    security reporting.

Publishing to crates.io remains manual until registry ownership and credentials
are configured:

```bash
cargo publish --locked
```

Never move or reuse a published tag or version. Follow a failed release with a
documented patch release.
