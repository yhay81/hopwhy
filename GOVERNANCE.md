# Governance

HopWhy uses a maintainer-led model.

- Contributors propose issues and pull requests.
- Maintainers triage changes, protect public contracts and safety claims, and
  decide releases.
- Release managers are maintainers authorized to create signed tags and
  publish artifacts.

The repository owner is the current maintainer and release manager. New
maintainers may be added after sustained, high-quality contributions and
demonstrated judgment around network safety, redaction, compatibility, and
incident response.

## Decision principles

Decisions prioritize:

1. avoiding surprising network activity or disclosure;
2. accurate, calibrated causal claims;
3. stable machine contracts and reproducible fixtures;
4. cross-platform behavior;
5. maintainability and contributor usability.

Material probe, safety-default, or schema changes should be discussed in an
issue. Maintainers seek consensus but may decide when necessary. A short
rationale should be recorded for consequential decisions.

Contributor pull requests need maintainer approval. Maintainer-authored pull
requests may be merged after required checks pass and any review feedback is
resolved. Releases follow [RELEASING.md](RELEASING.md).
