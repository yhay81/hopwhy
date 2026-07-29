# Machine contract

The compact contract is authoritative for command names, output formats, schema
versions, exit classes, and safety defaults:

```bash
hopwhy --format json schema --document brief
```

## Schema documents

```bash
for document in brief spec report plan compare replay capabilities error; do
  hopwhy --format json schema --document "$document"
done
```

The full documents use JSON Schema draft-07. Current top-level identifiers are:

| Document | `schema_version` |
| --- | --- |
| inspect report | `hopwhy.report.v1` |
| dry-run plan | `hopwhy.plan.v1` |
| compare | `hopwhy.compare.v1` |
| replay | `hopwhy.replay.v1` |
| capabilities | `hopwhy.capabilities.v1` |
| error | `hopwhy.error.v1` |
| compact contract | `hopwhy.contract.v1` |

Specs are strict and reject unknown fields. Output reports remain forward
extensible within a major schema version, but consumers should ignore unknown
fields and branch on `schema_version`. The v0.1 seal binds fields modeled by
the v0.1 reader after deserialization; ignored extension fields are not
integrity-protected evidence.

## Output

- `human` is concise and not a parsing contract.
- `json` is one pretty-printed document.
- `ndjson` is exactly one compact document plus a trailing newline.
- completion output is raw shell source.

Query values, addresses, and body bytes follow the option values recorded in
`options`. Consumers can therefore detect a report with expanded disclosure.
Proxy credentials are unconditionally excluded from both the endpoint and its
configuration fingerprint.

## Diagnostic versus operational failure

A refused connection, invalid certificate, or redirect limit can be a valid
diagnostic observation. If HopWhy emitted an integrity-sealed report, the
command exits 0 and `failed_at` plus phase errors carry the target outcome.

Nonzero exits mean HopWhy could not produce the requested contract:

| Code | Class |
| ---: | --- |
| 1 | local I/O/setup |
| 2 | usage/input |
| 3 | pre-report policy |
| 4 | local input/operation budget |
| 5 | contract/integrity |

Machine errors use `hopwhy.error.v1`.

## Compatibility

Before 1.0, breaking changes may occur in a minor release but must receive a
new schema version and changelog entry. Patch releases do not intentionally
break a published schema or exit-code meaning.

The digest-pinned [v0.1 report
corpus](../tests/fixtures/contracts/README.md) freezes exact serialization and
offline replay behavior for a representative DNS failure and declares the
mutations that every current reader must reject.
