# Platform support

HopWhy 0.1 builds and tests on:

| Platform | Architecture | Release artifact | Support |
| --- | --- | --- | --- |
| Linux | x86_64 | `.tar.gz` | supported |
| macOS | x86_64 | `.tar.gz` | supported |
| macOS | arm64 | `.tar.gz` | supported |
| Windows | x86_64 | `.zip` | supported |

Rust 1.85 is the minimum supported compiler.

## Cross-platform guarantees

- same command names, schema versions, exit-code classes, and safety defaults;
- system resolver use with IPv4/IPv6 address visibility;
- bounded standard TCP connections;
- public-root rustls validation for the independent direct TLS phase;
- reqwest/rustls HTTP client with platform trust and automatic redirects
  disabled;
- deterministic local fixture tests without public-network dependency.

## Expected variation

Resolver answer order, timing, proxy environment, address availability, socket
errors, and certificate trust context can vary. Reports retain these as
observations and limitations.

Route/interface selection, native resolver configuration, packet paths, PAC,
SOCKS, OS-native certificate store differences, and proxy CONNECT internals are
not normalized in 0.1.

For platform-specific failures, include the OS version, HopWhy version, compact
capabilities output, a redacted dry-run plan, and the smallest safe report.
