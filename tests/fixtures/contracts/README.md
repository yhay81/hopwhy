# Report compatibility corpus

`v0.1/dns-failure.report.json` is the byte-for-byte compatibility artifact for
`hopwhy.report.v1`. It models an observable DNS failure, the phases not reached
after that failure, bounded probe usage, a calibrated hypothesis, and the
integrity seal used by offline replay and compare.

`manifest.json` pins the accepted file digest and declares mutations that the
current report reader must reject. Published version directories are immutable;
add a new directory for an intentional future contract version.
