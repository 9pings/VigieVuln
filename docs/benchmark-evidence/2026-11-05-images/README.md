# Image comparator evidence — 5 November 2026

See [the comparative report](../../BENCHMARK-IMAGES.md) for findings and limitations.
`raw/` preserves compressed scanner reports and inventories with uncompressed
SHA-256 hashes. `vv-pathways.json` records isolated direct/transfer/offline runs;
`fleet-equality.json` checks finding, severity and enrichment tuples across paths.
`implementation.json` fingerprints the uncommitted CLI source and Linux executable.

The two linux/amd64 OCI layouts were acquired with VigieVuln's `fetchRegistryImage` (no container execution). Trivy and Grype scanned the same OCI directory for each image. The raw results, logs, image layouts and database snapshots are in `/tmp/vv-image-benchmark-20261105/{traefik,nginx}` and its sibling cache directories on the benchmark host; hashes and acquisition metadata are in `provenance.json`. The OCI layout's platform manifest digest is the input identity; the Docker Hub tag is only the resolution used at acquisition time.

Trivy 0.76.1 used `--scanners vuln --offline-scan --list-all-pkgs`, all severities and unfixed findings included. Grype 0.121.0 used its default vulnerability matching and squashed image scope; no extra CPE matching was enabled. Its CycloneDX output contains file records as well as packages, so count library components separately. The databases were refreshed once before the scans, then updates were disabled for both targets. The Trivy Java DB was needed for the nginx image; the first nginx attempt failed before the Java DB was present and is excluded. An early Trivy attempt against an OCI tar failed because this Trivy version expects an OCI directory for `--input`; it is excluded.

`run-comparators.sh` reruns the frozen comparison given those layouts, binaries and databases. Comparing findings requires exact package/version identities and documented advisory relationships; package inventory and advisory datasets differ across tools. A difference is not by itself a false positive or a confirmed omission. Both distributions were reported as end-of-life by the comparators, so their coverage may be incomplete.
