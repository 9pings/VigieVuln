# External application verification — 17 November 2026

Measurements for VigieVuln 1.3.0. See the [benchmark](../../BENCHMARK.md)
for results and scope.

| Evidence | Contents |
| --- | --- |
| [Verification summary](verification-summary.json) | Exact repository commits, profiles, findings counts, warnings and remaining limitations |
| [Maven](maven-verdict.json) | OpenRefine native trees, SBOM inventories and local-reactor coverage |
| [Gradle](gradle-verdict.json) | Traccar's 18 unlocked version disagreements and sampled advisory checks |
| [Scoped lock](gradle-scoped-lock-runtime.json) / [all-configuration lock](gradle-all-lock-runtime.json) | Native Gradle lock variants compared by version sets, retaining scope differences |
| [Python](python-verdict.json) | Preserved pip resolution, the 61 missing transitives and selected advisory boundary checks |
| [Paperless npm](paperless-npm-inventory.json) | Independent package-lock inventory comparison |
| [pip-audit](checker-comparison.json) | Same-inventory comparison with PyPI and OSV services, explicit aliases and exact package/version identities |
| [Export integrity](export-integrity.json) | Finding-to-component links, duplicate refs and orphan refs |
| [Python findings stability](python-findings-stability.json) | Python finding-set comparison |
| [Test summary](test-suite.txt), [runtime versions](environment-versions.txt), [source hashes](scanner-sha256.json) | Code/test/environment provenance |

`reports/` contains compressed findings, CycloneDX exports and raw pip-audit
outputs. `SHA256SUMS` covers the published files. Clones and caches are not bundled;
JSON workspace paths are provenance, not hosted links.

Reproduce using the recorded commits, runtime versions, scan profiles and
[checker arguments](checker-commands.json). Compare package/version/advisory sets,
not raw counts. Live feeds and fresh pip resolutions can change the results.
