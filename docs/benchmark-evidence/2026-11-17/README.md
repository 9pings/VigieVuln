# External application verification — 17 November 2026

These are dated measurements of the 1.3.0 development tree, including the
targeted Gradle literal-version and multi-version CycloneDX corrections.
They record limitations as well as successful comparisons. See the
[benchmark explanation](../../BENCHMARK.md) before interpreting counts.

| Evidence | Contents |
| --- | --- |
| [Verification summary](verification-summary.json) | Exact repository commits, profiles, findings counts, warnings and remaining limitations |
| [Maven](maven-verdict.json) | OpenRefine native trees, SBOM before/after and unresolved local-reactor path |
| [Gradle](gradle-verdict.json) | Traccar's 18 unlocked version disagreements and sampled advisory checks |
| [Scoped lock](gradle-scoped-lock-runtime.json) / [all-configuration lock](gradle-all-lock-runtime.json) | Native Gradle lock variants compared by version sets, retaining scope differences |
| [Python](python-verdict.json) | Preserved pip resolution, the 61 missing transitives and selected advisory boundary checks |
| [Paperless npm](paperless-npm-inventory.json) | Independent package-lock inventory comparison before/after the SBOM correction |
| [pip-audit](checker-comparison.json) | Same-inventory comparison with PyPI and OSV services, explicit aliases and exact package/version identities |
| [Export integrity](export-integrity.json) | Finding-to-component links, duplicate refs and orphan refs |
| [Python findings stability](python-findings-stability.json) | Finding sets unchanged by the SBOM-only correction |
| [Test summary](test-suite.txt), [runtime versions](environment-versions.txt), [source hashes](scanner-sha256.json) | Code/test/environment provenance |

The `reports/` directory contains gzip-compressed JSON findings and CycloneDX
exports for the final application runs, plus the unlocked Traccar and the
resolved-Python NetBox variants. Raw pip-audit outputs are preserved as
`pip-audit-pypi.json.gz` and `pip-audit-osv.json.gz`. `SHA256SUMS` covers the
published files. Local clones, caches, environments and screenshots are not
bundled here; their original execution paths in JSON are provenance, not links
to hosted files. Personal workspace prefixes were replaced with `<workspace>`.

To repeat the procedure, use the commits and runtime versions in these files,
clone inside an isolated container, obtain native inventories before comparing
scanner outputs, and run the CLI with the recorded profile. The
[checker arguments](checker-commands.json) show the same-inventory pip-audit
comparison. Compare sets using normalised package names, equivalent versions and
explicit advisory aliases, not just raw finding counts. Live indexes and feeds
can change: a fresh pip resolution or advisory consultation need not reproduce
this snapshot. No application deployment or exploitability test was performed.
