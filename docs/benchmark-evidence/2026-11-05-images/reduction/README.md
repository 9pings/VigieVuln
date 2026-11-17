# Image comparison: reduction pass

These files document the final replay of a reduction pass over the same OCI manifests and frozen
Trivy/Grype outputs as the earlier [recall comparison](../recall/final-comparison/). The
previous comparisons and raw scanner outputs remain unchanged. The data is a
snapshot, not a claim of exhaustive detection or runtime exploitability.

| Image | VV findings | VV distinct CVEs | VV package/version/CVE tuples | Trivy-only tuples | Grype-only tuples |
| --- | ---: | ---: | ---: | ---: | ---: |
| NGINX | 707 | 409 | 629 | 185 / 788 | 2 / 600 |
| Traefik | 285 | 234 | 273 | 0 / 204 | 51 / 206 |

The exact comparisons are [NGINX](nginx-comparison.json) and
[Traefik](traefik-exact-comparison.json); the corresponding VV final
findings are [NGINX](nginx-findings.json.gz) and
[Traefik](traefik-findings.json.gz). Each replay recorded one warning: EUVD
detail HTTP 403 prevented retrieval for 28 NGINX and 11 Traefik CVEs.

The separate [Traefik same-binary comparison](traefik-comparison.json) records
its evidence: the image manifest, executable path and SHA-256, embedded Go module
and revision, OCI source/version labels, and module-proxy tag/revision agreement.
Grype's generic binary and VV's Go module are not treated as the same coordinate
in the exact comparison. When the identity evidence is applied, 46 of Grype's 47
program observations relate to the same binary; five observations remain across
the program and Alpine packages. The proof does not establish function reachability.
The [selected CVEProject records](traefik-cveproject-records.json.gz) and
[selection metadata](traefik-cveproject-selection.json) retain source scope.

The two NGINX-only Grype observations concern a third-party NGINX package matched
against Debian data; see the linked primary-source discussion in the
[benchmark](../../../BENCHMARK-IMAGES.md). The 185 remaining Trivy tuples require
individual adjudication. Public Freexian ELA notices provide release-specific
fixed versions for nine tuples among the preceding 194 post-LTS gaps. An ELA does
not necessarily publish the version in which the issue was introduced, and its
fix requires the corresponding Extended LTS repository. Remaining unresolved
items are not automatically false positives.

The current Debian tracker is also consulted independently of its historical snapshot.
All 185 remaining Trivy tuples appear among 191 **unconfirmed observations** in the
NGINX report. They are excluded from confirmed vulnerability totals. The
[candidate evidence](nginx-current-candidates-result.json) and
[replay procedure](nginx-current-candidates-README.md) record the source commit,
comparison thresholds and release annotations. A rule for a current source package
does not by itself establish applicability to unsupported Debian 11.

[Validation](validation.json) records the full CLI suite (2,266 passed, 11 skipped,
zero failures), server suite (590 passed), 22 additional targeted tests, offline
network tripwires and standalone NGINX finding/risk/fix parity with no executables
in PATH. The generated HTML was inspected in Chromium without horizontal overflow.
The [deployment receipt](deployment.json) and [source manifest](deployed-source-manifest.json)
identify the installed build; both public health endpoints returned HTTP 200.

The generic proxy diagnostic follow-up separates cache revalidation from failed
refresh, and deduplicates a source-level alert only when its exact failed requests
already have detailed alerts. See [regression validation](proxy-warning-validation.json).
The typed CVE package index is [published in production](production-package-index.json):
4,317 entries, no missing raw source records, and a local typed Go query returns
12 records. This local administrative check is separate from client authentication.
