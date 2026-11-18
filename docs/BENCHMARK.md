# Scanner comparisons — updated 17 November 2026

## Application checks — 17 November 2026

Four fixed application releases were scanned in Docker and compared with native
inventories. Results describe these inputs and environments, not general accuracy
or exploitability.

| Application | Version | Result |
| --- | --- | --- |
| OpenRefine | 3.9.0 | 152/153 Maven coordinate/version pairs present. `commons-io:2.16.1` is missing on a local-reactor `packaging/provided` path; no specific missed CVE established. |
| Traccar | 6.6 | 48/48 direct production versions match. Without a lock: 18 runtime version differences and two confirmed false positives (Guava/CVE-2023-2976, HttpClient/CVE-2020-13956). A four-classpath Gradle lock covers all 265 runtime versions and avoids those alerts, but also includes compile/test entries and BOMs. All-configuration locks include tooling, some classified as production. |
| Paperless-ngx | 2.14.7 | All 184 Python and 1,302 npm lockfile pairs present, including development and optional-platform entries. |
| NetBox | 4.2.3 | All 38 requirements pins present; 61 additional transitives from a fresh pip resolution are absent from the manifest-only scan. This Python 3.11/Linux resolution does not establish historical deployed versions. |

On the same 99 resolved Python packages, VigieVuln matches all recorded pip-audit
2.10.1 observations: 102 advisory groups via OSV and 101 via PyPI, with one
additional Pillow finding in VigieVuln. Matching uses explicit advisory aliases;
shared data sources limit the independence of this comparison.

Scans used the 17 November CVEProject snapshot (`--cve-offline`), other ordinary
sources online, `--retries 0`, and images disabled. Some runs had EUVD HTTP 403
and incomplete CVEProject npm coverage. Selected Django, Requests and h11
advisories and fixed-version boundaries were checked; exploitability was not tested.

Evidence: [run summary](benchmark-evidence/2026-11-17/verification-summary.json),
[pip-audit comparison](benchmark-evidence/2026-11-17/checker-comparison.json),
[inventories and exports](benchmark-evidence/2026-11-17/README.md).

## Maven scanner comparison — 3 November 2026

The pinned inputs are Apache Dubbo 2.7.8 and Spring Petclinic 2.4.5. The
VigieVuln runs below use the working tree recorded in the evidence; they compare
with preserved 2 November scanner reports, not refreshed comparator databases.

| Project | VigieVuln findings | Snyk observations | Matched Snyk | Snyk-only | VigieVuln-only |
| --- | ---: | ---: | ---: | ---: | ---: |
| Dubbo | 794 online / warm offline | 708 | 577 | 131 | 207 |
| Petclinic | 174 offline | 215 | 142 | 73 | 31 |

No omissions against OSV-Scanner, Trivy or Grype were observed in these compared
sets. This does not establish exhaustive detection: 53 confirmed Dubbo omissions
remain in the Snyk comparison, and not every unmatched finding is adjudicated.
Shared advisory sources also limit scanner independence.

Evidence: [Dubbo comparison](benchmark-evidence/2026-11-03/dubbo-classic-comparison.json),
[Petclinic comparison](benchmark-evidence/2026-11-03/petclinic-classic-comparison.json),
[run profiles and report hashes](benchmark-evidence/2026-11-03/field-debug-results.json).

## OSV-scoped comparison — 2 November 2026

OSV-Scanner 2.3.8 used the live OSV API. VigieVuln used the recorded development
build with OSV-only lockfile profiles; Dubbo also enabled cached CVEProject data.
These measurements do not represent every source in the default scan. Warm offline
runs used prepared project caches and Docker `--network none`; cold runs used a
fresh home initialized only from the recorded seed.

| Ecosystem and input | Project and commit | OSV online | VigieVuln online | VigieVuln offline | Observed difference |
| --- | --- | ---: | ---: | ---: | --- |
| Maven reactor | [Apache Dubbo](https://github.com/apache/dubbo) `0be2a1bbbf9168490acecaf1eed1bd16cb8db402` | 727 | 734 | 734 | Seven additional groups; see per-record evidence |
| npm, package-lock | [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 320 | 320 | 320 | Same set |
| PyPI, root poetry.lock | [Poetry](https://github.com/python-poetry/poetry) `46bf7fd3d1797b75ad9b07adc280039d93414e07` | 90 | 90 | 90 | Same set |
| RubyGems, Gemfile.lock | [Mastodon](https://github.com/mastodon/mastodon) `fbcbf7898f000d9d1a21d52e8a8d3ed4602aa7db` | 158 | 158 | 158 | Same set; cold seed also 158 |
| Packagist, composer.lock | [phpMyAdmin](https://github.com/phpmyadmin/phpmyadmin) `ed65cd2d8b26073d30311163f8e25e722a9aef0f` | 36 | 36 | 36 | Same set |
| Yarn v1, yarn.lock | Mastodon, same commit | 273 | — | 273 | Same set; cold seed |
| pnpm v5.4, pnpm-lock.yaml | [Vite](https://github.com/vitejs/vite) `566d4c7bb51cf56550a5374ee46e1e1cbea1cf1f` | 235 | — | 235 | Same set; cold seed |


Yarn and pnpm used isolated lockfile scopes and cold seeded caches; no online
VigieVuln run was measured for those rows. Other offline values are warm unless
stated otherwise. Poetry excludes its test fixtures. Trivy did not support the
pnpm lockfile used here; that is not a zero-vulnerability result.

For Prometheus commit `37468d88dce85ac507f3fb7864c7d1c078e3e27d`, VigieVuln returned
127 Go advisory groups online and warm offline. Its static inventory held 187 of
577 modules resolved by `go list -m all`. The `go 1.14` directive does not prove the
compiled standard-library version, so OSV's inferred standard-library findings
are excluded from dependency parity.

[Per-record evidence](benchmark-evidence/2026-11-02/) records versions, source profiles,
scanner outputs and adjudications. Counts compare package/version/advisory groups
using explicit identifier aliases; equal totals alone do not establish equal sets.

## Reproduce and interpret

Pin the project revision, scanner versions, source profile and database dates.
Compare inventories before findings, normalize explicit advisory aliases, and
check disputed results against publisher records and exact affected versions.
A cold advisory seed does not replace dependency metadata needed for resolution.

See [feature comparison](COMPARISON.md), [image benchmarks](BENCHMARK-IMAGES.md)
and [validation workflow](VALIDATION.md).
