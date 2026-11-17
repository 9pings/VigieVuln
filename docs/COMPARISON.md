# VigieVuln comparisons and build-free scanning

VigieVuln audits source checkouts, application components and, when explicitly requested,
container images. It produces reports and exports for review; it does not establish that a
vulnerability is reachable or that a scan has found every dependency. False positives and
omissions remain possible. Consult the report's coverage warnings and verify decisions
against the actual build, deployment and advisory evidence.

Comparison results depend on the project, input files, tool version, configuration, database
and date. They are not a universal ranking. The dated source-project comparisons and their
methodology are in [BENCHMARK.md](BENCHMARK.md); image inputs, tools and limits are in
[BENCHMARK-IMAGES.md](BENCHMARK-IMAGES.md). Trivy, Grype/Syft, OSV-Scanner and other tools
may be useful alongside VigieVuln, particularly when their inventory or advisory sources
differ. VigieVuln can also merge an optional Snyk scan using `--snyk`.

## Real-project checks — 17 November 2026

Four fixed GitHub application releases were cloned and scanned in isolated Docker
containers. Their Maven, Gradle or Python inventories were compared to native resolution;
the applications were not deployed and exploitability was not tested. The scan used a
17 November CVEProject snapshot with `--cve-offline`; other sources remained enabled online.
The reports record source failures and incomplete coverage. See the
[verification summary](benchmark-evidence/2026-11-17/verification-summary.json) for commits,
commands, counts, warnings and the scope of each check.

- **OpenRefine 3.9.0:** 152 of 153 external Maven coordinate/version pairs from the 12-module
  native Maven trees were in the corrected SBOM. One `commons-io` version remained absent
  from resolution when a local reactor POM was not followed; the scan warned about a missing
  POM. No particular missed CVE was established for that omission.
- **Traccar 6.6:** unlocked POM-based traversal selected different transitive versions from
  Gradle in 18 cases; two checked findings were false positives for the native runtime graph.
  A scoped Gradle lock covered the 265 runtime library versions checked. An all-configuration
  lock also included build tooling, illustrating why the chosen configurations matter.
- **Paperless-ngx 2.14.7:** the tested Python and npm lock inventories matched the independent
  version lists after correcting the SBOM's multi-version export. Selected advisory checks
  were performed; this was not an exhaustive assessment of vulnerabilities or exploitability.
- **NetBox 4.2.3:** all 38 pinned Python requirements were inventoried, but 61 of 99
  distributions in a fresh native pip resolution were absent from that unlocked scan. This
  resolution describes the test environment and date, not a historical deployed environment.

A separate [pip-audit comparison](benchmark-evidence/2026-11-17/checker-comparison.json)
used the same 99 pinned distributions, matching normalized names, equivalent versions and
explicit advisory identifiers or aliases. Every recorded pip-audit advisory from the PyPI and
OSV services had a corresponding VigieVuln finding on that input; VigieVuln also reported
one finding absent from the PyPI service result. This checks matching on a supplied inventory; it does not
establish that an unlocked manifest scan discovers its transitive dependencies.

## How it's autonomous (no build tools)

VigieVuln reads supported manifests and lockfiles without installing packages or running the
project's build tools. Its own resolution is an approximation where the native tool or a
complete lockfile is absent; it is not a substitute for the build's actual dependency graph.

| Input | What the scanner uses | Important limit |
| --- | --- | --- |
| Maven | Parses POMs, local inheritance and supported BOMs; traverses available dependency POMs per module. | Missing POMs, profiles, classifiers or reactor relationships can leave versions or dependencies unresolved. Review warnings and compare with Maven when accuracy matters. |
| Gradle | Reads supported build files, catalogs and `gradle.lockfile`; may traverse Maven POMs. | Without a lockfile, POM-based versions and graph can differ from Gradle. Locks contain only written configurations; build, test and runtime may differ or be combined. Compare against the relevant native Gradle configurations. |
| npm / Yarn / pnpm | Parses supported lockfile formats; without a lock, checks supported exact manifest pins. | A manifest-only inventory is partial and cannot establish the complete installed tree. |
| Composer | Reads `composer.lock`, or supported exact `composer.json` pins without it. | Manifest-only scans are partial. |
| Python | Reads supported Poetry, Pipenv, uv and PDM locks; checks supported exact pins in requirements and `pyproject.toml`. | Without a resolved lock, it does **not** resolve transitive packages. Markers, platform and environment affect native resolution. |
| NuGet, Go and Ruby | Reads supported lockfiles or manifests directly. | Coverage depends on the format, target and metadata; see [usage](USAGE.md). |
| Vendored files and binaries | Inspects supported committed JavaScript, JARs, native binaries and certificates. | Identification and advisory coverage depend on available evidence. |

Maven metadata, registries and advisory feeds are normally queried online and cached; cache
freshness and source availability affect results. `--offline` prevents network access but
requires the needed data and dependency metadata to have been prepared beforehand. A seed
containing advisory data alone does not provide every POM. See the
[air-gapped workflow](../README.md#air-gapped-audits) and [data sources](DATA-SOURCES.md).

Source-tree image analysis is **off by default**. Enable it with `--images`, or use the
separate `vigievuln image` command for an archive, registry image, root filesystem or
publisher inventory. The scanner does not need a Docker daemon; the findings only cover the
contents and sources actually acquired. See [IMAGES.md](IMAGES.md).
