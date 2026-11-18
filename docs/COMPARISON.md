# Scanning and comparisons

VigieVuln reads supported manifests and lockfiles without building or installing the
project. It scans source dependencies, vendored components and explicitly selected images.

## Feature comparison

Capabilities were checked against the linked product documentation on **18 November 2026**.
Cells describe selected CLI workflows, not relative accuracy or equivalent coverage.
“Not assessed” means this comparison makes no support claim. Snyk cells distinguish
Open Source (OSS) from Container; features can depend on a plan, authentication or version.

| Capability | VigieVuln | OSV-Scanner | Trivy | Grype + Syft | OWASP Dependency-Check | Snyk OSS / Container |
| --- | --- | --- | --- | --- | --- | --- |
| Source dependencies | Manifests / locks; no build | Supported manifests / locks | Filesystem / repository scan | Directory via Syft catalogers | File analyzers / build integrations | OSS: supported manifests |
| Container images | Image command; source opt-in | Image command / archive | Image scan | Image via Syft | Not assessed | Container test |
| SBOM input | Image command: CycloneDX / SPDX | CycloneDX / SPDX | SBOM scan | CycloneDX / SPDX | Not assessed | SBOM test |
| SBOM output | CycloneDX 1.6 | CycloneDX / SPDX¹ | CycloneDX / SPDX | Syft: CycloneDX / SPDX | Not assessed | OSS: Enterprise² |
| Offline vulnerability scan | Prepared cache | Prepared OSV database | Prepared DB; offline flags | Prepared DB; update disabled³ | Cached data; --noupdate⁴ | Service-backed; exceptions vary |
| CMS instance inventory | Nine products; coverage varies | Not assessed | Not assessed | Not assessed | Not assessed | Not assessed |
| End-of-life context | Application frameworks; optional support data | Not assessed | OS distributions | OS distro warnings | Not assessed | Not assessed |
| License review | Optional registry / SPDX checks | --licenses; deps.dev | License scanner | Syft metadata; Grant policy | Not assessed | OSS license policies |
| Secrets / key material | Keys and certificates only | Not assessed | Secret scanner | Not assessed | Not assessed | Separate Snyk products |
| Reports | HTML, JSON; Word optional | HTML, JSON, SARIF | JSON, SARIF, templates | JSON, SARIF, templates | HTML, JSON, SARIF | JSON, SARIF |
| CI failure control | --fail-on / incomplete | Exit status / config | --exit-code | --fail-on | --failOnCVSS | OSS / Container thresholds |

¹ OSV-Scanner SBOM output contains only vulnerable packages unless `--all-packages` is used.
² Snyk OSS SBOM generation requires an Enterprise plan and an internet connection; Container
SBOM generation has its own Enterprise/early-access conditions. ³ Grype validates database age
by default; offline use requires a prepared database and suitable update/age configuration.
⁴ OWASP `--noupdate` disables specified automatic updates; prepare required data and disable or
configure network-dependent analyzers for the intended offline workflow. License findings and
secret scanning have different scopes; VigieVuln's key/certificate inventory is not a general
secret scanner.

Primary documentation: [OSV-Scanner usage and licenses](https://google.github.io/osv-scanner/usage/),
[OSV image](https://google.github.io/osv-scanner/usage/scan-image),
[OSV offline](https://google.github.io/osv-scanner/usage/offline-mode/),
[Trivy source scans](https://trivy.dev/docs/latest/target/filesystem/),
[Trivy scanners and gating](https://trivy.dev/docs/latest/configuration/others/),
[Trivy air gap](https://trivy.dev/docs/v0.55/guide/advanced/air-gap/),
[Grype scan targets](https://oss.anchore.com/docs/guides/vulnerability/scan-targets/),
[Grype database](https://oss.anchore.com/docs/guides/vulnerability/database/),
[Syft and Grant](https://oss.anchore.com/docs/projects/),
[Syft scan targets](https://oss.anchore.com/docs/guides/sbom/scan-targets/),
[Dependency-Check analyzers](https://dependency-check.github.io/DependencyCheck/analyzers/index.html),
[Dependency-Check CLI](https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html),
[Snyk OSS test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test),
[Snyk Container test](https://docs.snyk.io/developer-tools/snyk-cli/commands/container-test),
[Snyk SBOM](https://docs.snyk.io/developer-tools/snyk-cli/commands/sbom) and
[Snyk Container SBOM](https://docs.snyk.io/developer-tools/snyk-cli/commands/container-sbom).

## How it's autonomous (no build tools)

| Input | Resolution and limits |
| --- | --- |
| Maven | POMs, inheritance, BOMs and dependency POM traversal; missing metadata or unsupported reactor relationships can leave gaps. |
| Gradle | Locks, catalogs and static build-file parsing. Without a lock, POM traversal can differ from Gradle; locked configurations may mix runtime, tests and tooling. |
| npm / Yarn / pnpm / Composer | Supported locks; exact manifest pins provide a partial inventory without a lock. |
| Python | Supported locks or exact manifest pins; no pip-style transitive resolution. |
| NuGet / Go / Ruby | Supported locks and manifests; coverage depends on format and target. |
| Binaries and images | Supported content and identity metadata. Source-tree image analysis is opt-in (`--images`). |

Offline scans require prepared advisory data and dependency metadata. See
[usage](USAGE.md), [images](IMAGES.md) and [data sources](DATA-SOURCES.md).

## Measured comparisons

The [17 November application benchmark](BENCHMARK.md#application-checks--17-november-2026)
compares OpenRefine, Traccar, Paperless-ngx and NetBox with native inventories.
On the same 99 Python packages, VigieVuln matched all recorded pip-audit OSV and
PyPI advisories. Inventory gaps and false positives remain in some manifest-only scans.

Results depend on inputs, configuration, sources and date; they do not establish
exhaustive coverage or exploitability. See the [source benchmarks](BENCHMARK.md)
and [image benchmarks](BENCHMARK-IMAGES.md) for evidence and scope.
