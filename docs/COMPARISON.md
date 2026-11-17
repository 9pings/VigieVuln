# Scanning and comparisons

VigieVuln reads supported manifests and lockfiles without building or installing the
project. It scans source dependencies, vendored components and explicitly selected images.

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
