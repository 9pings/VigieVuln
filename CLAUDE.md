
# VigieVuln CLI repository

This Git repository contains the `vigievuln` npm CLI at its root. Run `npm ci`,
`npm test`, and `npm run pack:release` here. The package version is 1.4.0;
`package.json` is authoritative for the version and supported Node.js releases.
The independent server repository lives alongside this checkout at `../server`.
It consumes the CLI through its npm dependency. There is no parent repository.
The default client cache and configuration directory is `~/.vigie-vuln/`; current
advisories and cached resources use SQLite (`cache.sqlite`). Legacy filesystem cache
archives are not imported into the current format. Some protocol and schema names retain
their historical `fad` prefix; do not infer cache-format compatibility from that prefix.

## Current implementation and audit limits

- Source-tree image discovery and analysis are off by default; opt in with `--images`.
  `vigievuln system scan` inspects OCI images, archives, root filesystems, VM disks,
  collected inventories and publisher SBOMs; `vigievuln system collect` writes the portable
  inventory. Coverage depends on the available content and supported formats.
- The binary codec uses hash lookups and also extracts bounded PE/ELF metadata and Go
  build information where available, including extensionless ELF executables. Metadata
  is evidence, not a guarantee of package identity.
- Gradle lockfiles record resolved versions for the configurations actually locked; the
  inventory can combine compile, runtime, test and tool configurations. Without a lock,
  the static POM walk is not Gradle resolution and may pick wrong versions or miss
  dependencies. See `docs/USAGE.md` and `docs/ARCHITECTURE.md`.
- Without a Python lockfile, requirements and project manifests are parsed best-effort;
  the scanner does not run pip or resolve a complete Python dependency graph.
- CycloneDX exports retain each known version for Maven, npm and PyPI coordinate records;
  an export is limited by the evidence the scan collected.

## Working in this repository

- Install with `npm ci`; run `npm test` and focused fixture tests for changed behavior.
- Ordinary tests use local fixtures and fake providers. Network integration tests are opt-in.
- Code layout: [lib/README.md](lib/README.md). Only command entry points and configuration live at the root of
  `lib/`; code specific to one data source goes in `lib/providers/<name>/`, to one ecosystem in `lib/codecs/<name>/`.
- Register ecosystem parsers as codecs; see [architecture](docs/ARCHITECTURE.md).
- Preserve per-version manifest attribution and source evidence when merging findings.
- Keep dependency discovery, advisory applicability and CVE record enrichment distinct.
- Retain indeterminate verdicts; missing evidence must not become a clean result or a resolved baseline finding.
- A scan with coverage gaps publishes its report marked incomplete (`summary.scanReliable` false, banner, chapter 0).
  It is cancelled only without any inventory or any assessing advisory source, or under `--fail-on-incomplete`
  (`lib/scan/reliability.js`, `publication`).
- Keep source and image findings separate in executive summaries and charts.
- Follow [release instructions](docs/RELEASING.md) for packaging and publication.

[Usage](docs/USAGE.md) · [Images](docs/IMAGES.md) · [Contributing](CONTRIBUTING.md)
