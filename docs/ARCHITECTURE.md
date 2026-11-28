# Architecture

VigieVuln inventories source dependencies and application instances, matches them
against vulnerability evidence, and renders reports. An optional image pipeline
inventories acquired OCI images, archives, root filesystems or publisher SBOMs.
For commands and coverage limitations, see [usage](USAGE.md),
[CMS and frameworks](CMS-FRAMEWORKS.md), and [images](IMAGES.md).

## Module map

[`lib/README.md`](../lib/README.md) is the guide to the code layout: where each command
starts, what each folder holds, where a new module goes.

| Area | Main modules | Responsibility |
| --- | --- | --- |
| CLI | `vigievuln.js`, `lib/cli-*.js`, `lib/options-env.js`, `lib/config.js` | Commands, option resolution, configuration, orchestration, outputs and gates. |
| Ecosystems | `lib/codecs/`, `lib/inventory/dep-record.js` | Discover supported manifests and locks; collect dependency records and registry metadata. |
| Maven and Gradle | `lib/codecs/maven/`, `lib/codecs/gradle/` | Parse POMs and build files; resolve supported management, graph and BOM rules. |
| Data sources | `lib/providers/index.js`, `lib/providers/<name>/` | One folder per source: its requests and everything specific to it (NVD, OSV, CVEProject, EUVD, KEV, EPSS, CERT-FR, GCVE, distribution trackers, CMS publishers, registries). |
| Advisories | `lib/advisories/` | Store native advisory records and match them against packages. |
| Findings | `lib/findings/` | Merge sources, rate, prioritise, enrich, attribute, suppress, gate and compare findings. |
| Applications | `lib/applications/`, `lib/applications/plugins/` | Recognise CMS and framework instances; relate findings to instances and proven owners. |
| Images and systems | `lib/cli-image.js`, `lib/cli-collect.js`, `lib/artifacts/`, `lib/images/`, `lib/system-inventory/` | Acquire artifacts, collect installed components, evaluate advisories and retain coverage. |
| Other evidence | `lib/certs/`, `lib/providers/retire/`, `lib/codecs/binary/`, `lib/providers/hashid/`, `lib/maintenance/`, `lib/inventory/license-policy.js` | Certificates and keys, vendored JavaScript, binaries, end of life, licenses. |
| Reports | `lib/reports/` | Render HTML, Word-compatible HTML, JSON, CycloneDX, CSAF, SARIF and Excel. |
| Scan context | `lib/scan/` | Coverage, reliability and publication policy, diagnostics, source health, provenance. |
| Cache | `lib/cache/` | SQLite storage, resource cache, proxy cache and portable cache archives. |

## Modules loaded by the server

The server repository loads CLI modules by path, `require('vigievuln/lib/<name>')`, about
forty of them (providers, advisory store, cache, NVD, OSV, CVE download, resource cache).
Those paths are a contract. The `exports` map of `package.json` binds each path the server
knows to the module's current file, so a module can move without breaking the server, and
a module with no importer in this repository can still be in use
(`lib/providers/nvd/bulk.js`, `lib/cache/resource/fs-store.js`). After moving, renaming or
removing a module, run

```bash
node scripts/check-server-modules.js ../server
```

which lists the modules the server loads and fails when one no longer resolves.

## Codecs

Each registered codec in `lib/codecs/` identifies supported project files,
collects dependency records and supplies ecosystem-specific behavior. The registry
and interface are in `lib/codecs/index.js` and `lib/codecs/codec.interface.js`.
Add an ecosystem through a codec and fixtures rather than hard-coding it in the
report pipeline. Collection and matching must preserve parse errors and coverage
limits instead of interpreting missing evidence as a clean result.

Supported source inputs include Maven, Gradle, npm, Yarn, pnpm, Composer, Python,
NuGet, Go and Ruby manifests and locks. Exact formats and fallback behavior are
listed in [usage](USAGE.md). Locks, when present, describe only their recorded
scope; they do not establish deployed contents.

Maven resolution walks each module using its supported inherited declarations,
management and dependency POMs. External metadata and some local reactor
relationships may be unavailable; those gaps affect coverage. Gradle records use
Maven package coordinates with `ecosystemType: "gradle"`. The Gradle collector
reads locks, catalogs and supported static build declarations. Without a lock,
POM-based transitive resolution is an approximation and can select versions other
than Gradle's. Without a resolved Python lock, exact supported pins are checked
but pip transitive resolution is not performed.

## The resolved-deps Map

`makeDepRecord()` creates the shared dependency record. The map is normally
keyed by ecosystem and coordinate; independently located embedded or binary
components retain location-specific identities. The main fields include:

- `ecosystem`, `ecosystemType`, `namespace`, `name`, `coordKey`, and `provenance`;
- `version` for a representative value and `versions` for known resolved versions;
- `scope`, `isDev`, `manifestPaths`, and version-specific paths and scopes;
- `via`, `viaPaths`, `depth`, `maskedVersions`, or `occurrences` when supported by
  the evidence and ecosystem.

A finding applies to a specific version. Attribution uses version-specific paths
and relationship evidence rather than assuming that every manifest containing a
coordinate resolves every version. Composer physical occurrences and application
ownership remain distinct where proven. Unknown ownership and unresolved versions
remain explicit; neither is inferred from a package name alone.

## Cleanup pipeline (`lib/codecs/maven/pom.js`)

The extraction workflow can write normalized descriptors to a separate target
and exclude configured private coordinates. It does not modify source files in
place. The output is a representation of parsed evidence, not proof of the
original application's installed or deployed graph. See [usage](USAGE.md).

## Report pipeline

1. **Collect:** codecs and application plugins inventory the selected source
   tree. Optional image acquisition and assessment use the artifact pipeline.
2. **Resolve:** supported Maven, Gradle and other ecosystem metadata provide
   versions and relationships. Missing, ambiguous or unsupported evidence is
   retained as a warning or coverage result.
3. **Match:** CVEProject, OSV, publisher and distribution sources provide
   advisory evidence where enabled and available. Matching uses package and
   version applicability rather than treating an unknown version as affected.
4. **Enrich:** NVD and EUVD provide per-CVE record details; EPSS, KEV, GCVE and
   CERT-FR add their respective context. Enrichment alone does not establish
   package applicability. A single NVD/EUVD record summary reports unavailable
   or stale details without turning an enrichment-only failure into an inventory
   or advisory-discovery gap. Actual discovery and inventory failures remain
   separately visible and can affect completeness gates.
5. **Attribute and assess:** version paths, application ownership and artifact
   evidence are applied; CPE refinement, priority and selected maintenance,
   license, binary and certificate checks add context.
6. **Render and gate:** report builders share the finding model. Triage and
   baseline comparisons preserve suppressed and unassessed states. Gates evaluate
   findings or explicitly requested completeness capabilities.

See [data sources](DATA-SOURCES.md) for source behavior and freshness. A source
outage, incomplete inventory or unassessed range cannot prove a package clean.
A finding identifies affected evidence; it does not establish reachability or
exploitability in a particular deployment.

## Report structure

HTML and findings JSON are the default source-scan outputs. Optional formats
include Word-compatible `.doc`, Excel, CycloneDX SBOM, CSAF VEX and SARIF.
Reports include findings, source context and coverage, plus a `SHA256SUMS` file
unless disabled. Image reports keep project and image summaries distinct.
`--baseline` compares findings with a prior JSON export; incomplete evidence can
leave changes unassessed. [Usage](USAGE.md) describes output and gate flags.

CycloneDX exports known scanned Maven, npm and PyPI versions and associates each
finding with its version. Composer occurrences and image or embedded components
retain their own identities. Exports cannot supply versions or relationships
that collection did not establish.

## Cache and network

The default client cache is `~/.vigie-vuln/cache.sqlite`; the proxy has a separate
cache. `lib/providers/` mediates supported direct and proxy source requests.
Credentials and cache scope depend on the selected workflow; consult
[usage](USAGE.md) before sharing descriptors or archives. `--offline` uses prepared
local data and performs no network requests, but does not guarantee the cache is
complete or current. An advisory snapshot alone does not provide every dependency
POM or image inventory. Cache age and source coverage remain visible in reports.

Image inspection is off by default in source-tree scans; enable `--images` or use
`vigievuln system scan`. Registry access is separate from vulnerability data access.
See [image acquisition and air-gap preparation](IMAGES.md).

Image filesystem collection keeps OS package inventory from dpkg, APK and RPM
separate from application and binary inspection. Supported metadata identifies
the image's own components and libraries or tools recorded in installed metadata,
including descriptors in dependency directories such as `node_modules` or
`vendor`; nesting alone does not exclude them. Installed metadata does not prove
that every package file exists or that the component executes. Go build information
and embedded JARs can provide evidence for components in binaries. Project
dependency declarations are not resolved or downloaded to invent additional
image contents. A publisher-supplied SBOM is a separate, explicit inventory input.
These image rules do not change source-tree scans.

## Testing

Run `npm test` for the offline suite, or `node --test test/<name>.test.js` for a
focused test. Collector and matcher tests use fixtures and injected fetchers;
`test/offline-guarantee.test.js` checks that offline paths do not use the network.
See [contributing](../CONTRIBUTING.md) for development setup.
