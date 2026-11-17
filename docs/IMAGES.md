# Native images and Linux binaries

`vigievuln image` inventories Docker/OCI images, root filesystems and publisher
SBOMs, then matches the observed components against vulnerability data. It does
not require Docker, Trivy, Grype, a package manager or execution of the inspected
files. The compiled executable includes its parsers; the npm installation uses
the supported Node runtime.

## Inputs and first scan

```bash
# Docker save, OCI archive, docker export/rootfs tar, OCI layout or rootfs directory
vigievuln image ./image.tar --offline
vigievuln image ./rootfs --offline

# Native registry HTTP client; no Docker daemon or credential helper
vigievuln image alpine:3.20 --registry --platform linux/amd64

# Try the publisher inventory first; fall back to image layers if unusable
vigievuln image alpine:3.20 --registry --platform linux/amd64 --prefer-sbom

# An existing publisher document
vigievuln image ./publisher.spdx.json --sbom --offline
```

Without `--platform`, all image platforms available in the input are inspected
as separate targets. A partial set of publisher SBOMs does not silently drop the
other platforms. Registry references are resolved to immutable digests; the
resolution time is retained. Pin `name@sha256:…` when reproducing an exact image.

Local archives support tar, gzip and zstd, ordered layers, whiteouts and opaque
directories. OCI descriptor digests and declared uncompressed layer digests are
checked. Missing integrity metadata is reported. Archive traversal, unsafe links
and invalid descriptors fail the acquisition. Devices and FIFOs are never created.
`docker export` archives have no image-layer history and may omit mounted volumes;
VV only assesses the supplied filesystem.

## Source declarations

Use `--definitions <directory>` to include Dockerfile, Containerfile and YAML
image declarations in the report and exported inventory:

```bash
vigievuln image ./image.tar --offline --definitions ./source
```

A declaration is associated with an image only when it explicitly names an
`@digest` that matches the scanned image manifest or its resolved registry
index. Tags and matching filenames do not prove which content was scanned;
unresolved references remain visible as unbound declarations. A Dockerfile
`FROM` identifies a build-stage base, not the final built image. Locations,
line numbers where available and the original declaration survive inventory
export and offline replay. Without a source directory, the report states that
no source declaration was supplied.

Image analysis in source-tree scans is **off by default**. Enable it with
`--images`, `-a images`, or `"images": true` in configuration. The explicit
`vigievuln image` command still scans its supplied input.

An enabled source-tree scan resolves an eligible registry tag while acquiring the
image; the report links the declaration to the digest resolved during that scan.
Repeated declarations are grouped while their local file locations remain visible.
`--no-images` (or `-d images`) disables source-image discovery and acquisition.
Source scans use the declared platform, otherwise `--image-platform` (default
`linux/amd64`); the selected platform travels with the anonymized descriptor.

For an air-gapped source scan, `--images --export-anonymized` transfers eligible image
references and requested platforms alongside dependency coordinates, not Dockerfiles,
build contexts, paths or credentials. Review the descriptor: registry hostnames and
repository names may be private. `vigievuln cache prepare <descriptor> --images --output <archive>`
acquires eligible registry images online and prepares their cache for the subsequent
offline source scan (also enable `--images` there). Dockerfiles remain in the isolated environment and their images
cannot be built during online preparation. An absent or invalid required inventory
prevents a successful image-cache preparation; other incomplete advisory coverage is
reported separately.

## Image update suggestions

For an image with a usable registry reference and known platform, VV can list
registry tags and suggest the highest comparable patch tag on the same numeric
major/minor branch and exact variant. It accepts branch tags such as `1.24`,
full patch tags such as `1.24.0`, and a tag followed by an immutable digest.
It does not order arbitrary tags, infer a variant, or cross a branch boundary.
VV verifies the candidate's platform using its manifest and image configuration,
without downloading its layers. A matching mutable tag with a different platform
manifest digest is identified as a rebuilt tag. A newer tag or rebuilt image is
an update candidate; it does **not** prove that any particular CVE is fixed.

The report includes the registry observation time and candidate digest when
available. A normal registry acquisition retains its original reference and
resolved digest. For an image acquired from an OCI layout or archive, an
inventory can also record `metadata.registryReference` with `reference`,
`indexDigest`, `platformDigest` and `verifiedAt`. VV uses that reference only
when its platform digest exactly matches the inventoried image digest or its
resolved acquisition digest. This separate binding does not change the recorded
acquisition method; it must come from an actual registry verification, not a
matching filename or tag alone.

The tag list and platform-manifest observations are cached with their collection
time for offline replay. Offline suggestions describe that saved observation;
they cannot establish the registry's current state. When a reference, comparable
tag, platform proof or cached observation is unavailable, the report advises
updating the image or affected package or binary without inventing a version.

## Advisory reuse and proxy limits

Individual advisory records whose last source modification is at least 365 days
old are reused by default. `--no-reuse-stable-advisories` restores normal cache
lifetimes; `--reuse-stable-advisories` explicitly enables reuse. Set a different threshold with
`--stable-advisory-age-days <days>` (1–36500). Missing or future modification
dates do not qualify. Package consultations and catalogues keep their own refresh
policies, and KEV and EPSS are refreshed independently. Reuse does not mean that
an advisory or its risk can never change.

`--force-update` overrides stable reuse and requests online revalidation; it
cannot be combined with `--offline`. Offline scans use available saved evidence
without network access. `--proxy-rate-limit-wait-ms <milliseconds>` controls how
long each request may wait for proxy retries (default 45000 ms of cumulative
retry delays per request, excluding ordinary scanning). Cooldowns are coordinated
across concurrent requests; retry allowances remain independent.

Registry image inventories are persisted in the local SQLite cache and included
in prepared air-gap archives. Online scans re-resolve a mutable tag's manifest:
when its digest and requested platform are unchanged, the saved content inventory
is reused without downloading layers or extracting the image again. A cached
immutable digest needs no registry check. Changed digests, invalid inventories,
and `--force-update` rebuild the inventory. Publisher SBOMs are checked separately
because they can change independently of the image. Vulnerability assessment is
rerun using the available advisory data; the inventory cache does not freeze CVEs.
Image layers and extracted files remain temporary and are removed after collection.

## Prepare online, assess offline

Use the same default local cache for the scan and cache export:

```bash
# Connected machine: inventory exact content and prepare vulnerability data
vigievuln image alpine:3.20 --registry --platform linux/amd64 \
  --export-inventory alpine.inventory.json --report-output online-report
vigievuln cache export image-cache.tar.gz

# Transfer the inventory and cache archive to the disconnected machine
vigievuln cache import image-cache.tar.gz
vigievuln image alpine.inventory.json --inventory --offline \
  --report-output offline-report --lang fr
```

The inventory contains components and evidence, not the image files. This permits
later reassessment without transferring the full image. Its SHA-256 checks detect
corruption; they are not a publisher signature. An updated vulnerability cache may
produce new findings for the same inventory.

Alternatively, transfer the Docker/OCI archive and inspect it directly offline.
An offline registry request uses only a previously cached inventory for that exact
reference and selection; it cannot establish what a mutable tag currently means.
Missing cached data produces coverage notices, not a clean verdict.

`--cache-dir <directory>` selects a separate cache for image operations and
`cache export/import`. Use the same selection for preparing and exporting data.

An inventory collected offline can also be used to prepare the cache online:

```bash
vigievuln cache prepare alpine.inventory.json --output image-cache.tar.gz
```

Preparation exports available data and reports any incomplete coverage. Add
`--fail-on-incomplete advisories,sources` to enforce a stricter result; the archive
still retains the successfully prepared data.

### Fleet and servers

`image` loads the same configuration layers and source profiles as source scans.
Use `--proxy-cache <url>` and, when required, `--proxy-cache-token`; the official
service is selectable with `--vigievuln-proxy`. Explicit HTTP consent is required
for an insecure service (`--allow-insecure-http`). Advisory requests use that
proxy only, with caches isolated by proxy origin; direct cache data is not silently
treated as proxy-confirmed evidence. The explicit registry acquisition remains a
separate access to the OCI registry. `--proxy` configures a forward network proxy.

```bash
vigievuln image ./image.tar --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./client-cache
vigievuln cache export image-cache.tar.gz --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./client-cache
vigievuln cache import image-cache.tar.gz --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./airgap-cache
vigievuln image ./image.tar --offline --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./airgap-cache
```

Hosted services use targeted distribution/package/version OSV consultations
instead of requesting prohibited full database archives. The resulting cache
proves coverage for consulted versions only. Server installations need the updated
CLI library for these distribution scopes; development tests do not upgrade a
deployed server. See the [measured pathway and image comparisons](BENCHMARK-IMAGES.md).

## Installed components and vulnerability sources

The OS inventory reads dpkg, APK and RPM databases. RPM storage adapters handle
SQLite, NDB and Berkeley DB. Distribution identity comes from `os-release` and
retains its actual release. File ownership links binaries and installed
application metadata to their OS packages, including merged `/usr` aliases.

OS packages are assessed with distribution-specific OSV data and Debian, RPM or
APK version ordering. Distribution patches are not judged solely by the upstream
version number. An unknown distribution, repository scope, source version or
comparison remains indeterminate. Collecting RPM packages does not itself prove
that suitable advisories exist for that distribution.

Installed application collectors cover npm, Python dist/egg metadata, Composer,
Ruby gem specifications, .NET dependency metadata, embedded JARs and Go buildinfo.
They inspect installation directories such as `node_modules` and `vendor` without
executing their code. The scanner also consults native CVEProject and GCVE records
in the shared SQLite advisory store. This matching runs independently of OSV and
NVD: a verified native package/version match can produce a finding when those
sources are disabled or unavailable. The source name remains attached to the
finding. The native matcher requires an explicit package identity and a version
rule it can evaluate; unsupported ranges, conflicting source statements and
missing evidence remain indeterminate. A product name alone is not a package
identity. For distribution packages, an explicit PURL must also establish the
package-manager type, distribution and exact release, plus source or binary
architecture; source package version and architecture must be known where needed.
No advisory is applied merely because package names happen to match.

A complete native source corpus is not implied by consulting local records.
Coverage records and notices distinguish missing, stale, partial and failed
sources; no match in incomplete data is not a clean verdict. Legacy GCVE index
coverage counters can understate package identities recognized by the newer
native matcher. `--fail-on-incomplete sources` can enforce a source coverage
requirement; ordinary vulnerability severity gates do not fail solely because a
source is incomplete.

On a direct online scan, preparing a missing or expired CVEProject source can
fetch its full cvelistV5 archive (hundreds of MB compressed and substantial
unpacked temporary storage) and index native records. GCVE refresh verifies its
signed directory and downloads allowed GNA feeds. This preparation is shared
across the image targets in one scan; the matcher walks older native records
once to include package identities that earlier cache versions did not index.
A shared or hosted proxy may offer only targeted native operations and cannot be
assumed to provide a complete distribution corpus; the report marks this
limitation. `--offline` reads only existing caches and never refreshes sources.
The `eu` and `us` source profiles exclude sources outside their region, and a
source excluded by a profile cannot be used through a different source name.
Prepare and transfer caches ahead of an air-gapped scan; missing data is reported.

EUVD and CERT-FR supply contextual information for identifiers they actually
cite. Their identifier-level references, descriptions or scores alone do not
prove an installed package/version is affected and are not used as independent
package detectors. The separate GCVE native matcher can detect findings only when
its own record provides the required explicit package and version evidence.

NVD, KEV, EPSS, EUVD and CERT-FR enrich findings by default; derived GCVE aliases are also retained separately from native GCVE evidence. `--enrich kev,epss` selects only
KEV and EPSS; `--enrich none` disables enrichment. NVD enrichment does not replace the OS
distribution's vulnerability verdict. EUVD detail retrieval runs even when NVD metadata is present; each CVE retains its own source evidence. Only missing display metadata is filled, and a score is never combined with another source's CVSS vector. Confirmed EUVD details and CERT-FR lookups are cached for offline replay. Missing offline enrichment or failed detail retrieval remains visible.

Explicit OS data preparation/import is also available:

```bash
vigievuln image --sync-advisories --distribution debian:12
vigievuln image --import-advisories ./advisories.zip \
  --distribution debian:12 --snapshot-complete --offline
```

Import accepts OSV JSON, JSONL or ZIP. Only use `--snapshot-complete` for a complete
dataset covering the stated release: a few selected CVEs cannot establish absence
of other vulnerabilities. A partial import cannot silently replace a complete
snapshot.

When `os-release` cannot establish the precise advisory scope, supply a JSON
configuration through `--advisory-config`. For example, a RHEL EUS repository
scope must be selected from the actual image's product/repository evidence:

```json
{
  "distribution": { "id": "rhel", "versionId": "9.6" },
  "base": "Red Hat",
  "ecosystem": "Red Hat:rhel_eus:9.6::appstream",
  "versionScheme": "rpm"
}
```

This example covers the specified repository only; it is not a universal RHEL
configuration. An optional `sourceUrl` points to a compatible dataset mirror.

## Publisher SBOMs and free data

VV can discover OCI referrers and BuildKit SBOM attestations, and read SPDX 2 or
CycloneDX JSON, including supported in-toto/DSSE envelopes. It verifies available
subject/digest bindings. Publisher signature verification is not implemented:
the report labels that evidence and retains incomplete inventory coverage.
`--expected-digest sha256:…` checks a locally supplied document's image subject.

System source-package names and versions must also be available for the current
distribution assessor. Missing source identity causes `--prefer-sbom` to fall
back to image layers. A direct `--sbom` import remains possible, with explicit
incomplete advisory coverage rather than inferred source identities.

There is no assumed universal image-name-to-CVE database. Registry metadata gives
the exact image and possibly its inventory; OSV and distribution feeds provide
package vulnerability records. Availability varies by publisher and image.

- [BuildKit attestations](https://docs.docker.com/build/metadata/attestations/)
  can be read without downloading the image layers when the publisher includes them.
- [Chainguard's public directory](https://www.chainguard.dev/docs/get-started/onboard-your-teams)
  exposes image metadata and SBOMs; registry access depends on the particular image.
- [OSV downloadable data](https://google.github.io/osv.dev/data/) and
  [Ubuntu OSV publication](https://documentation.ubuntu.com/security/security-updates/osv/)
  support local preparation of vulnerability information.

Reading an existing publisher inventory does not require installing the software
that generated it.

## Linux binaries and evidence limits

ELF detection uses file signatures, including executables with no extension.
Bounded ELF readers cover 32/64-bit layouts, both byte orders, interpreter,
dynamic dependencies, SONAME and GNU build ID. Go buildinfo contributes concrete
module versions, replacements and supported stable toolchain versions.

A SONAME or build ID is not a software version. Arbitrary stripped or statically
linked C/C++ binaries cannot always be attributed to exact packages from their
bytes. Such binaries remain inventoried with incomplete advisory coverage.
Installed-package metadata and publisher SBOMs are additional evidence, not proof
that every embedded component has been identified.

Source-tree scans also discover Dockerfile and YAML image references. These
references do not trigger automatic image downloads or establish the contents of
the final build. HTML/Word and JSON expose the declaration-only coverage warning.

## Reports and CI

HTML and JSON are generated by default. `-r html,json,doc,xlsx,sbom,csaf,sarif`
selects all report formats. Artifact identity, platform, inventory origin and
coverage are included in HTML/Word and JSON; component locations and identities
are retained in machine-readable finding exports. The artifact section contains
the component inventory, including components without findings.

```bash
vigievuln image ./image.tar --offline --lang fr \
  --fail-on high --fail-on-incomplete inventory,advisories,sources
```

Warnings identify failed operations or applicable components/data that could not be assessed. A source deliberately excluded by configuration, a CVE-only lookup with no CVE identifier, or reuse of a prepared offline snapshot is not an alert. These observations remain in scan context and do not fail coverage gates. Source-wide corpus limitations remain visible separately from whether the requested consultation ran. A provider-marked stale response, a failed refresh, unavailable required data or an unevaluable component still produces an alert. An archive covered by its verified, assessed OS package does not also require a Maven identity; corrupt or unowned archives remain gaps.

Exit `0` means no selected gate failed, `1` means a finding gate failed, and `2`
means required coverage is incomplete or the command failed. Without the strict
coverage gate, an incomplete scan may exit `0` while still displaying warnings.
`--fail-on kev` also requires the advisory and relevant KEV coverage needed to
make that decision. `--no-report` suppresses report files, not assessment or gates.

## Configuration and extension contracts

`--registry-auth credentials.json` accepts `username`, `password`, `token` and
optional trusted `authOrigins`. Environment alternatives are
`VIGIEVULN_REGISTRY_USER`, `VIGIEVULN_REGISTRY_PASSWORD` and
`VIGIEVULN_REGISTRY_TOKEN`. Credentials are not obtained through Docker helpers.
`--insecure` explicitly permits HTTP registries.

Resource policies are configurable through `--limits policy.json`, for example:

```json
{
  "artifactLimits": {
    "maxBytes": 21474836480,
    "maxFileBytes": 8589934592,
    "maxEntries": 1000000,
    "maxMetadataBytes": 16777216,
    "maxDepth": 256
  },
  "registryLimits": {
    "maxTagPages": 100,
    "maxTags": 100000
  },
  "imageUpdateTtlMs": 14400000,
  "maxSystemMetadataBytes": 67108864,
  "maxSnapshotBytes": 134217728
}
```

Limit exhaustion is an explicit error or incomplete collector result. These
limits control resources rather than silently truncating the inventory.
The image update TTL is a positive integer in milliseconds; tag pagination and
tag-count bounds are positive integers. A registry lookup that reaches a bound
does not establish the newest tag.

The JavaScript API exposes independent extension points:

| Subsystem | Extension |
| --- | --- |
| Artifact sources | `openArtifact(input, {sources})`; adapters implement `probe/open`, return targets and cleanup |
| Compression and integrity | `compressions` (`probe/create`) and `digestAlgorithms` |
| OS inventory | `collectors`; RPM `rpmStorageAdapters` |
| Installed applications | `handlers` and `archiveCollectors` |
| Binary metadata | `lib/codecs/binary/metadata.js` extractor registry |
| Publisher inventory | `purlAdapters` and `distributionAdapters` |
| OS advisory scope | `adapters` with `resolveScope`, including version comparison |
| Risk enrichment | `enrichmentAdapters` and `europeanAdapters` with `id/run` |
| Native source preparation | `nativeSourceAdapters` with explicit source coverage; package matching requires typed native records |
| Declared image references | `discoverImageReferences(root, {extractors})` |

Format constants and distribution scope mappings live in their adapters. The
orchestrator does not identify software from a catalogue of binary names. See
[the development plan](PLAN-native-images-linux.md) and the subsystem tests for
contracts, failure states and extension examples.

## Independent distribution and vendor sources

The image assessment also consults independent source adapters, even when OSV is
excluded. `--no-distro-advisories` excludes this group explicitly; regional source
profiles exclude operators whose region is not established. Each source retains
its own version semantics, consultation status and evidence.

For a retired Debian release with an exact codename, VV can prepare a pinned
historical tracker snapshot and assess release-specific CVE/DSA/DLA fixes. It does
not apply unstable-release fixes to stable packages. See
[historical Debian scope and cache preparation](HISTORICAL-DEBIAN.md). A successful
historical consultation does not cover advisories published after the cutoff.

Alpine tracker candidates are shown as additional evidence when their repository
or installed-version bounds do not establish an affected verdict. NGINX vendor
ranges apply only to coherently declared vendor packages; generic distro builds
are not matched against upstream ranges because distro backports differ. Package
signatures and runtime configuration are not inferred from these declarations.

Go binaries with a `(devel)` main module can acquire a version when embedded clean
VCS metadata, the image's declared source/version and the module proxy record
agree on the exact revision and repository. Only the necessary standard OCI
labels are retained. Resolution is cached and exportable; offline assessment uses
that evidence without executing the binary or contacting a service. Conflicting
metadata does not produce an identity. A cached proof reused after a failed
refresh is explicitly marked stale.

All these snapshots and identity proofs use the regular SQLite cache archive.
They work through the fleet and hosted resource operations as well as direct
HTTP. Additional evidence remains separate from confirmed CVE counters, and
source-specific coverage is considered when comparing scan deltas.
