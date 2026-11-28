# Native images and Linux binaries

Image analysis inventories container contents and matches the observed components
against vulnerability data. It requires no Docker daemon, external scanner,
package manager or execution of the inspected files. The compiled executable
includes its parsers; the npm installation uses the supported Node runtime.

## Scan project images with `--images` / `-a images`

The usual workflow is to include images in a project scan. Add `--images` or
`-a images` to discover Dockerfile, Containerfile and YAML image references and
inspect eligible registry images alongside the project's dependencies:

```bash
vigievuln scan ./code --images
# Equivalent ecosystem-selection syntax
vigievuln scan ./code -a images
```

Image analysis is **off by default**; configuration can also enable it with
`"images": true`. The report keeps project and image findings, charts and
coverage warnings separate. A Dockerfile `FROM` identifies a build-stage base;
this scan does not build the application's final image.

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

## Collect evidence on a production Linux host

On Alpine x86_64, extract the full `vigievuln-linux-x64-musl-v<VERSION>.tar.gz` archive
and run `./vigievuln` beside its supplied `lib/` directory.
On the audited host, supply a filesystem root and the destination of the inventory.
For a workstation without containers:

```bash
vigievuln system collect / --output /mnt/audit/workstation.json
```

The primary input may also be a local Docker/OCI archive, an OCI layout, an
extracted root, or a standalone VM disk. Use the same command for each input.

```bash
vigievuln system collect ./server.vhdx --output ./server.json
vigievuln system collect ./store.tar --output ./store.json
vigievuln system collect / --images --projects /srv/apps --output /mnt/audit/server.json
```

On a running system the collector never enters kernel or virtual filesystems (procfs,
sysfs, devtmpfs, debugfs, tracefs, cgroup, pstore, configfs…), network and FUSE mounts
(NFS, CIFS, 9p, sshfs…) or the container engine stores: their type is read from
`/proc/self/mountinfo`. It reads regular files only. Leave out anything else with
`--exclude-path`, absolute or relative to the collected root; the option also applies to
`system scan <root>`:

```bash
vigievuln system collect / --exclude-path opt/collection-kit --exclude-path srv/data --output /mnt/audit/server.json
```

A collection running for more than 30 seconds reports its progress on stderr every
30 seconds (elapsed time, files examined, current directory). `system scan` reports the
stage in progress the same way, and records the duration of each stage in
`provenance.stageTimings`.

The CVE chapter starts with **Host system**. It identifies the disk, partition or
archive, lists host interpreters and services with their advisory results, and
shows findings on other system dependencies. Each subsequent section covers one
project, CMS or framework instance, identified
by target and project root. HTML and Word reports show paths from the root of the
inspected filesystem, for example `/var/www/html/composer.lock` or `/usr/local/bin/php`.
Each section shows findings for direct dependencies,
then transitive dependencies, with the paths that establish each occurrence.
Uncertain relationships are labelled explicitly. A project's installed libraries
stay attributable to that project.
The final **Images** section appears when local container inspection was requested
with `--images`, `--docker` or an additional `--image` input.

With `--images`, the collector inspects locally available images referenced in
the project's Dockerfiles and YAML. An additional `--image` can supply an archive
for a declaration. The collector can also export a matching image from a local
Docker Engine. Each additional image has its own ordinary image inventory.
An unresolved or missing reference remains visible and returns exit code 2.

On the auditor machine, `analyse` uses the project report layout, including
the maintenance, licenses, remediation and scan-context chapters. CMS modules,
themes and plugins belong to their CMS instance. A nested module manifest supplies
ownership and version evidence. Its dependencies appear under that module in the
instance report. The collapsed project component inventory lists the affected
occurrences and their advisory IDs. The module inventory lists the extensions
installed in the CMS. **Outdated** compares their installed versions against
identified public catalogues and shows how many could be checked. Each update
identifies the package descriptor when available and the file containing the
observed installed version when they differ. A missing
catalogue record or an unverified identity counts as unchecked.
Collection records Composer ownership evidence and metadata for
certificates and keys in project directories. The JSON contains paths and
fingerprints without key material. Earlier inventories can still be replayed.

Use `analyse server.json --lang fr` for the default assessment, including versions
past active support. Add `--licenses` to assess licenses. Add `--offline` to use only the auditor’s cache
and supplied advisory snapshots. Missing lifecycle data is recorded in coverage.

On a Docker server, add `--docker` to inventory all images in the local Engine
cache, including untagged images. `--docker-socket` selects a local Unix socket
(default `/var/run/docker.sock`). Optionally supply existing Docker save, OCI or
rootfs archives, OCI layouts or extracted directories with `--image`. For example:

```bash
vigievuln system collect / --docker --projects /srv/apps --image /srv/exports/app.tar --output /mnt/audit/server.json
```

The collector reads files locally and does not initialise a user cache, consult
advisory databases, contact a registry or execute an image. Archive and Engine
layer extraction use the system temporary directory, serially per input. Allow space for the expanded filesystem and layer processing. A target with a small tmpfs can select another approved temporary directory with `TMPDIR=/mnt/audit/tmp vigievuln system collect ...`. Normal
completion and handled failures remove temporary files. The JSON is replaced
atomically in the chosen destination directory. The collecting account needs
permission to connect to the local Docker socket. An inaccessible Engine or failed image
acquisition is recorded in the partial inventory and returns exit code 2.

The inventory retains installed package versions, supported binary identities,
paths to package metadata, and lockfile evidence for Composer, npm, pnpm, Yarn,
RubyGems, Poetry, uv, PDM, Pipenv, Gradle and NuGet.
Locked versions are labelled `lockfile`. Dockerfile and YAML declarations keep
their paths and locations. `--projects` narrows declaration discovery within
the root. Matching a local tag is recorded as a candidate. A declaration alone
does not establish which image is running. Virtual system directories and
standard container storage directories are excluded from the host filesystem walk.
Unreadable files, active RPM database journals and unsupported components can
limit coverage.

### Standalone Linux VM disks

The CLI embeds the 7-Zip WebAssembly reader. Tested standalone files include
RAW/IMG, QCOW2, VHD, VHDX, VMDK and VDI with ext4, directly or inside an MBR or
GPT partition table. Each readable partition becomes a separate target. Supply a
self-contained disk. LVM, encrypted volumes, external backing chains, multi-file
VMDK and non-ext filesystems are outside this reader's supported scope. A mixed
disk can produce a partial inventory (exit 2). If no readable partition is
found, collection fails and preserves any existing output.

Decoding uses the system temporary directory. Set `TMPDIR` to a writable
filesystem with sufficient space. The reader accesses raw partitions by offset, stages partitions from wrapped
disks when necessary, extracts regular files, skips links and special files, and limits expansion to 20 GiB cumulatively
or 80% of the initially available space, whichever is smaller. It limits the
reader process to 15 minutes per disk and omits files over 512 MiB with a coverage
warning. A directly readable filesystem root avoids disk extraction.
The distribution includes the reader's notices. [7z-wasm source](https://github.com/use-strict/7z-wasm)

### Auditor-side report

Transfer the JSON to the auditor and run the existing inventory assessment
there. This step consults the auditor's configured sources and writes the reports.

```bash
vigievuln system scan ./server.json --report-output ./server-report
```

Use `--offline` for auditor-side replay with a prepared cache. CMS-specific
advisories use cached snapshots or explicit local feeds such as
`--wordfence-feed <file>` and `--prestashop-advisories <file>`. A missing source
is recorded in coverage. WordPress core file integrity requires file contents
and is outside the scope of inventory replay.

The existing `vigievuln system scan --inventory ./server.json` accepts the same report and offline options.

For a trusted inventory above the default 128 MiB input limit, set
`maxSnapshotBytes` in a JSON file and pass it with `image --limits <file>`
on the auditor's machine.

## Scan a standalone image with `vigievuln system scan`

Use the dedicated command for a Docker/OCI archive, registry reference, root
filesystem or publisher SBOM. It scans the supplied input directly, without
requiring a project scan or `--images`.

```bash
# Docker save, OCI archive, docker export/rootfs tar, OCI layout or rootfs directory
vigievuln system scan ./image.tar --offline
vigievuln system scan ./rootfs --offline

# Native registry HTTP client; no Docker daemon or credential helper
vigievuln system scan alpine:3.20 --registry --platform linux/amd64

# Try the publisher inventory first; fall back to image layers if unusable
vigievuln system scan alpine:3.20 --registry --platform linux/amd64 --prefer-sbom

# An existing publisher document
vigievuln system scan ./publisher.spdx.json --sbom --offline
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

### Associate source declarations

Use `--definitions <directory>` to include Dockerfile, Containerfile and YAML
image declarations in the report and exported inventory:

```bash
vigievuln system scan ./image.tar --offline --definitions ./source
```

A declaration is associated with an image only when it explicitly names an
`@digest` that matches the scanned image manifest or its resolved registry
index. Tags and matching filenames do not prove which content was scanned;
unresolved references remain visible as unbound declarations. A Dockerfile
`FROM` identifies a build-stage base, not the final built image. Locations,
line numbers where available and the original declaration survive inventory
export and offline replay. Without a source directory, the report states that
no source declaration was supplied.

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
vigievuln system scan alpine:3.20 --registry --platform linux/amd64 \
  --export-inventory alpine.inventory.json --report-output online-report
vigievuln cache export image-cache.tar.gz

# Transfer the inventory and cache archive to the disconnected machine
vigievuln cache import image-cache.tar.gz
vigievuln system scan alpine.inventory.json --inventory --offline \
  --report-output offline-report --lang fr
```

The inventory contains components and evidence, not the image files. This permits
later reassessment without transferring the full image. Its SHA-256 checks detect
corruption; they are not a publisher signature. An updated vulnerability cache may
produce new findings for the same inventory.

When a saved image inventory does not establish the current filesystem scope, an
offline scan retains its component observations and reports the scope limitation.
Reacquiring the image online can establish the current inventory.

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
vigievuln system scan ./image.tar --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./client-cache
vigievuln cache export image-cache.tar.gz --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./client-cache
vigievuln cache import image-cache.tar.gz --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./airgap-cache
vigievuln system scan ./image.tar --offline --proxy-cache https://scanner.example \
  --source-profile proxy --cache-dir ./airgap-cache
```

Hosted services use targeted distribution/package/version OSV consultations
instead of requesting prohibited full database archives. The resulting cache
proves coverage for consulted versions only. See the
[measured pathway and image comparisons](BENCHMARK-IMAGES.md).

## Installed components and vulnerability sources

The OS inventory reads dpkg, APK and RPM databases. RPM storage adapters handle
SQLite, NDB and Berkeley DB. Distribution identity comes from `os-release` and
retains its actual release. File ownership links binaries and installed
application metadata to their OS packages, including merged `/usr` aliases.
OS package inventory is separate from the application and binary file walk.

Image filesystem inspection distinguishes the image's own components from
libraries and tools identified by available installed metadata, including
descriptors in `node_modules`, `vendor` or other dependency directories. It reads
metadata and binaries statically; a package listed in installed metadata is not
proof that every file exists or that the package executes at runtime. The scanner
does not resolve dependency graphs or download dependencies declared in project
manifests to infer image contents. Package fragments that do not establish a
package identity are not treated as installed packages. Go build information and
nested JARs can identify components present within a binary or archive. An absent
finding does not establish that every component was identified or assessed.

The CVE chapter groups each image by installation source: OS packages (APT/dpkg,
APK, RPM), global installations (first-level npm global packages, Python,
RubyGems, Composer in recognized shared/user prefixes), applications with their
own root descriptor outside package stores, bundled JavaScript (RetireJS), and
other components/sub-dependencies. Nested npm dependencies remain in the last
group, including those bundled in npm itself. OS file ownership takes precedence.
Unknown/custom prefixes remain in the last group. A shared Python/Ruby environment
does not establish which packages were explicitly requested by the installer.
Classification does not prove execution at runtime.

The Images chapter starts with declared image references. Its component details
and the JSON report omit sub-dependencies without vulnerability findings; the
complete inventory stays in acquisition snapshots for advisory reassessment.
Catalogued interpreters and services, direct application roots and global installs remain visible, while other OS packages
and native binaries are detailed only when an advisory is associated with them.
The total component count continues to describe the full collected inventory.

### Interpreter and service fingerprints

The image details and CVE chapter group catalogued interpreters, runtime engines
and network services separately. The detection table records the path, observed
version, evidence and advisory check. An ELF dependency may reference a shared
library whose file was not observed. The report lists these references, unidentified native files and the
catalogued products without observed evidence. Static contents cannot establish
which process is running or which port is reachable.

Each built-in fingerprint is a JSON file under `data/fingerprints/interpreters/`
or `data/fingerprints/services/`, grouped by family. To add one, register its
literal import in `data/fingerprints/index.js`. Schema version 1 records an ID,
label, category and anchored executable and OS package patterns. Optional fields
describe an ELF banner with version captures, a library name, a structured ELF
reader, a Go main module, PE VERSIONINFO identity fields and an upstream CPE.
These rules use product evidence independently of executable hashes. An exact
filename alone is shown as a candidate with unknown version.

The ELF readers recognize build banners, CPython's exported `Py_Version`,
supported constant-return WebKitGTK/JavaScriptCore version APIs, Node's inspector
and release metadata, and Bun standalone module graphs (appended and ELF section
formats). A Bun application's own version is independent of its embedded engine.
PE readers use matching product and publisher/original-filename fields from the
same version resource. Java and Tcl installations can also provide prefix-local release metadata.
The PE readers also inspect directly embedded PE files in ordinary,
uncompressed RCDATA, one level deep. Custom wrappers, stripped builds, packed
resources and other architectures can leave the exact runtime unknown.

For OS packages the scanner uses distribution advisories. For identified upstream
executables with a supported version and CPE it queries NVD by product/version,
then checks the vulnerable CPE and version constraints. Platform constraints it
cannot establish remain indeterminate. Offline scans replay prior consultations.
A proxy needs support for the typed `nvd/image-product` operation. A missing
consultation, unsupported fingerprint or disabled source cannot establish absence
of CVEs. Reacquire inventories made before this collector to obtain binary evidence.

### Optional RetireJS image scan

```bash
vigievuln scan ./code --images --image-retire
vigievuln system scan nginx:stable-alpine --registry --image-retire
vigievuln system scan ./rootfs --image-retire --offline
```

`--image-retire` is off by default and independent of the source-tree RetireJS
option. It inspects regular `.js`, `.mjs` and `.cjs` files without executing them
or following symlinks. Package stores (`node_modules`, `vendor`, Python stores,
package caches, `usr/share/nodejs`, etc.) are excluded; deployed `dist` and `build`
directories are included. Files attributed to installed OS packages are excluded
to avoid overriding distribution backport assessments. The default limits are 16 MiB per file, 128 MiB of JS
and 10,000 files per image; limits or unreadable files produce incomplete coverage.
The image `--limits` file accepts `maxImageJsFileBytes`, `maxImageJsBytes` and
`maxImageJsFiles`. The scan uses RetireJS filename/content/hash signatures; it
does not unpack arbitrary JavaScript bundles or infer dependency graphs.

Offline use requires cached signatures and image contents or an inventory acquired
with this option. Saved JS identities are reassessed against the available
signatures, not saved vulnerability verdicts. Online image acquisition with this
option re-inspects contents, including when an earlier inventory exists, and takes
precedence over `--prefer-sbom`. An explicit SBOM or an older snapshot cannot supply
the missing JS scan and is reported as incomplete when this option is requested.

HTML stores identical CVE detail panels once and restores their copies locally in
the browser for viewing, copying and printing. Word remains fully expanded.
`findings.json` uses compact JSON whitespace and retains the existing schema and
all vulnerability evidence; format it with `jq . findings.json` when needed.

The image filesystem policy does not change source-tree scans. An explicitly
supplied publisher SBOM is a separate inventory input, rather than a filesystem
walk; its listed components and any limitations remain visible as SBOM evidence.

OS packages are assessed with distribution-specific OSV data and Debian, RPM or
APK version ordering. Distribution patches are not judged solely by the upstream
version number. An unknown distribution, repository scope, source version or
comparison remains indeterminate. Collecting RPM packages does not itself prove
that suitable advisories exist for that distribution.

Distribution advisories are built in for Debian, Ubuntu, Alpine, AlmaLinux and Rocky
Linux. Another distribution (RHEL/UBI, Amazon Linux, Fedora, SUSE, Wolfi…) needs
`--advisory-config`; without it its packages are inventoried and reported as not
assessed. Details that decide a verdict:

- **End-of-life release.** Its security tracker is frozen. The report says so and is
  marked incomplete: vulnerabilities published after the end-of-life date are not
  recorded for its packages.
- **Debian and Ubuntu kernels.** A signed kernel image (`linux-image-<version>`,
  source `linux-signed-…`) is assessed under the kernel source it was built from
  (`linux`), at the image's own version.
- **RPM epochs.** A package built at its source's own version-release shares the source
  epoch. A subpackage carrying its own version leaves the source version unknown.
- **RPM module streams.** An erratum built for a module stream (`php:7.4`) applies to
  packages of that stream, identified by their modularity label. It is not applied to
  a non-modular package of the same name or to another stream.
- **Distroless images.** The dpkg `status.d/` directory is read like `status`.

Installed application and binary collectors inspect supported metadata without
executing the inspected code. The scanner also consults native CVEProject and GCVE records
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
sources; no match in incomplete data is not a clean verdict.
`--fail-on-incomplete sources` can enforce a source coverage
requirement; ordinary vulnerability severity gates do not fail solely because a
source is incomplete.

On a direct online scan, preparing a missing or expired CVEProject source can
fetch its full cvelistV5 archive (hundreds of MB compressed and substantial
unpacked temporary storage) and index native records. GCVE refresh verifies its
signed directory and downloads allowed GNA feeds. This preparation is shared
across the image targets in one scan.
A shared or hosted proxy may offer only targeted native operations and cannot be
assumed to provide a complete distribution corpus; the report marks this
limitation. `--offline` reads only existing caches and never refreshes sources.
The `eu` and `us` source profiles exclude sources outside their region, and a
source excluded by a profile cannot be used through a different source name.
Prepare the auditor cache against the same inventory before offline replay, including the distribution release and language ecosystems found on the target. A Debian snapshot cannot cover Alpine APK packages. See the cache preparation example above.

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
vigievuln system scan --sync-advisories --distribution debian:12
vigievuln system scan --import-advisories ./advisories.zip \
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

With image analysis enabled, source-tree scans discover Dockerfile and YAML image
references. Declarations alone do not establish the contents of the final build;
unacquired images remain visible as incomplete coverage in HTML/Word and JSON.

## Reports and CI

HTML and JSON are generated by default. `-r html,json,doc,xlsx,sbom,csaf,sarif`
selects all report formats. Artifact identity, platform, inventory origin and
coverage are included in HTML/Word and JSON; component locations and identities
are retained in machine-readable finding exports. Inventory totals describe the
acquired inventory; system components and binaries are detailed when associated
with an advisory or CVE. Image warnings are grouped separately from project
warnings; CVE-record enrichment has one shared summary.

```bash
vigievuln system scan ./image.tar --offline --lang fr \
  --fail-on high --fail-on-incomplete inventory,advisories,sources
```

Warnings identify failed operations or applicable components and data that could not be assessed. A source deliberately excluded by configuration, a CVE-only lookup with no CVE identifier, or reuse of a prepared offline snapshot is not an alert. These observations remain in scan context and do not fail coverage gates. Source-wide corpus limitations remain distinct from whether a consultation ran. Unavailable inventory or advisory discovery can affect coverage gates; NVD/EUVD per-CVE enrichment failures are summarized separately without marking inventory incomplete. An archive covered by its verified, assessed OS package does not also require a Maven identity; corrupt or unowned archives remain gaps.

Exit `0` means no selected gate failed, `1` means a finding gate failed or a
known-malicious package was found, and `2` means the scan was cancelled or the command
failed. Without the strict coverage gate, an incomplete scan exits `0` and publishes its
reports marked incomplete (banner, chapter 0, `summary.scanReliable: false`). It is
cancelled only when it has no inventory or when no advisory source assessed any package.
`--fail-on kev` also requires the advisory and relevant KEV coverage needed to
make that decision. `--no-report` suppresses report files, not assessment or gates.

## Configuration and extension contracts

`--registry-auth credentials.json` accepts `username`, `password`, `token` and
optional trusted `authOrigins`. Environment alternatives are
`VIGIEVULN_REGISTRY_USER`, `VIGIEVULN_REGISTRY_PASSWORD` and
`VIGIEVULN_REGISTRY_TOKEN`. Set `registry` in the file, or `VIGIEVULN_REGISTRY_HOST`, to the
host the credentials belong to (`registry.example.com`, `ghcr.io`, `docker.io`): they are then
sent to that registry only. Without it they are offered to whichever registry the scanned
reference names, so bind them wherever public images are scanned too.
Credentials are not obtained through Docker helpers.
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
the subsystem tests for contracts, failure states and extension examples.

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

AlmaLinux and Rocky Linux packages are assessed against the distribution's published
errata: a vulnerability the distribution has not fixed yet has no erratum and is not
listed, which the report states. Debian, Ubuntu and Alpine trackers also record unfixed
vulnerabilities. An erratum can cite a CVE identifier that is reserved but not published;
when NVD answers that it holds no such record, the report says so without treating it
as a coverage gap.

A Go binary whose `(devel)` main module cannot be given a verified version is listed in
the scan notices: advisories for the application itself are then not assessed, while its
embedded module dependencies and standard library are.

Go binaries with a `(devel)` main module acquire a version when the module proxy
records that a proposed version was cut from the exact revision embedded in the
binary, itself built from an unmodified checkout. The version is proposed by the
image's declared source and version labels (`1.23.8` and `v1.23.8` are the same
version) or by the build's own linker flag (`-ldflags -X main.Version=1.23.8`), which
also covers a module served from a vanity path (`code.gitea.io/gitea`) and a binary
on a plain filesystem. Neither a label nor a linker flag binds a version without that
proof. Only the necessary standard OCI labels are retained. Resolution is cached and exportable; offline assessment uses
that evidence without executing the binary or contacting a service. Conflicting
metadata does not produce an identity. A cached proof reused after a failed
refresh is explicitly marked stale.

All these snapshots and identity proofs use the regular SQLite cache archive.
They work through the fleet and hosted resource operations as well as direct
HTTP. Additional evidence remains separate from confirmed CVE counters, and
source-specific coverage is considered when comparing scan deltas.

The executive summary ranks vulnerable images separately from project dependencies,
with up to three critical CVEs per image. Project and image charts use separate rows;
each row appears only when its inventory is present. NVD/EUVD record availability
and update failures share one enrichment summary without changing inventory coverage.

### Mutable image tags

Source scans with `--images` and registry image scans warn about references without a digest, including `latest`, `stable-alpine`, numeric tags such as `1.30.7`, and an omitted tag. Pin the declaration as `nginx:1.30.7@sha256:<digest>` to keep the same image content between scanning, building and deployment. A digest resolved and recorded by the scanner does not pin the original declaration. This warning does not mean image analysis failed.
