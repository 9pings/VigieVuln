# Release notes — VigieVuln

## [1.3.5] — 2026-11-25

- Group system-scan advisories by project or CMS instance, with direct and transitive findings and their source paths.
- Keep CMS modules and themes under their instance. Group extension advisories by owner, give private extensions their own dependency breakdown, and collapse component inventories by default.
- Give the host its own inventory and findings for interpreters, services and system dependencies. Show the container images chapter when local image inspection was requested.

- Recognise Ghost and Redmine through the shared application plugins, read multi-document pnpm lockfiles, and attribute direct, indirect and development dependencies to the owning application.
- Report unique advisory identifiers alongside active occurrences, show distribution urgency beside CVSS, and distinguish security maintenance from end of life. Supply verified remediation versions for RubyGems, PyPI and stable Composer releases where the advisory establishes a safe boundary.
- Compare upstream language advisories for distribution-owned components and retain uncertain downstream applicability with its evidence. Identify the PrestaShop Docker installation template separately from the deployed tree.

- Run system work with `vigievuln system collect` and `vigievuln system scan`; they replace the `collect`, `analyse` and `image` commands. Scan a project with `vigievuln scan <path>`; the `-s`, `--src` and `--source` flags are rejected.
- Publish the reports of a scan with coverage gaps, marked incomplete: a banner and chapter 0 list each gap, `summary.scanReliable` is `false`, and the terminal names the checks that did not complete. A scan is cancelled only without any inventory or any assessing advisory source. `--fail-on-incomplete` restores cancellation for the listed capabilities.
- Scan images and systems that contain systemd: backslashes in file names are accepted on POSIX hosts. Clamp symbolic links that climb above the root, keep a symlink target when an opaque whiteout replaces the link, and read the dpkg `status.d` directory of distroless images.
- Treat the members of pnpm, npm and Yarn workspaces as covered by the root lockfile, and stop warning about manifests that declare no dependency. Report a Maven type or classifier variant only when it resolves to another version, and name the coordinates.
- Read every OSV severity entry, so a CVSS v4 vector listed first no longer hides a scorable v3 vector or the distribution rating. Take severity, score and vector from one source when merging, the highest rating first. Honour OSV `versions` lists beside ranges for system packages and Composer pre-release rules for Drupal advisories.
- Assess signed Debian and Ubuntu kernel images under the `linux` source. Match RPM errata for packages with an epoch, and apply a module-stream erratum only to packages of that stream. Version a Go application built from a checkout from its own linker flag (`-X main.Version=…`) or an unprefixed version label, once the Go module proxy records the same revision: the 80 advisories of Gitea 1.23.8 reported by other scanners are now found. Name Go applications whose main module still has no verifiable version.
- Record each package's CVEProject consultation in a project cache archive, so an air-gapped scan of a prepared project is no longer reported as lacking a second advisory source. Keep `cache prepare` free of finding gates.
- Assess WordPress plugins and themes by default, under their header or directory slug, and read plugin headers as WordPress does (Akismet was not inventoried). List private CMS extensions, including those the public catalogue does not know, with the private packages of the other ecosystems instead of marking the report incomplete.
- Consult the publisher advisories of a detected Drupal, PrestaShop, TYPO3 or SPIP installation in every online scan; the `--…-advisories-live` options are no longer needed.
- Let `--fail-on-incomplete` pass on a complete project that contains no CMS application. Stop warning about Composer, PyPI and NuGet manifests that declare no dependency.
- Report a distribution CVE once instead of once per advisory lane (`DEBIAN-CVE-x` and `CVE-x`), and fold a DSA or DLA announcement into the CVEs it covers. Detail an advisory once for all the packages built from one source package, naming the others in its row, and keep full detail for the 100 highest-priority advisories of each source or component; the others are counted in the HTML report and kept as compact entries in the JSON, SBOM, SARIF and CSAF exports. On a Debian 12 system with a kernel package the HTML report goes from 195 MB to 10 MB and `findings.json` from 278 MB to 39 MB.
- Read large batches of CVE records from the NVD mirror first, even with an API key, and request ENISA EUVD records only for detailed findings and CVEs still lacking a rating or a description: an online scan of a system with a kernel package goes from 92 minutes to 8 with an empty cache. Record the duration of each system-scan stage and report a stage or a collection that runs for more than 30 seconds on stderr.
- Read the source package and the epoch a CycloneDX or SPDX producer declares for a system package (package URL `upstream` and `epoch` qualifiers, VigieVuln, Trivy and Syft properties): a scanned SBOM of an Alpine image reported nothing, and a Trivy SBOM of Debian 12 now gives the same 242 findings as the image. Keep a distribution source that returns several hundred thousand assessments on a large host instead of losing it to a stack overflow.
- On AlmaLinux and Rocky Linux: no longer count an imported RPM signing key (`gpg-pubkey`) as a package without advisory coverage, state in the report that packages are assessed against published errata only, and report a CVE identifier that the record sources definitively do not hold as not published yet instead of marking the scan incomplete.
- Leave kernel, virtual, network and FUSE filesystems out of a live system collection, and add `--exclude-path` to `system collect` and `system scan`.
- Bind registry credentials to one host with `registry` in the `--registry-auth` file or `VIGIEVULN_REGISTRY_HOST`; bound credentials are never sent to another registry.
- Do not apply a malicious-package advisory to a same-named dependency that the lockfile resolves from a Git forge or a local path.
- Fail a project scan on a known-malicious package without `--fail-on`, as system scans do. Keep `cache import --force` a merge unless `--replace` is given. Warn that the advisory tracker of an end-of-life distribution is frozen.

## [1.3.4] — 2026-11-25

- Collect Linux filesystems, local container images and supported VM disks offline with `vigievuln collect`. Replay the portable inventory and generate reports on the auditor machine with `vigievuln analyse`.
- Identify CMS and framework instances, keep their evidence paths, and report installed libraries and other system dependencies separately. Add local Docker image selection from project declarations.
- Include a Linux x86_64 musl archive for Alpine alongside the glibc release.
- Show progress while processing CVEProject records during advisory preparation.

## [1.3.3] — 2026-11-22

- Identify interpreters, embedded runtimes and network services in container images with 75 product fingerprints. Extract versions from supported ELF binaries, Windows resources and installation metadata.
- Check supported upstream binary versions against NVD and retain distribution advisory handling for installed OS packages.
- Group interpreters and services in image details and CVE reports, including detection evidence, unknown versions and incomplete advisory checks.

## [1.3.2] — 2026-11-20

- Group image CVEs by installation source and show declared image references first; omit unaffected image sub-dependencies from report inventories.
- Add optional `--image-retire` inspection of deployed JavaScript, excluding package stores, with offline reassessment and explicit coverage limits.
- Reduce report size with compact JSON and shared identical HTML CVE details, retaining vulnerability evidence and occurrences.
- Assess vendor NGINX packages on Alpine using retained maintainer metadata; refresh older inventories online.
- Respect branch-specific NGINX fixes and accept CVE identifiers with or without their prefix in the official feed.
- Warn when image references are not pinned by digest, including numeric version tags, in source and registry image scans.

## [1.3.1] — 2026-11-18

- Summarize NVD/EUVD record availability in one warning, separate from discovery coverage.
- Separate source and image summaries and charts; rank vulnerable images with their most critical CVEs.
- Restore the documented scanner feature comparison on the project site.
- Inventory installed image libraries and nested CLI tools separately, without resolving their declared dependencies.
- Ignore npm metadata fragments and separate image warnings from project warnings.
