# Release notes — VigieVuln

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
