# Image update observations and offline replay

On 5 November 2026 the two tags recorded in the original acquisition evidence were
resolved again against Docker Registry. The SHA-256 of each index response was
recalculated and matched the registry digest header. The index lists the exact
Linux amd64 manifest originally inventoried; see
[registry-reference-verification.json](registry-reference-verification.json).
The inventory and source cache used below are copies. The original inventory remains
an OCI-layout inventory: the verified registry link is recorded separately in
`metadata.registryReference`, with the scanned platform digest.

| Reference | Scanned Linux amd64 digest | Same-branch observation |
| --- | --- | --- |
| `docker.io/library/traefik:v2.11.0` | `sha256:903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111` | [`v2.11.61`](traefik-update.json), Linux amd64 manifest `sha256:13064dcca35341355072281e92861d4ed5ee6134013e1f243b7b6d8f55107f75` |
| `docker.io/library/nginx:1.24.0` | `sha256:2e26275ed7a47e8e93f264d39a09ca4bc3f4058c904c75087e237f4ea883f2a1` | [`1.24.0`](nginx-update.json), same Linux amd64 manifest |

The resolver selected numeric patch tags on the same branch and checked that each
candidate has a matching image platform. Registry tag order and platform support do
**not** establish that any vulnerability is fixed. No target image was scanned or
proven secure. These are observations at the recorded time, not live status.

Each report was regenerated with the copied inventory and warmed copied cache, using
`image --inventory --offline --enrich nvd,kev,epss,gcve,euvd,certfr`. A network
tripwire rejected fetch and socket connections; no attempt was recorded. The raw
JSON results are [Traefik](traefik-findings.json.gz) (212 findings) and
[NGINX](nginx-findings.json.gz) (80 findings). The original inventory, package
versions and advisory applicability were not changed. The separate source reference
was added only after its manifest-to-inventory digest match was verified.

The final reports keep one description per CVE, show consulted EUVD/GCVE/GHSA
sources as linked badges, and put the concise image or component action in the
update column. The collapsed inventory has a chevron and lists affected components
first, including those without a known fixed version.

After the shared-component audit, both reports and compressed findings were
regenerated from the same image inventories and caches with the network tripwire
active. The replay returned 212 Traefik and 80 NGINX advisory findings, with
zero warnings and no network attempts. The component chart displays 212 and 155
projected CVE rows respectively; the image inventory navigation links were also
checked in a browser. Mixed source/image checks were synthetic regression tests,
not additional real-world scans.

Validation after the shared-component audit: 2,188 CLI tests passed, 11 skipped;
583 server tests passed with the refreshed local CLI dependency. After the final
CWE legend correction, the 49 chart and translation tests also passed.
The audit covered mixed report counters and navigation, chart attribution,
finding identity across images, artifact-scoped delta coverage, and CycloneDX
provenance for embedded JARs. This is not an exhaustive certification of all paths.
The application was [deployed](deployment.json) with the same packaged CLI.
Web, worker and curation share the recorded immutable image; the deployment lock
was verified, PostgreSQL and the WAF were not recreated, and the public health
endpoint returned HTTP 200 after the update.

The per-image totals now use a compact table with localized severity badges and
a styled vulnerability link. Both HTML examples and Word exports were regenerated
offline; the 17 image-report/remediation tests passed. The table and its anchor
were checked in Chromium at desktop and narrow viewport widths.
