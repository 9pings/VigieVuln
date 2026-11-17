# Traefik comparison: scoped review

The [machine evidence](traefik-adjudication.json) preserves the exact 51 Grype observations absent from the initial VV report, direct-cache Go records, the current GHSA records, and the Alpine snapshot identity. The image was `traefik:v2.11.0`, platform manifest `sha256:903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111`. These are package-level results; runtime reachability and configuration were not tested.

## Grype-only application observations

Forty-seven observations concern `pkg:generic/traefik@2.11.0`; Grype uses its `stock-matcher` against `nvd:cpe`. Its component inventory identifies the file with Syft's `binary-classifier-cataloger` / `binary-signature`. The [Syft v1.55.0 classifier](https://github.com/anchore/syft/blob/v1.55.0/syft/pkg/cataloger/binary/classifiers.go) matches a Traefik filename and version-like bytes, then supplies a Traefik CPE. The OCI config at digest `sha256:c1ef9171e9d171746404b3deec2a4c9902a34ab090be5e0af6292cf46d578b35` independently names Traefik, its upstream repository and `v2.11.0`. The Go main-module path is `github.com/traefik/traefik/v2`, but its embedded version is `(devel)`; the initial VV inventory did not infer a concrete main-module version.

At least one missing application observation has independent maintainer support: [GHSA-5w68-77r2-r64c](https://github.com/traefik/traefik/security/advisories/GHSA-5w68-77r2-r64c) includes versions through v2.11.54 and fixes v2.11.55. This supports a version-level candidate for the image; exploitation additionally depends on configuring the affected digest authentication middleware. The other 46 have not been independently adjudicated. Their CPE matches should not all be treated as confirmed vulnerabilities or false positives.

## Four Grype-only OS observations

Grype reports CVE-2025-60876 on `busybox`, `busybox-binsh` and `ssl_client` at `1.36.1-r15`, and CVE-2026-27171 on `zlib@1.3.1-r0`; each comes from `nvd:cpe` rather than the Alpine advisory source. The Alpine 3.19 OSV snapshot used by VV contains 27 BusyBox and two zlib advisory records, but neither of these CVEs. The [Alpine BusyBox tracker](https://security.alpinelinux.org/vuln/CVE-2025-60876) lists other 3.19 builds as possibly vulnerable but does not establish the exact `r15` status in the displayed tracker rows. The [Alpine zlib tracker](https://security.alpinelinux.org/vuln/CVE-2026-27171) lists the exact 3.19 `1.3.1-r0` as **possibly vulnerable**. The absence of an OSV record is not proof of safety, and a generic CPE range alone does not establish a distro backport verdict. The split BusyBox packages also require file/function ownership evidence before equating three package observations with three independently affected components.

## Five VV-only observations against Trivy

The direct OSV consultation returned Go database records. All five package/version coordinates are inventoried by Trivy, but Trivy did not emit the corresponding IDs in this run. Exact records are retained in the machine evidence:

- `github.com/aws/aws-sdk-go@v1.44.327`, CVE-2020-8911 and CVE-2020-8912: GO-2022-0646 and GO-2022-0635 respectively list all versions with no known fixed version and identify `service/s3/s3crypto` symbols. Their GHSA aliases instead report a fix at `1.34.0`. This is a source conflict; symbol reachability in the binary was not established.
- `github.com/docker/docker@v24.0.7+incompatible`, CVE-2026-34040: GO-2026-4887 explicitly lists the docker/docker module without a fixed boundary; its GHSA alias currently lists Moby module names instead. The affected authorization-plugin functionality was not established in this image.
- `github.com/redis/go-redis/v9@v9.2.1`, CVE-2025-29923: GO-2025-3540 includes an open lower bound through `9.6.3`; its GHSA alias instead specifies narrower affected intervals starting at `9.5.1`. This is a range conflict, not proof that the older version is affected.
- `go.etcd.io/etcd/client/pkg/v3@v3.5.6`, CVE-2026-73500: GO-2026-6107 explicitly includes this module and fixes the 3.5 branch at `3.5.33`; its GHSA alias is filed against the broader `go.etcd.io/etcd/v3` module. The specific listener symbols' use was not established.

These differences do not prove a VV range parser error: the direct OSV queries returned the cited GO records and the displayed VV verdicts follow those records. The Go database [documents conservative all-version mappings](https://go.dev/doc/security/vuln/database#note-on-versions) when normalization is uncertain. Conflicting aliases and symbol-level applicability require further review before making false-positive or confirmed-omission claims.
