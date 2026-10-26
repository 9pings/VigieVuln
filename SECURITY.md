# Security policy

## Reporting a vulnerability

Report vulnerabilities in `vigievuln` itself **privately**, via
[GitHub private security advisories](https://github.com/9pings/VigieVuln/security/advisories/new).
If that isn't available to you, email `pp9Ping@gmail.com` with `vigievuln security` in the
subject.

Please don't open a public issue for a vulnerability. This is a single-maintainer project —
expect a first response within **7 days**, and a fix or a plan within **30 days** for anything
confirmed. Credit is given in the release notes unless you'd rather stay anonymous.

Findings *about your own dependencies* that vigievuln reported are not vulnerabilities in
this project — those belong in a normal issue (the
[false positive / false negative](https://github.com/9pings/VigieVuln/issues/new?template=false_positive.yml)
template).

## Supported versions

Only the latest released version on npm is supported. There are no backport branches.

## Threat model

vigievuln parses **untrusted input**: manifests, lockfiles, archives and certificates from a
source tree you may not control. The parsing surface is where security bugs are expected, and
reports there are especially welcome. In particular:

- **Archive extraction** — `.jar`/`.war`/`.ear` are unzipped **in memory** (`fflate`), never to
  disk, and nested archives are recursed to a bounded depth. Path traversal (zip-slip) has no
  filesystem to reach, but resource exhaustion (zip bombs) is a valid report.
- **Certificate and key parsing** — X.509 goes through Node's built-in `crypto.X509Certificate`.
  Key material is **classified and hashed, never decrypted**, and its contents are never written
  to the report.
- **XML / YAML / TOML parsing** — `pom.xml` (xml2js), lockfiles (js-yaml, smol-toml). XXE and
  entity-expansion reports are in scope.
- **Command execution** — subprocesses include `snyk` (opt-in `--snyk`), `retire`,
  CVE download helpers, archive utilities (`tar`, `zip`, `unzip` or PowerShell),
  and runtime re-execution for proxy configuration. CMS marker files are read,
  never executed.
- **Shared cache** — bind to loopback by default. A shared token also authorizes
  statistics and cache clearing. Use TLS termination when crossing an untrusted
  network; HTTP alone exposes tokens and forwarded source credentials. Upstream deadlines, transfer limits, a metadata/body/spool quota and concurrency
  limits bound shared-cache work; filesystem block overhead needs additional headroom. See the operating limits in
  [`docs/USAGE.md`](cli/docs/USAGE.md#shared-proxy-cache-server-serve-cache--proxy-cache).

## What leaves your machine

Under `--offline`, **nothing**: no network call is made at all, only the warmed
`~/.fad-checker/` caches are read. This is enforced by a regression test
(`test/offline-guarantee.test.js`, a tripwire fetcher that throws if touched) and is
reproducible in a network-free namespace:

```bash
unshare -rn node cli/vigievuln.js -s ./proj --offline
```

Online, vigievuln sends **package coordinates and versions** to the data sources listed in
[`docs/DATA-SOURCES.md`](cli/docs/DATA-SOURCES.md) (OSV.dev, NVD, Maven Central, npm, Packagist,
PyPI, NuGet, RubyGems, proxy.golang.org, endoflife.date, FIRST.org EPSS, CISA KEV, deps.dev,
CIRCL hashlookup) — plus **file checksums** for committed native binaries. It never uploads
source code, file paths or manifest contents. If you consider your dependency list itself
sensitive, use the anonymized air-gapped workflow described in the README.

Configuration, including your NVD API key, lives in `~/.fad-checker/config.json` with mode
`0600`. Registry credentials given via `--add-repo --auth`/`--token` are stored there too —
they are sent only to the registry they belong to, and never appear in a report or export.
