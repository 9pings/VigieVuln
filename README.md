<h1 align="center">
<img src="docs/assets/VigieVuln_Logo_sm.png" alt="VigieVuln" height="200">
</h1>


[![npm version](https://img.shields.io/npm/v/vigievuln.svg)](https://www.npmjs.com/package/vigievuln)
[![npm downloads](https://img.shields.io/npm/dm/vigievuln.svg)](https://www.npmjs.com/package/vigievuln)
[![license](https://img.shields.io/npm/l/vigievuln.svg)](LICENSE)
[![node](https://img.shields.io/node/v/vigievuln.svg)](https://nodejs.org)
[![CI](https://github.com/9pings/VigieVuln/actions/workflows/ci.yml/badge.svg)](https://github.com/9pings/VigieVuln/actions/workflows/ci.yml)


**VigieVuln** is a polyglot dependency auditor built for **professional code audits**.

It scans dependencies and **9 CMS/frameworks** in one pass without build tools, supports **air-gapped** workflows, detects private packages, binaries and certificates, and produces HTML, JSON and other reports.


🌐 **[Project site & docs →](https://9pings.github.io/VigieVuln/)**

*Terminal demo recorded with VigieVuln 1.0.1.*

<p align="center"><img src="docs/assets/demo.gif" alt="vigievuln animated terminal demo: an offline Maven audit — dependencies absent from Maven Central flagged as private/internal, the compact single-line vulnerability-database progress, then findings coloured by severity" height="500"></p>

## Features

- **Multiple ecosystems in one pass**: Maven and Gradle, npm/Yarn/pnpm, Composer, PyPI, NuGet, Go and Ruby — plus **vendored JS**, committed **native binaries** and **embedded JARs**.
- **No build tools**; No `mvn`/`gradle`/`npm`/`pip`/`dotnet`/`go`, no `node_modules/` → [how](docs/COMPARISON.md#how-its-autonomous-no-build-tools)
- **CVE from multiple sources, merged & prioritised**; CVEProject + OSV.dev + Packagist security advisories + NVD, ranked **CISA KEV → EPSS → CVSS**.
- **European vulnerability references**: ENISA **EUVD** id + ENISA's exploited flag, **GCVE** id, and the **CERT-FR** advisories citing it. Hosted proxy lookups send relevant CVE identifiers to the proxy.
- **Beyond CVEs**; Report **EOL and out-of-active-support** frameworks, deprecated/abandoned/yanked, outdated, SPDX **licenses**, and **private/internal packages**
- **CMS & frameworks audited as instances**; Symfony, Laravel, WordPress, Drupal, Joomla, PrestaShop, TYPO3, Magento/Adobe Commerce and SPIP with per-instance inventory (core, plugins, themes, bundles, components) → [the dedicated guide](docs/CMS-FRAMEWORKS.md)
- **Crypto material**; committed **certificates**, **private vs public keys** across PEM/OpenSSH/PuTTY/PGP and JKS/PKCS#12 keystores.
- **Air-gapped flow**; **zero network under `--offline`** → [Benchmark](docs/BENCHMARK.md) · [Air-gapped](#air-gapped-audits)
- **Hosted proxy with a verified account**; `--set-proxy-cache vigievuln` → [hosted proxy](docs/USAGE.md#hosted-vigievuln-proxy)
- **Project monitoring**; `vigievuln watch ./project --name 'My Project'` — one free project with up to **100 distinct direct dependency coordinates** → [monitoring guide](docs/USAGE.md#project-monitoring)
- **Shared cache for a scanner fleet**; `vigievuln serve-cache` + `--proxy-cache`  → [cache usage](docs/USAGE.md#shared-proxy-cache-server-serve-cache----proxy-cache)
- **Supply-chain risk**; known-**malicious** advisories and suspected **typosquats** (`--typosquat`).
- **Audit-grade**; every report carries a **provenance manifest** and a **Methodology & limitations** chapter; a `SHA256SUMS`;
- **Differential audits** diff against a prior run (`--baseline`) and CI can gate on *new* findings only.
- **Reports in English or French** (`--lang fr`)
- **Outputs & CI**; Pro HTML report + JSON baseline by default + Word, Excel, CycloneDX 1.6 SBOM, CSAF 2.0 VEX, SARIF 2.1.0, JSON; gate with `--fail-on`, triage with `--ignore`/`--vex`.
- Report **made for productivity**; every table / chart has a **Copy for word** button.

📖 **[Usage & all flags](docs/USAGE.md)** · **[Architecture](docs/ARCHITECTURE.md)** · **[Comparison vs other tools](docs/COMPARISON.md)** · **[Data sources](docs/DATA-SOURCES.md)**

## Quick start

```bash
npm install -g vigievuln
vigievuln scan ./code             # → ./vigievuln-report/cve-report.html
```

A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (instant) gives 10× faster enrichment: `vigievuln --set-nvd-key YOUR_KEY`. A few common runs; full list via `vigievuln --help` or [docs/USAGE.md](docs/USAGE.md)

### Monitor a project

Create and verify your [account](https://www.vigievuln.fr/account), then sign in and explicitly accept the [terms of service dated 2026-10-28](https://www.vigievuln.fr/terms) when prompted:

```bash
vigievuln login
vigievuln whoami
vigievuln watch ./project --name 'My Project'
vigievuln project status
vigievuln logout
```

`watch` collects the inventory locally and uploads it once. Run it again with the same unique project name to update that project's inventory; it does not run a background watcher. `login` selects the official proxy if none is configured; an existing proxy remains selected.

The free tier watches **one project, up to 100 direct dependencies and a 0.5 MB descriptor**, for **one month renewed by each upload**; expiry deletes the monitoring data and triggers an email.

If the current terms have not been accepted, the CLI displays their link and asks for explicit acceptance in an interactive terminal. For non-interactive use, run `vigievuln login` interactively and accept the terms first.

To review the inventory before uploading, export it locally:

```bash
vigievuln watch ./project --export fichier.json
```

`--export` writes an offline descriptor without uploading; review package names and versions, including private packages, before sharing it.

Enable alerts in your account to receive new high, critical or known exploited vulnerabilities affecting your direct dependencies; refresh the inventory when dependencies change. [Monitoring guide](docs/USAGE.md#project-monitoring).

Existing commands remain supported: `vigievuln -s ./code`, `auth login|status|logout`, `--prepare-project` and `project push`.

### Official Vigie Vuln proxy cache

[Vigie Vuln DB](https://www.vigievuln.fr/) hosts vulnerability data and the official proxy cache in Europe.

Configure the proxy once, then sign in with your verified [Vigie Vuln account](https://www.vigievuln.fr/account) when prompted:

```bash
vigievuln login  # selects the official proxy if none is configured
vigievuln scan ./code
```

The selection and the proxy key created during proxy sign-in are saved in `~/.vigie-vuln/config.json` and reused on subsequent scans. This proxy key is separate from the account session used by `watch`. Alternatively, save an existing key with `vigievuln --set-proxy-cache-token <key>`, or provide it via `VIGIEVULN_PROXY_CACHE_TOKEN` (useful in CI). Remove the selection or key with `--unset-proxy-cache` or `--unset-proxy-cache-token`. `--proxy-cache <url>` overrides the saved selection for one scan. The hosted proxy receives requested package coordinates and CVE identifiers; it does not receive your source code. [Proxy documentation](docs/USAGE.md#hosted-vigievuln-proxy).

With the official proxy, scans also match published [VigieVuln advisories](https://www.vigievuln.fr/advisories/vigievuln?lang=en) for Maven and npm packages, including when OSV is disabled. Their `VV:CVE-…` identifier and sources are retained; AI-assisted reconciliation and review are disclosed on each advisory. Partial version evidence leaves other versions unknown. Cached advisories are available offline.

### Interactive HTML samples

- **[Apache Dubbo 2.7.8 — open the report](https://9pings.github.io/VigieVuln/samples/dubbo.html)**: the project used for the report screenshot below, rescanned with VigieVuln 1.1.3; 105 Maven descriptors, direct/transitive CVEs, KEV matches, EOL and fix recommendations.
- **[Multi-instance CMS & frameworks — open the report](https://9pings.github.io/VigieVuln/samples/multi-cms-frameworks.html)**: WordPress 6.4.2, Drupal 8.5.0, Symfony Demo (Symfony 7.1.1) and BookStack v24.10 (Laravel 10.48.22), with findings attributed to each instance.

These are standalone reports from real source scans, generated on **2026-10-29** using the hosted proxy and local caches. The CMS sample focuses on PHP dependencies; WordPress advisory coverage is explicitly incomplete without a Wordfence feed. [Sample scope, sources and reproduction commands](docs/samples/README.md).

> [!WARNING]
> vigievuln is new and may still contain ( rare ) bugs. Treat its output as a strong first pass, **double-check anything critical**, and please [report issues](https://github.com/9pings/VigieVuln/issues); they get fixed fast.

## Why use vigievuln for code audits?

An author-maintained comparison of audit workflows; see [`docs/COMPARISON.md`](docs/COMPARISON.md)
for versions, sources and limitations. `⚠️` indicates partial or conditional support.

| What an auditor actually needs to do                                                       | **VigieVuln** | OSV | Trivy | Grype+Syft | OWASP DC | Snyk |
| ------------------------------------------------------------------------------------------ | :-: | :-: | :-: | :-: | :-: | :-: |
| Audit a **100-module polyglot monorepo in one command**, with **no toolchain installed**  | ✅ 105 modules | ⚠️ reactor skipped | ⚠️ needs `~/.m2` | ⚠️ opt-in | ⚠️ Java build | ⚠️ `mvn` build |
| **Scan offline / air-gapped with cached data**                                            | ⚠️ cached metadata | ⚠️ limited | ⚠️ `~/.m2` | ⚠️ opt-in | ⚠️ mirror | ❌ |
| **Identify the private/internal deps** across a big project                               | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Extract cleaned deps descriptors** into an external directory                           | ✅ `-t` | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Report EOL / deprecated frameworks & deps**, transitive ones included                   | ✅ | ⚠️ deprecated only | ⚠️ OS distros only | ❌ | ❌ | ⚠️ web UI only |
| **Report committed keys & certificates**                                                  | ✅ | ❌ | ⚠️ key rule | ❌ | ❌ | ❌ |
| **Spot committed binaries** (`.dll`, `.exe`, …) and check them against their checksums    | ✅ | ❌ | ⚠️ some | ⚠️ patterns | ❌ | ❌ |
| **Clearly list what was *not* scanned** — before the client asks                          | ✅ warnings + method | ⚠️ log | ⚠️ log | ⚠️ log | ⚠️ log | ⚠️ log |
| **Answer "against what data?" six months later**                                          | ✅ | ❌ | ❌ | ⚠️ DB date | ⚠️ NVD date | ❌ |
| **Send a report, not a JSON dump**                                                       | ✅ HTML + `.doc` | ⚠️ HTML list | ⚠️ template | ❌ | ⚠️ HTML list | ⚠️ `snyk-to-html` |
| **Charts, per-CVE drill-down and a pasteable Word copy**                                 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Make delta reports showing only what changed**                                         | ✅ `--baseline` | ❌ | ❌ | ❌ | ❌ | ⚠️ cloud |
| **Audit CMS/framework instances as such** — plugins, themes, publisher advisories       | ✅ 9 products | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Share one cache across the fleet**, API keys server-side                               | ✅ `serve-cache` | ❌ | ⚠️ local DB | ⚠️ local DB | ⚠️ local DB | ⚠️ cloud |


Offline dependency resolution depends on cached metadata. In the Dubbo test, a cold advisory seed alone produced 185 groups versus 734 with warm metadata and reported missing POMs; see the [benchmark](docs/BENCHMARK.md) for scope and warnings.

**Deliberately not a goal: reachability.** A finding is a vulnerable version on the dependency
graph, and the report says exactly that (in Methodology) instead of guessing at call paths. Deciding
whether the vulnerable code is reachable in *this* application is the auditor's call, made with
application context no scanner has.

## More examples

```bash
vigievuln -s ./proj -e "^com\.acme\."                        # exclude private libs (coord regex)
vigievuln -s ./proj -t ../clean -e "^com\.acme\."            # extract only: normalised descriptors, private modules flagged
vigievuln -s ./proj -t ../clean -e "^com\.acme\." -a snyk   # same extraction + scan + merge Snyk
vigievuln -s ./proj --offline                                # fully offline (zero network, needs a warmed cache)
vigievuln -s ./proj -a osv-db,typosquat                      # OSV advisory matching + typosquat
vigievuln -s ./proj -a licenses --fail-on high               # license chapter + CI gate
vigievuln -s ./proj --report-json --baseline last.json --fail-on-new   # differential audit: fail CI on NEW findings
vigievuln diff last.json this.json                           # standalone diff of two findings JSONs
vigievuln -s ./proj -r html,json,xlsx                        # include the Excel workbook
vigievuln -s ./site --app-plugins wordpress --private-component wp-content/plugins/acme --offline
```

> [!IMPORTANT]
> **`--offline` reads the cache, it doesn't replace it.** On a *cold* cache there is nothing to
> match against; an empty report is not evidence that the project is clean. Initialise it from
> a seed or warm it online, then review coverage and freshness warnings in the offline report.
> Cached advisories can match other applicable versions, but neither a partial cache nor an
> old snapshot guarantees complete or current results.
> Air-gapped machines get their cache via [`--export-cache` / `--import-cache`](#air-gapped-audits).

## What it finds

The report keeps the six root chapters. Sub-chapters appear only when they contain results and are numbered consecutively; application inventory and methodology remain available in scan context:

| Chapter | Source | What it catches |
| --- | --- | --- |
| **0. Warnings** *(top)* | local heuristics | Missing lockfiles, unresolved Maven versions (BOM-managed), private packages absent from configured registries |
| **Δ. Changes since baseline** *(top, with `--baseline`)* | diff vs prior JSON | New / fixed / unchanged findings per category + the list of **new production CVEs**; for repeat audits and `--fail-on-new` CI gating |
| **1. CVE** *(X direct, Y indirect, Z dev)* | CVEProject + OSV.dev + Packagist + qualified publisher feeds + NVD/CPE | **Applications first when findings exist**; CMS/framework findings by instance and owner · **Production**; public CVE / GHSA in other prod deps, per ecosystem, per manifest, **prioritised** by CISA KEV + EPSS + CVSS · **Vendored JS vulns** ([retire.js](https://retirejs.github.io/)) — one row per physical library, linked CVEs + CWEs on the row, every advisory behind a click · **Dev** (`test`/`provided`, `dev`/`optional`/`peer`) · **Likely false positives** (CPE-filtered) |
| **2. Unmanaged / unversioned components** | deps.dev + CIRCL (by checksum), retire.js, built-in X.509 | **Embedded binaries**; CVEs in libs shipped inside committed `.jar`/`.war`/`.ear` (fat-jars, shaded uber-jars) · **Native binaries** (`.dll`/`.exe`/`.so`/`.dylib`): available metadata and checksum evidence; metadata alone does not reliably identify a product or establish CVE applicability · **Vendored JavaScript** inventory (jQuery, Bootstrap, …) vulnerable *or not* · **Certificates &amp; key material**; committed certs (expiry / weak key / weak signature / self-signed), **private vs public keys** (PEM/OpenSSH/PuTTY/PGP/SSH) and keystores, all parsed offline |
| **3. Maintenance / EOL** *(X EOL, Y obsolete, Z outdated)* | endoflife.date · curated + registry flags · Maven Central / npm / Packagist / PyPI / NuGet | **End-of-Life** frameworks (+ an "Out of active support" band with `--eol-support`; Symfony/Laravel grouped as one row per framework; PHP runtime when the Composer constraint proves it), split **direct** (declared / parent-POM-inherited — bump these) vs **transitive** (bump the dep that pulls them in) · **Obsolete / deprecated / abandoned / yanked** · **Outdated** (newer version available, with release dates; direct deps only) |
| **4. Licenses** *(opt-in: `--licenses`)* | registry metadata + Maven POMs → SPDX policy | Each dep's license normalised to SPDX and classified; copyleft (GPL/AGPL/LGPL/MPL), proprietary and unknown flagged for review |
| **5. Fix Recommendations** | computed | Per-ecosystem pin recipes: Maven `<dependencyManagement>`, Gradle `constraints { }`, npm `overrides`, yarn `resolutions`, `composer require`, `pip install`, `dotnet add package` |
| **6. Scan context & limitations** | provenance manifest + walk | **Scanned descriptors** (every manifest parsed) · **Ignored directories** (pruned paths + rule) · **Methodology, data sources & limitations** (data-source freshness, run config, explicit statement of **what vigievuln does *not* assess**) · **Application inventory & coverage** (also shown when no CVE matches) |
| **Supply-chain risk** *(cross-cutting)* | OSV `MAL-…` + name heuristic | **Known-malicious** packages (always block the CI gate, any `--fail-on` level) and **suspected typosquats** (`--typosquat`: an npm/PyPI name one edit from a popular package; `lodahs`↔`lodash`) |

The HTML report opens in any browser, contains every detail (CVSS vectors, references, full descriptions, CPE configurations, via-paths for transitives) and ships a Word-compatible `.doc` twin. Every match carries a **composite priority** (KEV-exploited > EPSS likelihood > CVSS severity), and the run can additionally emit a **CycloneDX 1.6 SBOM** (`--report-sbom`, vulnerabilities inline) and a **CSAF 2.0 VEX** (`--report-csaf`) for downstream tooling.

<p align="center"><img src="docs/assets/report.png" alt="vigievuln HTML report; executive summary with severity tiles and a detailed CVE table with CWE, descriptions and fix versions" width="900"></p>


## CMS & frameworks

See the [CMS coverage limits](docs/CMS-FRAMEWORKS.md#coverage-and-its-current-limits)
and [shared-cache operating limits](docs/USAGE.md#shared-proxy-cache-server-serve-cache--proxy-cache).

vigievuln doesn't just read the `composer.json` under a WordPress or Drupal site — it inventories the **instance**: core, plugins, themes, bundles and framework components with their observed versions, attributes every dependency CVE to the component that ships it, and reports each instance in its own sub-chapter — synthesis included even when it comes out clean. Any recognized layout is activated by the default `--app-plugins auto`; `none` opts out.

| Product | Inventory | Advisory lane |
| --- | --- | --- |
| **WordPress** | core (`wp-includes/version.php`), plugins (public or private by `Update URI`), themes | **Wordfence** production feed (API key, or a warmed catalogue offline) + **core checksums** integrity (api.wordpress.org) |
| **Drupal** | core (lock + `Drupal.php` marker), modules incl. `modules/contrib`, themes, profiles, Drupal 7 branch | **packages.drupal.org** per-package security advisories |
| **Symfony** | framework, framework-components, bundles, libraries; **Symfony Flex recipes** (`symfony.lock`) | the dependency lanes (OSV.dev, Packagist, NVD) — no publisher feed exists, and the coverage says so |
| **Laravel** | framework, bundles, libraries | the dependency lanes (OSV.dev, Packagist, NVD) |
| **PrestaShop** | core (`_PS_VERSION_`), modules, themes | the publisher's **GitHub security-advisories** feed |
| **TYPO3** | core, extensions | the publisher's **GitHub security-advisories** feed |
| **SPIP** | core (`$spip_version_branche` in `ecrire/inc_version.php`), dist plugins (`paquet.xml`), user plugins (`paquet.xml`/legacy `plugin.xml`) | **NVD product CVEs** (`cpe:2.3:a:spip:spip`) — the only machine-readable SPIP source; plugins stay honestly not-qualified |
| **Joomla / Magento (Adobe Commerce)** | core, extensions/modules, themes | no machine-readable publisher feed exists; components locked as Composer packages read as covered by the **dependency lanes**, the rest stays honestly **not qualified**. A Magento source distribution reports its exact version from the root `composer.json` |

Every advisory snapshot a live lane fetches is stamped and cached in the local SQLite database, **prepared from the air-gapped descriptor** by `cache prepare`, and reused automatically offline — the Wordfence API key never travels to the enclave. Private/custom components are inventoried separately and never sent to any publisher. → **[the dedicated guide](docs/CMS-FRAMEWORKS.md)** · [application usage](docs/USAGE.md#application-inventory-experimental)

## Air-gapped audits

Run `vigievuln setup` in an interactive terminal to select all sources (the default), US-operated services, European-operated services, or a proxy only. Setup can sign in to an official or custom instance and initialise the local cache from its authenticated bundle. Regions describe the service operator, not the origin of every advisory it aggregates.

For unattended setup, use `vigievuln setup --mode direct --sources all` or `vigievuln setup --mode server --server-url https://server.example --seed`. The modes are `direct`, `official`, and `server`; direct mode also accepts `--sources us` or `--sources eu` and `--seed-url` with `--seed`. Authentication reuses a saved session or reads `VIGIEVULN_EMAIL` and `VIGIEVULN_PASSWORD` from the environment. To accept terms after reviewing them, pass `--accept-terms <exact-version>`; a different server version is rejected.

A local server can explicitly allow anonymous access, including seed downloads. An HTTP server requires confirmation before the first connection because credentials and keys are not encrypted. In unattended setup use, for example, `vigievuln setup --mode server --server-url http://192.168.1.10:8322 --seed --allow-insecure-http`; the confirmation is remembered for that exact origin. Prefer HTTPS on untrusted networks.

Stored OSV and GCVE advisories are matched against dependency versions during the scan. An online scan can collect GCVE data through the configured proxy without a seed; offline matching uses the local cache or an imported bundle. Check the report's coverage warnings: a collection can be incomplete or stale, and some advisory version formats cannot be evaluated reliably. A bundle checksum detects corruption but does not authenticate its origin.

Online scans add downloaded advisories to the same local store, so they can also match other affected versions offline. `--advisory-query-ttl <hours>` controls when source queries are refreshed (default: 4 hours; `0` requests revalidation on every online scan). `--force-update` revalidates consulted online sources, using conditional requests when available. A proxy may itself serve cached data; the report indicates known freshness and coverage limits. Selecting a seed in direct mode does not enable a proxy for subsequent scans.

The global seed can include previously observed public Maven POMs and npm manifests by version, but is not a complete registry mirror. Other ecosystems are not yet covered by this durable metadata store. Offline transitive resolution for a new project still depends on lockfiles, manifests and previously warmed local package data; the vulnerability seed alone cannot guarantee it.

> **Zero-data-sent guarantee.** Under `--offline`, vigievuln makes **no network calls
> whatsoever**; it reads only the warmed `~/.vigie-vuln/` caches and never transmits a
> dependency, path or finding off the machine. It is regression-tested
> (`test/offline-guarantee.test.js`, a tripwire fetcher that throws if touched) and
> auditor-reproducible: `unshare -rn node vigievuln.js -s ./proj --offline …` runs it in a
> namespace with **no network interface** and yields byte-identical findings. With warmed
> POM caches, VigieVuln can also resolve the **Maven transitive graph** offline.

When the audited system is **offline / confidential** (typical of a regulated or air-gapped audit) it
can't reach OSV / NVD / Maven Central / npm. Split the work across machines using a
descriptor of **dependency coordinates and filtered version hints**, with manifest paths
and registry URLs removed. Offline collection cannot distinguish private package names
from public ones: exclude internal dependencies and review the descriptor, including
parent/BOM coordinates, before transfer. The **detailed report is produced back on the
offline machine**.

The online step warms transferable package data and advisory records. The offline scan
matches available advisories against the dependencies it finds and reports known coverage
and freshness limitations.

```bash
# ── Phase 1; OFFLINE (audited machine): export the anonymized descriptor ──
# Exclude private/internal packages with -e (offline we can't tell private from public).
vigievuln -s ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   → deps.json: dependency coordinates and version hints. Review before transfer.

# ── Phase 2; ONLINE (any machine, no source needed): warm the caches ──
vigievuln cache prepare deps.json --output vigievuln-cache.tar.gz  # add --force-update to revalidate cached online sources
# Resolves and warms the descriptor, then writes its project-scoped SQLite archive.
# A configured proxy may initialise the local OSV catalogue if it is missing.
# CMS snapshots and Retire signatures are prepared during the same command.

# ── Phase 3; OFFLINE (audited machine): full report, all local context ──
vigievuln --import-cache vigievuln-cache.tar.gz   # merged into the enclave's own cache
vigievuln -s ./proj --offline               # re-collect locally (real paths) + cache hits
#   → full HTML/.doc report with manifests & structure, generated inside the enclave.
#   CMS advisory snapshots (Drupal/PrestaShop/TYPO3 feeds, WP checksums) fetched live by
#   the online phase ride the same archive and are consumed automatically — no flags.
```

`cache prepare` includes advisories for resolved packages and the data needed for
offline matching. If an offline scan discovers an unprepared package, its OSV
coverage is reported as incomplete. CMS and native-binary descriptors retain the
full NVD cache when their requirements cannot be narrowed to package coordinates.
`--export-cache` separately exports the complete local cache.

For Maven projects, regenerate descriptors made by an older build before preparing
the archive: the descriptor now includes path-free per-module resolution hints.
Review those coordinates and version hints before transferring the JSON.

Descriptor imports also warm Maven registry presence (unless
`--no-all-libs` is set). Legacy negative presence entries are discarded automatically:
older versions could confuse network errors with missing packages. Until verified
online, those entries remain **unknown**, including after a cache merge. Other warmed
analysis data is retained.

Unverified empty OSV cache entries are not trusted, because a failed request may have
been stored as “no vulnerabilities”. Re-warm and export the cache to verify these entries; until then offline reports warn about incomplete
OSV coverage. Existing cached advisory IDs remain usable. Offline KEV and binary identity
lookups reuse the last available snapshot even after four hours, without changing its date.

The [offline Docker integration check](docs/USAGE.md#offline-docker-integration-check) exercises this workflow in an isolated container.

What the descriptor (`fad-deps/1`) contains vs. drops:

| Kept (needed to scan) | Dropped (environment) |
| --- | --- |
| ecosystem, ecosystemType | manifest paths / pom paths |
| namespace, name | resolved registry URLs |
| version, versions | integrity hashes |
| scope, isDev | parent chains, lockfile type |
| application type + core version + inventoried **public** component identities | private component identities |

The online phase report is itself path-free; vendored-JavaScript (retire.js) findings are
produced **offline in phase 3**, since retire needs the actual `.js` files; its signature
DB is warmed online and included by `cache prepare` (phase 2). Full offline/cache control →
[`docs/USAGE.md`](docs/USAGE.md).

## Docs

- [`docs/USAGE.md`](docs/USAGE.md); every flag and workflow: offline/cache control, private registries, config files, recipes, safety rails.
- [`docs/CMS-FRAMEWORKS.md`](docs/CMS-FRAMEWORKS.md); the CMS/framework instance view: detection markers, per-product advisory lanes, coverage semantics and the air-gapped workflow.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); internals: codecs, collection, matching, report pipeline.
- [`docs/COMPARISON.md`](docs/COMPARISON.md); vs OSV-Scanner / Trivy / Grype / OWASP DC / Snyk, and how it stays build-free.
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — dated scanner comparisons on pinned projects, including warm and cold offline limitations.
- [`docs/DATA-SOURCES.md`](docs/DATA-SOURCES.md); the public datasets vigievuln uses + their licenses.
- [`CHANGELOG.md`](CHANGELOG.md) · [`CLAUDE.md`](CLAUDE.md); release history · code-level orientation for contributors.

## Contributing

The most useful contribution to a young scanner is **telling it where it's wrong**: run it on a
real project and file a [false positive / false negative report](https://github.com/9pings/VigieVuln/issues/new?template=false_positive.yml)
with the coordinate and the manifest snippet that produced it. Dev setup, ground rules and the
codec extension point → [`CONTRIBUTING.md`](CONTRIBUTING.md). Vulnerabilities in vigievuln
itself → [`SECURITY.md`](SECURITY.md) (please report privately).

**On AI assistance:** this codebase is written with heavy use of Claude Code; [`CLAUDE.md`](CLAUDE.md)
in the repo root is exactly what it looks like. The bar it's held to is the one you can check
yourself: the test suite (`npm test`), the zero-network guarantee enforced by a tripwire test and
and the dated comparisons and limitations documented in [`docs/BENCHMARK.md`](docs/BENCHMARK.md). `vigievuln` itself uses **no LLM at runtime**; findings come from public
vulnerability databases and deterministic parsers, and no report text is generated. Full
statement, including where review actually caught a bad finding →
[`AI_POLICY.md`](AI_POLICY.md). Where the code doesn't meet that bar, that's a bug report I want.

## License

Apache-2.0; see [`LICENSE`](LICENSE).
