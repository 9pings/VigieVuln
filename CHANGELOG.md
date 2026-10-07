# Changelog

All notable changes to `fad-checker` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- European references for every matched CVE: the ENISA **EUVD** id and ENISA's exploited
  flag (`lib/euvd.js` — the mapping dump + the exploited catalogue, bulk, 24h cache), the
  **GCVE** id (`GCVE-0-…`, computed — the GCVE rules map every CVE to GNA 0) and the
  **CERT-FR** advisories and alerts that cite it (`lib/certfr.js` — a local, incremental
  CVE → advisory index; the first run reads ~18 000 advisories once, ~75 s). No CVE id of
  the project is ever sent. Shown in the CVE detail panel (CERT-FR titles as written) and
  carried by every export: findings JSON (`euvd`, `euvdExploited`, `euvdExploitedSince`,
  `gcve`, `certfr`), CycloneDX `vulnerabilities[].references`, CSAF `references`, SARIF
  `europeanReferences` + `enisa-exploited` tag. ENISA's exploited flag is reported, not
  gated: the priority band and `--fail-on kev` stay on CISA KEV. `--no-euvd` / `--no-certfr`
  (`-d euvd,certfr`); both are cached for `--offline` and travel in `--export-cache`.
- EOL chapter: each row is click-to-expand. The detail panel lists every descriptor
  that declares the framework (or each component of a grouped framework) down to
  `file:line` plus the declaration itself; a transitive finding shows every chain
  and where the direct dependency to bump is declared (`lib/descriptor-refs.js`).
  Grouped EOL `components[]` now carry `manifestPaths` / `scope` / `via` in the JSON.
- NVD mirror (`fkie-cad/nvd-json-data-feeds`, a daily git mirror of the NVD API 2.0: same
  JSON, no key, no rate limit). Without an NVD API key it is read FIRST, in parallel; a CVE
  it does not hold (not mirrored yet) or cannot serve goes to NVD, which must answer (full
  retry schedule, the run stops otherwise). With a key NVD stays first and the mirror is its
  fallback. A cached record past its TTL is served rather than dropped when no source
  answers. `--no-nvd-mirror` (`-d nvd-mirror`) restores NVD-only.
- `--retries <n>`: number of retries (5+n s apart) before an unresponsive data source
  stops the run. Default 5 (unchanged behaviour); `0` disables retrying.

- EOL and paid support: when endoflife.date lists commercial support past the open-source
  end of life (`extendedSupport`, e.g. Broadcom for Spring), the EOL row states it — it
  stays an EOL finding, since those fixes are paid builds from the vendor's repository. It
  also gives the build of the dependency's OWN branch that fixes the CVEs found (from the
  advisories' per-branch bounds: CVE-2024-38820 on 5.3.x → a build above 5.3.40, not the
  6.1.14 migration) and, with the vendor repository configured (`--add-repo maven … --token`),
  the newest vendor build and whether it reaches that bound. A project already running a
  vendor build (newer than the cycle's last public release and absent from Maven Central)
  is not reported as EOL: a chapter-0 note says so. JSON: `extendedSupport`, `cycleLatest`,
  `branchFix`, `latestCommercial`; every CVE match carries `cve.branchFix`.

### Fixed
Reliability — every item below produced a false positive or a false negative; each is
checked against `mvn dependency:tree` / Maven's own `ComparableVersion` / the package
manager's documented semantics, and locked by a test.

- Maven version ordering now equals Maven's `ComparableVersion`: unknown qualifiers sort
  AFTER the release (`32.0.0-jre > 32.0.0`, Jetty `9.4.11.v20180605 > 9.4.11`), a number
  beats a qualifier, `1.0.1 > 1.0-1`, `1-rc < 1-rc1`, `1.0a1` = alpha-1. Guava's fixing
  release was "affected" by the CVEs it fixes, Jetty's by its own. Verified on 9 816 real
  version pairs (0 mismatch); 1 542 of them kept as a test oracle.
- Maven version ranges (`[1.0,2.0)`) are resolved to the highest published version inside
  them (maven-metadata.xml) instead of being compared as a literal version, which matched
  every upper-bounded CVE.
- Maven is now resolved MODULE BY MODULE (`lib/maven-reactor.js`): each module with its own
  `<dependencyManagement>`, external parent, imported BOMs and property overrides; the scan set
  is the union of what the modules really hold. The former global merged pass let one
  project's pins re-version another project's dependencies (several projects under one scan
  root) and kept a managed version a module overrides as a direct dependency. It replaces the
  per-module overlay (`lib/version-overlay.js`, removed).
- A coordinate present only in `<dependencyManagement>` (a version pin) or an imported BOM
  is no longer scanned as a dependency; it is kept only where a module really resolves it.
- Transitive resolution is deterministic and follows Maven's mediation: nearest wins, then
  first declared (the result used to depend on network latency); the winner keeps its version
  and a wider-scope path only widens its scope and its subtree's.
- `<exclusions>` (declared and managed) are applied; a dependency without `<scope>` takes the
  managed scope, locally and in upstream POMs (junit/mockito managed `test` in a root pom,
  logback managed `test` by a library's parent, no longer production); transitives of a
  `provided` dependency are dev; import-BOM / parent managed versions pin transitives.
- Upstream POMs: a child redeclaring an inherited dependency overrides it; an explicit
  managed entry beats an imported BOM and the first imported BOM wins;
  `${project.parent.version}` resolves. An external parent's own `<dependencies>` are scanned;
  an `<optional>` direct dependency is on its own module's classpath; an `activeByDefault`
  profile's properties override the main `<properties>`.
- Maven transitive resolution no longer seeds npm/PyPI/… records as Maven roots
  (`undefined:<name>` lookups sent to Maven Central and mirrors).
- Gradle: `constraints { }` entries and `force(...)` are version constraints, not direct
  dependencies (a constraint is a floor, a force a pin); `exclude(...)` (per dependency and
  per configuration) is applied; the widest scope wins whatever the declaration order;
  `gradle.lockfile` entries are not re-walked as resolution roots; `-e` matches the groupId;
  in a hybrid Maven + Gradle tree one build tool's record no longer overwrites the other's.
- yarn (v1 and Berry) and pnpm: dependencies are classified from the lockfile graph —
  transitives are transitive (with their `via` chain), dev is dev only when reachable solely
  through dev dependencies. Dev-only CVEs no longer trip `--fail-on`.
- npm aliases (`string-width-cjs` → `string-width`, `npm:` specifiers in package-lock v1/v3,
  yarn, Berry, pnpm) are scanned under the REAL package name; CVEs of the real package were
  never queried.

- Local OSV database (`--osv-db`): range events are evaluated in sorted order per the OSV
  schema (unsorted events gave false positives and negatives), and `limit` events are honoured.
- Source merging is alias-symmetric: a GHSA-keyed finding and a CVE-keyed one carrying that
  GHSA as an alias (or sharing any alias) are one finding, in either arrival order.
- Packagist advisories: the Composer constraint evaluator follows composer/semver — `^1.0`,
  `~1.2`, `1.2.*`, `<2.0` exclude 2.0 pre-releases; `1.2.3-p1 > 1.2.3`; `< 3.4.6` (spaced
  operators) parses; a `composer.lock` package at a pre-release/patch version is checked
  instead of silently skipped.
- NuGet `packages.lock.json`: `CentralTransitive` entries are transitive, not direct; Direct in
  any target framework / project wins; `Project` references are never scanned as packages.

### Changed
- Relicensed from MIT to Apache-2.0 (`LICENSE`, `package.json`).

## [2.7.0] - 2026-09-24

### Fixed
- Preserve GitHub advisory pagination through shared and local caches; refetch old
  cached pages without pagination metadata.
- Prevent abandoned batch reservations when an overlapping request encounters
  upstream failure backoff.
- Route SPIP's NVD product query through the provider cache and server credentials.
  Exclude non-vulnerable context CPEs and different product names; retain UNKNOWN
  severity when NVD provides no score.
- Preserve CMS snapshot collection dates through cache reuse and check live
  coverage against `--max-advisory-age`; fingerprint all GitHub advisory pages.
- Exclude generated CMS review reports from the npm package.

- Bound proxy transfers with deadlines, backpressure, concurrency limits and an
  evicting metadata/body/spool quota; protect readers and clean orphaned files.
- Merge CMS snapshots by collection date and publish imported semantic cache
  entries atomically, preserving the old entry if publication fails.
- Add `--wordfence-live` for scans and anonymized warming using server credentials.

### Documentation
- Document the remaining dependency advisory coverage gate limitation.
- Update npm description and CMS/framework keywords; remove development plans,
  reviews, handoffs and specifications from version control.
- Align CMS detection, SPIP warming, data-source and credential documentation with
  implementation; use `npm ci` for contributor setup.

### Added
- Optional Excel `.xlsx` export (`--report-xlsx [file]` or `-r xlsx`) with a summary and separate sheets for populated findings, inventory, application ownership, coverage, warnings, provenance and baseline diff. Numbers and booleans stay typed; advisory text is never interpreted as a formula. The workbook uses the same findings model as JSON and joins `SHA256SUMS` when enabled.
- **Same command, same options, same results online and air-gapped.** The 3-phase air-gap workflow now covers every CMS/framework lane with no extra flag: `fad-checker -s <proj>` online and `fad-checker -s <proj> --offline` in the enclave produce identical reports once phase 2 has run. Three pieces close the loop. (1) The anonymized descriptor (`fad-deps/1`) gains an `applications` section — public product identities only: application type, core version, and the inventoried **public** component identities (private components never leave; a module/theme is inventoried from its `.info.yml` without ever appearing in the lock). (2) `--import-anonymized` **warms every CMS advisory snapshot from the descriptor alone** (`lib/cms-snapshot-warm.js`): the Drupal feed for the union of the lock's `drupal/*` coordinates and the inventoried public identities — the exact set the live source queries —, the PrestaShop/TYPO3 repository feeds (coordinate prefix **or** declared application: an install's lock may hold none of the publisher's own packages), one WordPress checksums reference per declared core version (pinned by the warming run's `--wp-checksums-locale`), and the Wordfence catalogue when the warming machine holds an API key (the key itself never travels; the enclave reads the snapshot back without one). Each fetched snapshot is validated with its provider's schema before being written, so a shape change fails online instead of aborting the enclave. (3) The runner consumes those cached snapshots automatically **in every mode** — the lanes a scan runs are a function of the cache state, not of online/offline — with an explicit flag or live URL always winning, the fallback only engaging when the source's application plugin is selected, and the same schema/`--max-advisory-age` validation as an operator-supplied file. Auto-consumed snapshots report `completeness: "tool-fetched"` with the stamp's `sourceUrl`/`collectedAt` (`localSourceSnapshot` in `lib/application-plugins/wave2-common.js`); an explicit flag still reports `operator-declared`. Previously an offline phase-3 that skipped `--drupal-advisories`/`--wp-checksums` silently lost those lanes (measured: 84 vs 105 CVE on the CMS fixture), and a coordinate-only warming missed advisories of inventoried-but-not-locked modules (webform: 21 CVE). End-to-end on the fixture (Drupal 10.1.0 + WordPress 6.4.2, fresh offline Docker, pure 3-phase workflow, zero CMS flags): both scans report 105 CVEs, byte-identical findings and coverage — the only residual diffs are `generatedAt`, the runtime/mode provenance lines, and `fileModifiedAt` millisecond truncation from the tar transport. Wordfence without a key anywhere stays honestly `not-run`. Tests: `test/offline-snapshot-reuse.test.js`, `test/cms-snapshot-warm.test.js` (warming per source, union query set, keyless skip, loud failure, per-version checksums, Wordfence reuse without a key).
- **SPIP support** — the ninth CMS/framework instance view (`lib/application-plugins/spip.js`, auto-activated). Detection is conjunctive (`spip.php` + `ecrire/inc_version.php` with a readable `$spip_version_branche` — a bare `require "spip/spip"` never creates an application); inventory covers the core (observed version), the official `plugins-dist/` set (`paquet.xml`) and user plugins (`paquet.xml` or legacy `plugin.xml`), with private paths kept separate. The advisory lane is the one machine-readable SPIP source that exists: SPIP has no publisher API and no package ecosystem (`spip/spip` 404s on Packagist, no GHSA — hosted on git.spip.net, blog.spip.net publishes prose), so the core is assessed against **NVD's versioned product CPE** (`cpe:2.3:a:spip:spip`, 69 CVEs; `--spip-advisories[-live]`, optional NVD API key lifts the rate limit) using the same `matchVersionRange` primitive as the report's CPE cross-check; SPIP *plugins* have no advisory source anywhere and their rows say so honestly. Measured end-to-end on the official SPIP 4.4.24 release: a clean core reads `completed / no-match` (a stated result), a 4.1.2 core matches 10 CVEs (3 critical — CVE-2023-27372, CVE-2024-8517…). The full air-gapped loop works with no flag: the descriptor carries `{type: "spip", version}`, phase 2 warms the NVD snapshot, the offline phase 3 auto-consumes it with the same online-identical results. Tests: `test/application-spip.test.js` (conjunctive detection, paquet/plugin.xml inventory, NVD range assessment, per-plugin honesty, live/local/warmed reuse, unconfigured not-run).

### Changed
- The report's four overview donuts render **20% taller** (`lib/charts.js`, donut radius 47 → 56.4; every vertical coordinate derives from the radius, so the card scales cleanly and the Word/PNG export follows through the viewBox).
- The report's application-findings chapter is titled **"CMS & Frameworks"** (French: "CMS & frameworks") instead of "Applications" — it covers CMS instances and frameworks alike, and the TOC/numbering follow. The XLSX sheet keeps its `Applications` name (it is the machine-readable inventory, not the chapter).
- **A detected CMS/framework keeps its chapter even at zero findings.** The "CMS & Frameworks" section now renders whenever an application was inventoried (or a finding references one — an orphaned exposure is never dropped): the instance synthesis — version, direct/indirect counts, worst priority, coverage lanes — always shows, with a "No application CVE on the inventoried instances" intro (French: "Aucune CVE applicative sur les instances inventoriées…"); only the Production/Dev CVE tables wait for findings. Previously a zero-finding instance left the chapter out entirely (2.6.0’s "populated subsections only") and the instance was visible only through the inventory & coverage chapter — measured on the regenerated corpus: Magento 2.4.7-p3 (1 application, 0 CVE) now shows "1.1 CMS & Frameworks (0)" with its synthesis.
- **Every CMS finding now carries its fix version, and component versions are visible wherever the finding is named.** The Wordfence and PrestaShop/TYPO3 lanes already set `fixVersion` from the publishers' patched releases; the two lanes that could not now derive it honestly: Drupal advisories publish an affected *range* with disjoint branches ("X || Y"), so the fix is the smallest exclusive upper bound above the observed version (measured: drupal:core 10.1.0 → fix 10.1.8 for CVE-2024-11941, 10.5.12/10.6.13 for the 2026 SA records) — a wildcard-only branch stays `—` rather than inventing a patch level; SPIP's NVD ranges carry `versionEndExcluding`, which IS the fix ("affected < 4.1.10" → 4.1.10). In the report, the per-instance group headers of the "CMS & Frameworks" chapter now carry the owning component's observed version ("core Drupal 10.1.0", "plugin Acme Internal Checkout 2.3.0 (private)") next to the counts, and the Fix Version column of every CVE table (already rendering for wordfence/prestashop/typo3 findings) now fills for drupal and spip too. The installed version was already shown in the Dependency column of every CVE table, the instance synthesis (core), the inventory & coverage chapter (per component) and the executive summary's fix line.
- **Framework coverage no longer implies a gap it cannot fill.** A Symfony or Laravel instance used to report `advisories: not-run (0/155 — CMS_ADVISORY_NOT_QUALIFIED)` — reading like the scan could have done more. It cannot: neither framework publishes a machine-readable advisory feed, and their inventoried components ARE Composer dependencies whose advisory evaluation is the report's own dependency lanes (OSV.dev, Packagist security-advisories, NVD). The coverage row now says exactly that: `advisories (dependency-lanes): completed (155/155)` — no fake "Evaluation incomplete" flag on a clean framework scan (a zero-finding instance reads "No matching advisory in the consulted data"). Joomla and Magento follow the same principle per component (see the next entry). The CMS-style publisher lanes (Wordfence, Drupal, PrestaShop, TYPO3) are unchanged.
- **Joomla/Magento advisory coverage is now per component, same principle as Symfony/Laravel.** `finishInventory` no longer emits one blanket `not-qualified` row: a component whose coordinate is a Composer dependency the report's dependency lanes actually scanned (lock pin or best-effort manifest) reads `advisories (dependency-lanes): completed`; private components keep their `internal-advisories` row; only a component with no advisory source anywhere — a source-only extension with no dep record — keeps the honest `CMS_ADVISORY_NOT_QUALIFIED`. Measured: the corpus Joomla 5.4.1 (a composer-installed tree) reads its ~100 locked components as dependency-lanes-covered with the core + file extension honestly not-qualified; a locked Magento site reads product and modules covered; the Magento source archive keeps its three not-qualified rows (nothing scanned the product coordinate — true, not a gap the tool could fill).
- **A Magento source distribution reports its exact product version.** The core version was read only from the composer.lock pin — a source archive ships no lock, so the report showed `— / CMS_VERSION_UNKNOWN` and a partial inventory (measured: the corpus Magento 2.4.7-p3 source read `inventory: partial (2/3)`). The root `composer.json` of a source distribution carries the exact product version (`"version": "2.4.7-p3"`): it is now read as observed evidence, the missing-lock alarm is not raised for a tree that is the product by construction, and the corpus line reads `Magento Open Source 2.4.7-p3, inventory: completed (3/3)`.

## [2.6.0] - 2026-09-23

### Fixed
- Report subsections now appear only when populated and are numbered from the sections actually present; the contents bar uses the same list. CMS/framework CVEs lead chapter 1 when found, while a zero-finding application remains in the scan-context inventory and coverage. Report files now preserve application ownership relations through the writer.

### Added
- **Shared persistent proxy-cache server** (`fad-checker serve-cache`, `lib/proxy-cache.js`, scan-side `--proxy-cache <url>`): a long-running server that turns one machine into the cache point for every other instance — one upstream call per URL per TTL for the whole fleet, single-flight coalescing (10 concurrent identical lookups → one upstream call), stale-while-revalidate (`--no-swr` for a blocking refetch) and stale-if-error (a 403/429/5xx upstream serves the stale copy; a definitive 404 is mirrored as-is — that is how private packages are detected). The store persists in its **own root** (`~/.fad-checker-proxy-cache/`), deliberately outside the scan's `~/.fad-checker/` caches so `--export-cache`/`--import-cache` never bundle or swap the two together; only fad's public data sources are cached (private registries pass through uncached, credentials included, and never leave the scanning machine when a client uses `--proxy-cache`). Per-source TTLs mirror the client's (OSV 12h, NVD/endoflife.date 7d, rest 24h; `--ttl` overrides), bodies over `--max-body-mb` (default 32 MB — the CVE bulk zip is ~500 MB) stream through uncached, `GET /__stats` + `POST /__clear` manage the base, `--token` guards it when bound on `0.0.0.0`. **API keys are held by the server, not the instances**: `--nvd-key` / `--wordfence-key` / `--github-token` (flags > env > `--set-nvd-key` config) are injected upstream with each source's wire format, so a keyless instance shares the server's quota; without a server key the client's own credential is forwarded; a server key overrides a client's. **Corporate proxy support**: `--proxy <url>` on a scan and `--upstream-proxy <url>` on the server route all outbound requests through a forward proxy — Node only honours `HTTP(S)_PROXY` with `NODE_USE_ENV_PROXY` set at process start (verified: a mid-run `process.env` change is silently ignored), so fad re-execs itself with the environment applied; a `--proxy-cache` URL in the same command is added to `NO_PROXY` so local cache traffic stays out of the tunnel. Measured end-to-end on the npm fixture: a second instance with a cold local cache made 2 upstream calls instead of 16 (15 served from the shared base). Load-tested against deps.dev v3 (the source a future package-health lane would use): 200s at 440 req/s from one client, p50 ≈ 40 ms, zero 429s; the Scorecard lives behind `/v3/projects/{url-encoded projectKey}` (raw slashes 404).
- **A present CMS/framework is activated by the default `--app-plugins auto`** (user decision, 6e session, superseding the session-1 opt-in rule): any recognized layout is inventoried automatically, qualified or still experimental; `--app-plugins none` opts out and `all` remains an explicit synonym. This matches what the ecosystems' own tools do — `composer audit` audits the lock of the current directory, OSV-Scanner `scan -r .` sweeps every lockfile it finds, Trivy `fs .` auto-detects every language present, Snyk `test` auto-detects the project, `drush pm:security` bootstraps the site it is in; the single counter-example (WPScan's 2026 pull-back of automatic plugin enumeration) is a cloud-API quota economy whose detection of the CMS itself stayed automatic (comparison documented in `docs/COMPARISON.md`). fad's split carries the same logic without the constraint: local inventory is automatic, the networked advisory sources stay behind their explicit configuration and an unconfigured lane reports `not-run (CMS_PROVIDER_UNCONFIGURED)`, never a clean result. False positives were the acceptance question and were checked three ways: every plugin's detection is a conjunction of positive physical markers (WordPress `wp-load.php` + `wp-includes/version.php` + `wp-admin/index.php`; Symfony a kernel/front-controller marker *and* `symfony/framework-bundle` in that tree's lock; Laravel `artisan` + `bootstrap/app.php` + the framework requirement; Drupal the core `Drupal.php` + `core.services.yml` pair, or the literal 7.x `VERSION` define for Drupal 7; etc.), so a bare `require` constraint never creates an application; the real corpus (four wave-1 repositories + four publisher extracts) scans as exactly 8 applications with no phantom; and real bare PHP libraries (guzzle/guzzle, laravel/framework as a package, the symfony/symfony monorepo, composer/composer) scan with zero applications. The `CMS_PLUGIN_UNQUALIFIED` announcement diagnostic is gone with the gate it announced.
- **Publisher GitHub advisory lanes for PrestaShop and TYPO3** (`lib/application-providers/github-advisories.js`, `--prestashop-advisories[-live]`, `--typo3-advisories[-live]`): the machine-readable channel those publishers maintain themselves (verified 2026-09-23: 61 and 97 live advisories; joomla/joomla-cms and magento/magento2 have empty feeds — their bulletins stay HTML, those lanes stay `CMS_ADVISORY_NOT_QUALIFIED`). The whole repository feed is fetched once per scan (Link-header pagination, loud failure on runaway pages) and matched per inventoried composer coordinate. The publishers' range spellings are normalized in the lane only — the shared Packagist/Drupal evaluator is untouched: PrestaShop's "and" means two affected branches when every clause is an upper bound (`< 8.2.6 and < 9.1.1`, two patched versions) but one interval otherwise (`>= 8.0.0 and < 8.1.1`); TYPO3's comma-joined hyphen intervals (`13.0.0-13.4.33, 14.0.0-14.3.5`) are alternative branches — with Composer's AND they describe an empty set and every real advisory silently became a false negative. The ~30 2020-era PrestaShop records whose `package` identity is empty in the official feed are attributed to the PrestaShop core coordinate (documented inference; records without a fallback surface as one `CMS_ADVISORY_UNATTRIBUTABLE` diagnostic, never as silence), and their lossy unbounded ranges ("> 1.7.0.0") are decided through their `patched_versions` bound: a version at or above the publisher's patched release is fixed — PrestaShop 8.2.1 finds its 10 real advisories (fixes 8.2.3–8.2.8) and none of the 2020 false positives; 8.2.8 finds none. Real-feed assertions are gated behind `FAD_REAL_INSTANCES=1 node --test test/wave2-real-instances.test.js`.
- **WordPress core file-integrity capability** (`lib/application-providers/wp-checksums.js`, `--wp-checksums <file>`, `--wp-checksums-live [url]`, `--wp-checksums-locale <locale>`): compares the WordPress core files of every inventoried instance against the official api.wordpress.org checksums reference pinned to the observed core version and locale. Modified, missing-from-the-tree and extra files are three different results, all **diagnostics, never CVE findings**: `CMS_FILE_MODIFIED` (differs from the official distribution), `CMS_FILE_MISSING` (a source checkout is not the distribution archive — the four default akismet files ship only in the tarball — so this does not flip the verdict), `CMS_FILE_EXTRA` (an unexpected file inside `wp-admin/`/`wp-includes/`, the controlled perimeter; `wp-content/` is user land and never flagged). Verdict `affected` only on modified or unexpected core-directory files; a reference pinned to another version (`CMS_CHECKSUMS_REFERENCE_MISMATCH`) produces no verdict rather than fake divergences; per-code diagnostic lists are capped with an honest truncation notice. Measured on the real WordPress/WordPress 6.4.2 git tree: 2960/2960 reference files conforming (`completed / no-match`), and one appended comment in `wp-load.php` flips to `affected` naming the file — both asserted in the gated real-instance suite.
- **Application-provider findings now merge through the alias-aware source seam** (`mergeBySource`): a publisher constat the standard Composer lane already found — measured on the official TYPO3 v13.4.2 extract, where the Composer lane reads the exact pin `typo3/cms-core: 13.4.2` in `typo3/sysext/seo/composer.json` while the publisher lane reads the observed core marker — becomes ONE finding with the union of its sources (`github-typo3-advisories+nvd+osv+packagist`) instead of two duplicates; the publisher's fix version travels with the merge and application attribution is rebuilt from the physical occurrence. Findings the standard lanes cannot see (Drupal core, the WordPress catalogue) pass through intact. The source-label union is now over source tokens, so absorbing a second Packagist constat renders `osv+packagist`, not `osv+packagist+packagist`.
- The gated real-instance suite now also drives `--wp-checksums-live` on the real WordPress tree (pristine conforming + tampered affected, restored afterwards), and a new gated wave-2 suite downloads the official PrestaShop 8.2.1 and TYPO3 v13.4.2 release archives, reduces them to the documented marker files, and asserts the live publisher feeds end to end (GHSA-xrwj-pq6w-f8m4 fixed 8.2.8 and CVE-2026-44212 fixed 8.2.6 present on 8.2.1 with completed/affected coverage; no 2020 false positive; CVE-2026-19418 within `13.0.0-13.4.33` on 13.4.2 with fix 13.4.34; `typo3/cms-seo` an honest `no-match`).
- Experimental Joomla, PrestaShop, TYPO3 and Magento/Adobe Commerce application inventories, explicitly selected through `--app-plugins`. They use static, bounded reads of publisher-defined manifests and the Composer lock; report unknown versions, missing locks and unqualified application advisory coverage instead of inventing clean results. Magento retains the exact product `-pN` version and edition from the lock.
- **Packagist security-advisories lane for Composer** (`lib/packagist-audit.js`, default-on, `-d packagist-audit` to disable): queries the endpoint `composer audit` itself queries, then evaluates the official constraints per locked version. Found by benchmarking the real-instance corpus against `composer audit` 2.10.3 (2026-09-23): OSV carries twig/twig CVE-2026-46636 + CVE-2026-46627 and knplabs/knp-snappy CVE-2026-46643 only as CVEProject entries with GIT/CPE ranges and no composer coordinates, so a package+version OSV query can never return them — fad reported 3 fewer advisories than the official tool on drupal 8.5.0, symfony-demo v2.6.0 and BookStack v24.10. After the lane: exact parity on all three trees (68/68, 62/62, 64 unique of audit's 65 — its 65th is its own duplicate of GHSA-5vg9-5847-vvmq), zero duplicate findings. The evaluator covers the Packagist constraint grammar (`|`/`||` branches, AND by comma/space, `^` `~`, `X.Y.*` wildcards, partial versions, hyphen ranges; an unparsable token is `null` — undecidable, never a guess). Only package NAMES travel to packagist.org, exactly like the existing registry pass; under `--offline` the lane reads the warm per-package cache (`~/.fad-checker/packagist-advisories/`, 24 h TTL online, age ignored offline like OSV/NVD) and makes zero network calls — locked by tests.
- **Alias-aware source merging** (`lib/merge-sources.js`, extracted from `fad-checker.js` to be unit-testable): the same advisory can arrive keyed by its CVE from one source (OSV prefers the CVE alias) and by its GHSA remoteId from another (Packagist records with no `cve` field — league/commonmark GHSA-8rr7/jjv6/j8pm/c2pc on the real corpus). The merge now resolves collisions through `aliases` + `ghsa` instead of emitting the advisory twice; the existing finding keeps its primary id, severities prefer non-UNKNOWN, and the merged aliases are the union.
- Drupal advisory constraints with the API's `X.Y.*` wildcard branches (`11.2.*`, `11.0.*`, seen on SA-CORE-2026-010/011/012) are now **decided** — a version outside the branch is `no-match` — instead of sinking the whole advisory into `CMS_CONSTRAINT_UNSUPPORTED`. The live scan of the real drupal/drupal 8.5.0 tree moved from `partial / indeterminate` coverage with a constraint diagnostic to `completed / affected`; the wildcard grammar is asserted against the official API's real published constraints.
- The gated real-instance suite now drives `--drupal-advisories-live` and asserts the **full official record** for drupal/core 8.5.0 (15 advisories as of 2026-09-23, incl. the CVE-less SA-CORE-2023-* wave keyed by advisory id) — the offline corpus's 1-advisory operator snapshot can no longer pass as the authoritative coverage. The reduced WordPress fixture now contains only CVE-2024-31210 for 6.4.2; the vendor fixed CVE-2024-31211 in 6.4.2, and the test asserts its absence. The fixture is not a completeness check for the full Wordfence feed.
- Experimental application inventory for Symfony, WordPress (classic and Bedrock), Drupal (Composer and Drupal 7), and Laravel, with explicit `--app-plugins` selection, private component paths, coverage records, and Composer CVEs attributed to their physical copies and owners. HTML/Word, JSON, SARIF, SBOM, CSAF, and baseline diff carry occurrence context. Local Wordfence v3 and Drupal Composer advisory snapshots assess eligible public components; private extensions and unqueried packages retain incomplete coverage.
- `--max-advisory-age <duration>` bounds the age of configured advisory snapshots; the collection date must be declared inside the snapshot file (top-level `collectedAt`/`generatedAt`, or the reserved `_fadSnapshot.collectedAt` key tolerated by the Wordfence v3 feed). Undeclared, malformed or stale snapshots exit `2` before any report. A declared date also enriches coverage provenance (`sourceSnapshot.collectedAt`).
- Live advisory sources: `--drupal-advisories-live` queries the official packages.drupal.org security-advisories API for the inventoried public `drupal/*` packages (private components are never sent); `WORDFENCE_API_KEY` or `--wordfence-api-key` authenticates the official Wordfence v3 production feed; `--wordfence-feed-url` can override the endpoint. Fetched snapshots are stamped with their collection date, validated with the same schema as local files, and cached atomically under `~/.fad-checker/advisory-snapshots/`. Both refuse `--offline`, still require their `--app-plugins` selection, and fail the scan (exit `2`) on an unusable response.
- The application CVE section opens with an instance synthesis: one row per application instance — CMS, path, observed core version, direct/indirect/unknown-origin counts, worst priority, per-capability coverage and an explicit note for instances without findings ("no matching advisory in the consulted data" vs "evaluation incomplete"). Instances without any finding remain listed in the scan-context inventory and coverage. Full French translation included.
- Fix: a Drupal 8+ tree was misread as an extra, phantom Drupal 7 application — Drupal 8 ships `core/includes/bootstrap.inc` and `core/modules/system/system.module` too. Drupal 7 discovery now requires the 7.x `VERSION` define in `bootstrap.inc` as positive content evidence (found by scanning the real drupal/drupal 8.5.0 repository).
- Opt-in real-instance integration tests (`test/real-instances.test.js`, `FAD_REAL_INSTANCES=1`): clone WordPress/WordPress 6.4.2 (CVE-2024-31210), drupal/drupal 8.5.0 (SA-CORE-2018-002 — a lockless source tree must stay unproven, never acquitted), symfony/symfony-demo v2.6.0 (http-foundation v7.1.1, CVE-2024-50345) and BookStack v24.10 (laravel/framework 10.48.22, CVE-2024-52301), and verify detection, inventory, honest coverage and CVE attribution on the real trees.
- Drupal core version now corroborates the on-disk `core/lib/Drupal.php` `VERSION` marker: with no composer.lock (a git clone is a source tree), the observed version carries `versionStatus: "observed"` with its file evidence and real advisories are assessed instead of dead-ending at `CMS_VERSION_UNKNOWN`. A divergence between the lock and the marker keeps the lock as the installed-version authority and reports `CMS_VERSION_CONFLICT` with both values, marking the inventory coverage partial. Found by reviewing the report of the real drupal/drupal 8.5.0 scan.
- Instance-synthesis readability: the observed-version column falls back to the framework component for Symfony/Laravel instances (which have no core), and the coverage cell names the source lane (`advisories (wordfence-v3): completed`, `advisories (application-advisories): not-run (CMS_ADVISORY_NOT_QUALIFIED)`) so a completed standard SCA is never read as "nothing was checked". The gated real-instance suite now also runs a live OSV scan asserting CVE-2024-50345 and CVE-2024-52301 on the real trees.
- Drupal application discovery requires positive content evidence: standalone component scans validate `.info.yml` types and legacy `.info` name fields instead of trusting file names, announce `CMS_INFO_INVALID` for false markers, and a component scan that recognizes nothing is announced (`CMS_COMPONENT_NOT_RECOGNIZED`). Submodules of a distributed project inherit its advisory identity as `probable` with `parentComponentId`.
- Symfony Flex `symfony.lock` recipe context and extraction mirroring; Composer lock versions remain authoritative.
- `-t/--target` refuses a non-empty directory without `--force`, and always refuses source overlap and symlink targets.
- **`--lang en|fr`: the HTML/Word report in French — the whole report.** Not just the
  headings: chapter titles and the counts inside them, every table header, the scope chips
  and the "defined in / version managed by / pulled in via" footers, the CVE detail panel
  down to its reference categories, every chapter's intro paragraph, every status pill
  (`intact`, `devrait être géré`, `nom≠empreinte`, `🔑 CLÉ PRIVÉE`, …), the scan-warning
  headings, the licence categories, the eight methodology limitations, the per-ecosystem fix
  recipes, the empty states, the executive summary on screen AND the one the 📋 button
  pastes into Word — plus the 189 CWE titles it ships. The `<html>` element now declares its
  language, so Word and screen readers hyphenate and spell-check in the right one.
  Text that comes from a data source is deliberately NOT translated: a CVE description, an
  advisory summary or a registry deprecation reason is evidence, and paraphrasing evidence in
  an audit report is wrong. By the same rule a CVSS severity stays in NVD's own vocabulary
  wherever it is a finding's value — the badge, the priority band — while the labels around
  it are French. MITRE publishes CWE in English only, so the French titles are fad's own and
  MITRE's original travels with every one of them (tooltip in HTML, parentheses in the
  `.doc`) — otherwise a reader could not find on cwe.mitre.org what the report just told
  them. A translation may carry both plural forms, picked by the count, because French
  inflects where English does not ("1 obsolète", not "1 obsolètes"). English is unchanged,
  byte for byte, by construction: the English string is the translation key — and the suite
  now checks the catalogue and the source agree in both directions, so a new string cannot
  ship untranslated and a retired one cannot linger as dead weight for a translator to read.
- **A data source that goes dark now stops the run instead of quietly shrinking the report.**
  Online, a lookup that gets no usable answer is retried 5 times waiting 5+n seconds (6 → 10),
  each attempt logged; the schedule is shared per source, so a dead host costs one schedule and
  not one per dependency. If it never comes back the run stops **before writing anything** and
  prints the domain, the HTTP/transport codes, the first failing URL and the flag that disables
  that source, exiting **2** — distinct from the `1` that `--fail-on` uses, so CI can tell
  "vulnerabilities found" from "this scan is not trustworthy". A source whose warm cache covered
  every lookup stays completely silent: no request was issued, so there is no hole. A definitive
  404/410 is an answer, not an outage — it is how private packages are detected. `--offline`
  never aborts. New `--no-eol` so endoflife.date, which had no opt-out, has one to suggest.
- **A bare `fad-checker` answers instead of erroring.** Typing the name alone is a question —
  what is this, which version do I have, how do I run it — and "required option '-s, --src'
  not specified" answered none of it. It now prints a mini help: the banner with the running
  version, the ecosystems covered, and three real invocations (full report, `--offline`,
  `--fail-on` gate). Exit stays non-zero: nothing was scanned, so it must not read as a clean
  run to a job that mis-invoked it. `--help` gained the same version header, for the same
  reason a report carries one — someone reporting a bug should not have to hunt for it.
- **The report links back to the project.** The `fad-checker <version>` line in the HTML /
  `.doc` report header is now a link to the repository. A report is a hand-over artifact:
  someone who receives only the file has to be able to find the tool that produced it — its
  version, its docs, its issue tracker — without asking whoever ran the scan.

### Changed
- **Table headers wrap at spaces, never mid-word** (`thead th { word-break: normal }`). The shared `th, td` rule's `word-break: break-word` let a table's intrinsic-sizing calculation crush a column to a few characters, so a two-word header ("Version corrigée") wrapped to SEVEN lines — measured with a layout engine at a 173px header row, taller than every data row, on the regenerated drupal corpus report; the same mechanism had the vendored-JS header at 185px. Headers are now bounded by their word count and the row stays minimal (29px, one line, on every table of the real corpus reports).
- **The second application donut reads "Indirect CVEs per direct dependency"** (FR « CVE indirectes par dépendance directe », renamed from "per introducing component" at review): the grouping is unchanged — indirect CVEs counted under the direct dependency that introduces them, which is also the thing to bump — but the title now says what the reader is looking at.
- **The vendored-JS vulnerability chapter is one row per physical library, not per advisory.** A vendored file usually carries several advisories (jQuery 1.8.3 alone has two CVEs) and the old flat table made one physical library read as many findings. Each library row now carries the two cells an operator scans first — the linked CVE identifiers (NVD for CVEs; a CVE-less identifier links to the advisory's own source URL, never to a page that cannot know it) and the CWEs when known — plus the advisory count; clicking the row expands a nested sub-table with every advisory (severity, identifier, fix version, summary), using the same cve-row/detail-row interaction as chapter 1 so the toggle needs no new script. The `.doc` variant force-opens every sub-table — Word cannot click. Retire.js itself carries no CWE data, so vendored-JS findings now join the same NVD enrichment as the composer/npm findings (per-CVE cache, only CVE-shaped ids queried), which also upgrades retire's one-line summary to NVD's canonical description. Found while reworking the chapter: the identifier LIST cell must not reuse `td.cve` — its blanket nowrap put a 20-advisory library on one 4280px line (retire's CVE-less advisories fall back to prose sentences), blowing the table out to 7× its container; the list is its own class, each real identifier stays unbreakable, and a prose fallback wraps like the text it is.
- Removed the `php-runtime-undetermined` chapter-0 note and its French wording: a deployed
  PHP runtime is not a manifest property, the note fired on virtually every source tree
  (23 of them on the real drupal/drupal scan alone) and drowned the actionable warnings.
  The PHP runtime verdict is unchanged: a finding is still emitted when a declared
  constraint proves an EOL runtime; an undeterminable runtime is simply silent now.
- **BREAKING-ish — `--help` is one screen: the long tail folds into `-d` / `-a` / `-r`.** It
  had reached 176 lines and eighty options, thirty-six of which were a `--no-<something>` or
  an opt-in switch. Now `-d eol,nvd` turns things off, `-a licenses,snyk` turns on what is off
  by default, `-r html,json` picks the outputs and `-o` is the output directory. The folded
  flags **still work** — they are hidden from the help, not removed, so no existing script
  breaks — and `--help-all` prints them. The cache, registry and configuration commands are
  hidden the same way: they manage the tool, not a scan. An unknown token is a hard error, not
  a silent no-op, because a dropped `-d nvd` would produce a report claiming coverage the run
  never had.
- **Default outputs are now HTML + `findings.json`, not HTML + `.doc`.** The JSON means the
  next run has something to `--baseline` against without anyone having to remember a flag.
  `--report-doc` still writes the Word file for those who want it.
- **The pinned chapter bar is one row of equal, centred cells**, and chapter 3 is now
  **Maintenance / EOL**. Sub-chapters used to sit inline behind a `›`, so a full report listed
  sixteen links and the sticky bar wrapped onto two rows — a third of the viewport, on every
  scroll. Each chapter that has sub-chapters now reveals them on hover or keyboard focus,
  using CSS only: a nav that needs JavaScript to open is a nav that silently stops working in
  a report someone opens from a mail attachment. The bar is also divided into equal cells now, one per chapter and centred in it, so its shape no longer depends on how many findings the report happens to contain.
- **The merged priority cell reads as four labelled lines**, and the CVE table's widths were
  rebalanced around it: band + KEV, severity + CVSS score, then `EPSS: 100%` and
  `Published: 2021-12-10`. The last two are labelled because neither a bare percentage nor a
  bare date has a column header of its own any more. Four short lines need less width than
  three long ones, so Priority/severity gives 15% back, Fix Version and Source 10% each,
  Dependency takes a little more, and every point freed goes to Description — the only column
  whose content is prose.
- **A finding now says which MODULE ships it, not which file declares it.** The "defined in"
  footer showed up to three descriptor paths; it now shows up to two module names —
  `dubbo-dependencies-zookeeper` rather than
  `dubbo-dependencies/dubbo-dependencies-zookeeper/pom.xml` — with the path kept as the
  tooltip. Names are read per ecosystem: Maven artifactId (with the `<parent>` block stripped
  first), package.json / composer.json name, go module, pyproject name, .NET AssemblyName /
  PackageId / file name, Gradle `rootProject.name` or the directory, and a Ruby `.gemspec`
  beside a `Gemfile.lock`. `requirements*.txt` and `Pipfile` genuinely name nothing and keep
  falling back to the path rather than having a name invented from their directory. That cell
  was also what made the Dependency column wide, so its width went to Description.
- **The report no longer scrolls sideways, and the CVE table lost three columns.** A table's
  minimum width is set by its longest unbreakable token — a Maven coordinate is one — and
  chapter 1's nesting removes ~30px per level, so the document ran 495px wider than the
  viewport. Long tokens now break (only in the columns that hold them: a CVE id or a severity
  badge is never chopped mid-word), any residue scrolls inside the table instead of the page,
  and the inset flattens past the second level. Measured at 0px overflow from 768px to 1600px.
  Priority, Severity and Published are merged into one three-line cell — band + KEV, severity +
  CVSS, then EPSS + date — which returns their width to Description and Dependency. Both Word
  paths were updated with it: the `.doc` stylesheet and the clipboard's inline-style pass.
- **Overview chart 3 is now "Most vulnerable components".** It ranks the scanned project's
  OWN modules — Maven artifactId, package.json / composer.json name, go module, pyproject
  name, else the path relative to `--src` — by their count of **critical + high** production
  CVEs, so the reader learns which module to open first. It replaces "Direct vs transitive",
  which said where risk sits in the dependency graph but never which part of *your* tree
  carries it. A finding declared in several modules counts in each, because each one ships
  it. On a scan with a single descriptor there is nothing to rank, so that slot keeps the
  direct-vs-transitive donut unchanged. Module names come from the descriptors the codecs
  already parsed; a pom's `<parent>` block is stripped before reading its artifactId, or
  every module of a Spring Boot reactor would be labelled `spring-boot-starter-parent`.
- **BREAKING — `-v` is now `--version`, not `--verbose`.** Verbose keeps its long form only.
  A script running `fad-checker -s . -v` for verbose output will now **print the version and
  exit 0 without scanning**, which reads as a pass: grep your CI for `-v` and use `--verbose`.
  `-V` still works (it was the version flag), aliased before parse because commander permits
  one short flag per option. `docs/USAGE.md` and the bash completion were updated with it.
- **`--import-cache` now MERGES instead of replacing the cache.** It moved the whole
  `~/.fad-checker/` aside as `.fad-checker.bak-<timestamp>` (or deleted it with `--force`)
  and unpacked the archive in its place, so an enclave that was already warm lost every
  cache entry the archive didn't happen to carry — and `--offline` on the resulting cold
  cache reports **0 CVE / 0 EOL / 0 outdated**, which reads exactly like a clean project.
  Worse, `--export-cache` deliberately never bundles `config.json`, so replacing the
  directory also wiped the target's **NVD key and private registry credentials**, silently.
  And each import left a full copy of the cache in `$HOME` (123 MB on a real one), never
  cleaned up — a weekly sneakernet refresh grew to gigabytes.
  The import now reconciles the two sides, per cache family:
  per-key file caches (`osv-cache/`, `nvd-cache/`, `poms-cache/`, `retire-cache/`,
  `retire-signatures/`, `osv-db/`) union file by file; `entries{}` maps (`version-`,
  `maven-exists-`, `npm-registry-`, `eol-`, `epss-`, `packagist-`, `pypi-`, `nuget-`,
  `go-proxy-`, `rubygems-`, `hash-id-cache.json`) union key by key, the fresher side winning
  a collision and the merged map stamped with the **older** of the two `fetchedAt` (a union is
  only as fresh as its stalest half — antedating it would let a TTL check treat stale entries
  as just-fetched); whole-corpus snapshots (`kev-cache.json`) and the atomic `cve-data/`
  (index + `meta.json` must describe the same build) take the freshest side as a block.
  `config.json` is never touched. A stale archive can no longer roll a fresher enclave back.
  `--replace` restores the old wholesale swap (with the `.bak`), `--force` still means
  "replace, no backup". Locked by `test/cache-archive-merge.test.js`.

- **`-t <dir>` is now an extraction step, not a scan.** It walks the tree, links the reactor
  modules, writes the cleaned POM tree + mirrored manifests, prints the Maven POM analysis
  (missing parents / private libs) and **stops**. Before, every `-t` run also went through the
  full CVE/EOL/outdated pass and wrote a report nobody asked for — minutes of "hang" on a
  large reactor, offline or not, for a step whose only job is to produce that tree. The
  scan still runs when something explicitly consumes it: `--snyk`, any `--report-<type>`,
  `--fail-on` / `--fail-on-new`, `--baseline`. A read-only run (no `-t`) is unchanged.

### Fixed
- Composer's no-lock fallback no longer treats `4.4.*` or `1.0.x-dev` as an installed version. Packagist audit and public package metadata lookups skip known `repo.magento.com` packages instead of asking a different registry for an answer; the advisory scan reports the skipped scope. The progress total includes the PHP runtime phase.
- Corrected the WordPress 6.4.2 test feed: CVE-2024-31211 was already fixed in that version, and CVE-2024-31210 now uses the vendor's 7.6 CVSS vector. Wordfence live scans accept a bearer key via `WORDFENCE_API_KEY` or `--wordfence-api-key` and warn when the key or advisory source is missing.
- Packagist audit now rejects omitted packages, malformed responses and HTTP errors instead of treating them as clean; invalid legacy empty cache entries are revalidated. Composer caret and hyphen constraints follow the documented bounds, and `sources[].remoteId` participates in advisory deduplication.
- Drupal rejects an empty advisory array. Application sections keep distinct shared owner sets, and application charts use readable bars for overlapping categories.
- Removed a duplicated `validateSnapshot` declaration in `lib/application-providers/drupal-advisories.js` (the second, byte-identical copy silently shadowed the first; no behaviour change — dead code found during the official-tool comparison review).
- **Report reliability pass over the CMS/framework application layer** (driven by red tests on the observed defects, re-verified on the real WordPress/Drupal/Symfony/BookStack corpus):
  - The Drupal live source now queries the union of every instance's public packages: a second instance whose module was not part of the first query is fetched before its evaluation and merged — only responses actually obtained are merged, the disk snapshot holds the exact queried union with matching provenance, and the outcome no longer depends on discovery order (`CMS_PACKAGE_NOT_QUERIED` disappears). A required query that fails still exits `2` before any report.
  - A locally configured advisory source (`--wordfence-feed`, `--drupal-advisories`) is validated once before discovery — readability, size, JSON, provider schema, and freshness when `--max-advisory-age` is set — and the parsed snapshot is reused during assessment. An unusable source fails with exit `2` and no report even when no instance would have reached the file; a valid one is accepted with no matching instance.
  - The instance synthesis aggregates coverage per capability AND provider: a lane with any `failed`/`partial`/`not-run` check never reads `completed`, shows `executed/expected`, the number of unassessed components and the diagnostic counts, and an instance with a finding still carries the "evaluation incomplete" note when its lanes are incomplete (WordPress 6.4.2: 1 core assessed, 14 themes not — the lane reads partial, not completed).
  - Coverage is actionable and translated: every 6.4 coverage row names the component it is about (kind, name, path, occurrence id); chapter 0 groups identical coverage gaps into one navigable block per cause (application, capability, source, diagnostic) with count, expected action and the affected component list, instead of 14 identical raw messages; capability, lane, execution and result labels are translated in the French report while `CMS_*` codes and `sourceId` stay stable in JSON.
  - Section numbering: "Direct deps to update" is 5.1 under section 5 — the orphan "7.0" numbering is gone, and its French label is "Dépendances directes à mettre à jour".
  - Chapter 0 groups per-manifest warnings: `no-lockfile` and `parse-error` blocks collapse into one navigable block per type, each manifest listed with its own pinned/skipped detail; the JSON keeps one entry per manifest. On the real drupal/drupal scan the ~20 near-identical best-effort blocks become one, and the intentionally broken `HtaccessTest` fixture stays a scoped two-file parse limit that never leaks components or findings into the inventory.
  - Application direct/indirect follows the plan's §6.3 rule: only advisory-targetable kinds (core, framework, framework-component, bundle, module, theme, profile, plugin, mu-plugin, drop-in) root a require walk or hold a direct self-relation; a lock `library` never self-attributes. Packages installed by the application's own root manifest and claimed by nothing else are attributed to its primary core/framework (indirect, proof `root-manifest`) — the drupal/drupal layout where the root `replace`s `drupal/core` no longer yields 60 unknown-origin findings. Real corpus after correction: 28 direct / 162 indirect / 1 unknown (was 131 / 0 / 60); the core, `symfony/http-foundation` (in symfony-demo) and `laravel/framework` CVEs stay direct, the same http-foundation under Drupal core and Laravel framework reads indirect.
  - A shared physical occurrence is detailed in EVERY exposed instance section with its own origins per instance (`applicationExposures` in JSON), a "also exposed in" reference in each, while global counters stay a union of findings; the instance synthesis counts direct/indirect per instance too.
  - Overview charts on application scans announce the application axis: the CWE donut carries the DIRECT application findings only (core/framework/components/extensions — the CMS/framework versions' own vulns), the second donut groups the indirect CVEs by their INTRODUCING component (core Drupal, laravel/framework, plugins, themes…, unattributed ones kept as a count, never invented), and a third ranks the exposed instances (critical/high per instance, shared occurrences counted in each) with the distinct-finding count in the donut center and the advisories-coverage gaps in its note — overlapping exposures are never presented as exclusive donut parts. Filling the CWE donut requires the NVD enrichment lane (the CWE source); the final review reports are regenerated with NVD/EPSS/KEV active. SARIF, SBOM (`fad:finding` = `findingId=relation`), CSAF (one affected product per physical occurrence) and the occurrence-aware diff keep the same identities, and a finding whose advisory coverage went incomplete is reclassified unassessed, never "resolved".
- **The one French block in an otherwise English terminal.** The "a data source went dark"
  abort — and the retry lines leading up to it — printed in French whatever `--lang` said,
  so the operator who most needs to read it, the one whose run just refused to write a
  report, got it in a language the rest of the output never used. Now English, like every
  other line the tool prints. `--lang` deliberately does not reach it: that flag picks the
  language of the **report**, which goes to a client, while this is a diagnostic for
  whoever launched the scan.
- **The compiled binary asked for Node.js to scan vendored JavaScript.** The launcher looked
  for `node_modules/.bin/retire` before checking whether it was itself the compiled binary,
  and it resolved that path from `__dirname` — which in a bun-compiled binary still points at
  the directory it was BUILT in. Wherever that path also exists at run time (the machine that
  built it, a mounted or shared checkout) the binary ran a `#!/usr/bin/env node` script and
  died with `env: 'node': No such file or directory` with Node absent, losing the whole
  vendored-JS chapter — the one capability the self-exec exists to provide. It now decides on
  what the binary IS, not on what happens to sit on disk beside it. A box that never held the
  checkout was unaffected, which is why a container never showed it.
- **`--import-cache` could unpack nothing at all and still look like it had run.** `tar`
  restores the archived uid/gid when it runs as root; real root can chown to anything, but
  *mapped* root cannot — a rootless container, a userns-remapped daemon, anything under
  `unshare -r`. There the chown failed, tar aborted having written **nothing**, and the
  air-gapped run that followed found no cache and reported a clean project. Extraction now
  passes `--no-same-owner`, which is already the default for a non-root user.
- **A failed vendored-JS scan showed up as the raw string `retire-failed`.** The warning was
  raised and reached chapter 0 correctly; it just had no heading of its own, so the chapter
  printed the internal type id — and in a French report, printed it in English.
- **The copied executive summary stayed English in a French report.** The page was
  translated but the clipboard flavours are built as sentences in JavaScript ("The library X
  version Y is vulnerable to Z"), which the sweep had not reached. They now carry their own
  translations with placeholder interpolation rather than string concatenation, because word
  order differs between languages — `Top {n} most critical` has to be able to become
  `Les {n} plus critiques`. The rich Word flavour substitutes the bolded values into the
  translated sentence, so the bolding survives the reordering.
- **A copied vulnerability pasted as `CRITICAL9.8`.** The merged priority cell separated its
  severity badge from its CVSS score with a CSS margin, and drew the `EPSS:` / `Published:`
  colons with a `::after`. Both look right on screen and neither exists in `textContent` —
  which is exactly what the clipboard's plain-text flavour and the TSV export read. The
  separators are in the markup now, so the same text reaches the screen, the `.doc`, the
  clipboard and the TSV. The KEV chip had the same gap against the band badge.
- **The report called every descriptor a POM.** "Declared in (1 POM)" said POM whether the
  file was a `pom.xml`, a `package.json` or a `composer.lock`, and the advice for a CVE with
  no published fix was "Add `<exclusion>` in root POM" — given to npm, PyPI, NuGet, Go and
  Ruby readers, about a file their project does not have. The count now names the file kind
  when the paths share one (`3 pom.xml`, `2 package.json`) and says `N descriptors` when they
  do not, and each ecosystem's recipe carries its own no-fix line: an npm override, a yarn
  resolution, "upgrade or replace the gem". Wording that is genuinely Maven-only, such as the
  `parent POM` chip, is unchanged — those concepts only ever apply to Maven dependencies.
- **A URL-versioned npm dependency killed the scan.** `package-lock` v1 records a dep
  installed from a URL as `"version": "https://registry.npmjs.org/x/-/x-0.12.5.tgz"`, and the
  OSV cache filename interpolated that raw — so the scan died mid-step on
  `ENOENT … osv-cache/npm____javascript.util__https:/registry.npmjs.org/…`. Two fixes: a cache
  filename is now always one path segment (also in the Maven pom caches, which had the same
  gap, with a character set that leaves warm caches byte-identical), and a registry tarball URL
  is resolved to the semver in its filename, so the package is actually scanned instead of
  merely not crashing. A git ref, `github:`/`file:`/`link:` spec or a nightly with no version
  in its name has no concrete version and stays unresolved, never a fabricated one.
- **The source-health guard made the Maven outdated pass crawl.** Its retry schedule wrapped
  every fetch, including the ones `lib/maven-repo.js` and `lib/registries.js` issue with their
  own `AbortSignal` and their own failover to the next mirror or base. Each dead mirror then
  cost 6+7+8+9+10 = **40 seconds of sleeping** before the rotation was even allowed to try the
  next host — and every one of those retries reused the already-aborted signal, so all five
  failed instantly and pointlessly. A request that carries a signal is now passed straight
  through: the caller owns that budget. The coverage guarantee is kept where the information
  actually is, in the rotations themselves, which report a hole only when no host answered at
  all; a 404 from every base stays what it always was, the way an internal package is detected.
- **CSAF VEX declared the wrong publisher namespace.** `document.publisher.namespace` pointed at
  a stale `github.com/nathb2b/fad-checker`; it is now the canonical
  `github.com/9pings/fad-checker`, matching `package.json` and the SARIF `informationUri`.

- **Existence check hung on an offline box that was not told `--offline`.** The private-lib
  classification HEADs `maven-metadata.xml` for every non-local coord (100+ on a real
  reactor) with no request timeout, so a blackholed route (DNS fine, no egress — the usual
  audit VM) sat through the OS TCP timeout per probe, right after
  `✓ no missing Maven parent POMs`, with nothing on screen. Every Maven-repo request now
  carries a 20 s abort deadline, and the probe fan-out is preceded by **one bounded 5 s
  preflight per repository** (`reachableRepos`): when none answers the check is skipped
  with a visible warning, the cache is reused as-is (never wiped or restamped), and the run
  goes on.

### Security
- **Dependency refresh: 7 advisories to 0, all of them already permitted by the declared
  ranges.** `package.json` allowed every fix; only `package-lock.json` was stale, so a plain
  `npm update` closed the lot. `js-yaml` 4.1.1 → 4.3.2 (three HIGH: quadratic-complexity DoS
  in merge-key handling and `!!omap` resolution, incl. CVE-2026-59870), `retire` 5.4.2 → 5.7.0
  (drops `uuid` entirely, and carries `ip-address` past three HIGH SSRF/trust-boundary
  bypasses via `proxy-agent`), `rimraf` 6.0.1 → 6.1.3 (pulls `glob` 11.0.3 → 13.0.6, past a
  HIGH command injection, and `minimatch` 10.0.3 → 10.2.6, past three HIGH ReDoS), plus
  `commander` 14.0.3 and `smol-toml` 1.8.0.

  Two of these are reachable from **attacker-controlled input**, which is the reason this is a
  Security entry rather than a chore: `js-yaml` parses `pnpm-lock.yaml` and Berry `yarn.lock`
  from the audited tree, and `minimatch` compiles `--exclude-path` patterns. A scanner is
  pointed at untrusted repositories by definition.

  The declared **floors** were raised to the fixed versions, not just the lockfile. With
  `^4.1.1` left in place a consumer that already has `js-yaml` 4.1.1 in its tree would
  deduplicate fad-checker onto the vulnerable copy; the floor is what actually states the
  security minimum.

### Fixed
- **endoflife.date cache never refreshed.** `fetchEndoflife` returned whatever the cache held
  before looking at the 7-day TTL (an `{error}` entry included), and every run — offline
  included — restamped `meta.fetchedAt`, so the TTL could never trigger a refetch and a cached
  `support`/`eol` date was frozen forever. Now stamped **per product** on a successful fetch only:
  online, a stale entry is refetched (a failed refetch keeps serving the stale list, error
  entries are retried); offline, the warmed cache is served regardless of age, never blocking.
  Legacy cache files are upgraded in place.
- **`minimatch` was a phantom dependency.** `lib/path-filter.js` has always done
  `require("minimatch")` — the engine behind every `--exclude-path` glob — while
  `package.json` never declared it. It resolved only because `rimraf → glob` happened to hoist
  it to the top level of `node_modules`. Under a strict store (pnpm), or the day `rimraf` stops
  depending on `glob`, `--exclude-path` would have thrown at runtime on a resolution nothing in
  the manifest guaranteed. Now declared directly (`^10.2.6`). An audit of every external
  `require()` across `lib/`, `test/` and `fad-checker.js` found no other undeclared package.

### Added
- **Two-level EOL lifecycle + reliable PHP.** `--eol-support` reports frameworks/runtimes whose
  active (bug-fix) support has ended while security fixes continue (endoflife.date `support`
  field — Symfony 5.4 LTS since 2024-11-30, React 16/17/18, Django 5.2), as an "Out of active
  support" band; default output unchanged. Symfony/Laravel components are mapped from a
  generated, zero-false-positive list (`data/eol-composer-frameworks.json`, the monorepo's
  `replace: self.version` table — `symfony/monolog-bundle`, `*-contracts`, `polyfill-*` stay out)
  and reported as **one row per framework** with `anchor` + `components[]`. The **PHP runtime**
  is evaluated from the Composer platform constraint: a finding only when it proves an EOL PHP
  (`^7.4`, an exact pin), a chapter-0 `php-runtime-undetermined` note otherwise. JSON `eol[]`
  gains `status/cycle/support/anchor/components`; `--baseline` diffs treat a status change as a
  change.
- **`--nvd-cpe-match` (opt-in, off by default): match dependencies against NVD's CPE version
  ranges.** OSV/GHSA declare affected ranges per release *branch*; NVD declares them for every
  affected branch. For `CVE-2020-9546`, OSV covers 2.9.0–2.9.10.4 while NVD also covers
  2.0.0–2.7.9.7 — so `jackson-databind:2.5.2` is affected and never got a fix. fad already had
  that data in its NVD cache and only ever used it **subtractively**, to filter false positives.
  This uses it additively, restricted to coordinates with an **unambiguous 1:1** entry in
  `data/cpe-coord-map.json` (no name heuristics), and only for CVEs already enriched, so it adds
  no network path.

  **It is off by default because its measured precision is poor, and the reason is structural.**
  On Apache Dubbo 2.7.8 it adds 76 findings of which **9 (12%) are corroborated by Snyk**. CPE
  products are *framework*-level (`spring_framework`, `netty`, `log4j`) while Maven coordinates
  are *artifact*-level, so a framework CVE lands on every artifact of that framework —
  `CVE-2016-1000027` is a spring-web flaw and CPE puts it on spring-core, `CVE-2019-20444` is
  netty-codec-http and CPE puts it on netty-common. Curation cannot fix a granularity mismatch;
  allowing the map's deliberate 1:N entries made it worse still (262 findings, 8% corroborated).
  Shipped as a triage aid ("what might I be missing?"), never as a default. Locked by
  `test/nvd-cpe-match.test.js`, including a test asserting that a coordinate with no curated
  entry is not matched even when the name heuristic would have accepted it.

  The investigation behind it also settled what fad's 118 benchmark misses actually are, and
  the answer is not flattering: **they are real misses, not the other scanner's noise.** All 87
  public-CVE ones were checked against NVD — 7 confirmed, 13 where NVD's own range disagrees,
  67 where NVD names no CPE for the artifact. Both minorities were traced. The "NVD is silent"
  bulk are public-database coverage gaps: `CVE-2023-6481` on `logback-classic@1.2.2` exists in
  OSV with **no Maven package binding at all** (only a GIT range), while its own fixed-version
  list `1.2.12, 1.3.13, 1.4.13` shows the 1.2.x branch was affected and fixed at 1.2.12 — so
  1.2.2 is vulnerable and no public-source scanner can see it. The "NVD contradicts" cases are
  NVD contradicting itself: sibling jackson-databind gadget CVEs published weeks apart declare
  `2.0.0–2.7.9.7 / 2.8.0–2.8.11.6 / 2.9.0–2.9.10.4` (CVE-2020-9546) versus `2.9.0–2.9.10.4`
  alone (CVE-2020-10672). Public advisory data declares ranges per release *branch* and old
  unpatched branches are routinely absent; a hand-curated commercial database fills that in and
  aggregating public sources does not reproduce it. Documented in `docs/BENCHMARK.md` rather
  than left as "not yet diagnosed".

### Fixed
- **An imported BOM's `<properties>` leaked into the importing project — and won.**
  `<scope>import</scope>` imports a BOM's `<dependencyManagement>` and **nothing else**: the
  BOM resolves its managed versions in its own property context, and its `<properties>` never
  become the importer's. `core.js` merged them, and merged them so the BOM won
  (`{...merged.properties, ...imported.properties}`), so a BOM silently redefined the
  importing project's own property values. On Apache Dubbo 2.7.8 the reactor root sets
  `<hibernate_validator_version>5.2.4.Final</hibernate_validator_version>` and
  `dubbo-dependencies-bom` redefines it to `5.4.1.Final`, so `dubbo-filter-validation`'s
  `<version>${hibernate_validator_version}</version>` resolved to the wrong version — and a
  different version is a different CVE set. (`mvn dependency:tree` reports
  `hibernate-validator:jar:5.2.4.Final:test` for that module.) The BOM's managed entries are
  now interpolated against the BOM's own properties at the import boundary and the properties
  are dropped, mirroring what `transitive.js#effectivePom` already did for EXTERNAL import
  BOMs. Locked by `test/bom-property-leak.test.js`, which guards both directions: the leak
  must stop **and** importing a BOM must still supply managed versions.
- **A version declared only at test scope is now reported as dev.** `isDev` lives on the
  coord-wide record, so a version declared solely at `<scope>test</scope>` inherited the
  coordinate's production flag whenever the same coordinate was production at some other
  version — counting toward the production total and the `--fail-on` gate. Per-version scopes
  are now recorded next to per-version paths (`versionScopes`, mirror of `versionPaths`), and
  attribution applies the same widest-wins rule already used for overlay-recovered versions.
  On Dubbo, `hibernate-validator:5.2.4.Final` moves to the dev chapter, attributed to
  `dubbo-filter-validation` — exactly what Maven reports.

  Air-gapped recall on the public benchmark reaches **657/657 (100%)** of OSV-Scanner's own
  online finding set, up from 653.

### Changed
- **The benchmark now measures every scanner at full capability, not just air-gapped.**
  `docs/BENCHMARK.md` carries two tables, because they answer different questions. **Full
  capability** (all five online, best configuration, populated `~/.m2`, union 908 pairs):
  fad-checker 790 (87.0%), OSV-Scanner 657, Snyk 603, Trivy 546, Grype+Syft 45. **No tool
  finds everything, fad included** — its 118 misses all come from Snyk, 30 of them under a
  proprietary `SNYK-*` id no public database carries, and **88 genuine public-CVE misses that
  remain undiagnosed**. **No network** (`unshare -rn`, against OSV-Scanner's online output):
  fad 657/657, Grype+Syft 45, Trivy 40, OSV-Scanner 37.
  Also documented: Trivy's result is identical online and with a fully populated `~/.m2` (the
  local repository substitutes for the network entirely), Grype+Syft does not move at all
  between default and fully-enabled configuration, and the `settings.xml` mirror trick for
  reproducing the run when Maven Central rate-limits the IP.
- **The per-module overlay could not recover a version held only on a TEST classpath.**
  The overlay exists because the global transitive pass dedupes by `g:a` across the whole
  reactor and keeps one version per coordinate — but it hardcoded
  `includedScopes: ["compile","runtime","provided"]`, so a version reachable only through a
  test-scoped dependency was structurally unreachable. Measured on Apache Dubbo 2.7.8, this
  one omission accounted for **every one** of the 78 findings OSV-Scanner reported that fad
  missed (`jackson-databind:2.8.4:test` in dubbo-registry-sofa,
  `hibernate-validator:5.2.4.Final:test` in dubbo-filter-validation, `okhttp:3.11.0` /
  `okio:1.14.0` in dubbo-configcenter-apollo, `commons-compress:1.18:test` in
  dubbo-remoting-etcd3 — each verified against `mvn dependency:tree`).
  Air-gapped recall on that project: **579 → 653 of 657 (88.1% → 99.4%)**, production
  findings unchanged at 651, dev findings 11 → 147, **zero production finding lost**.
- **A version is now dev only when EVERY module resolving it does so at test scope.**
  On Dubbo, `jackson-databind:2.10.4` is test-scoped in `dubbo-config-spring` but
  **compile**-scoped in `dubbo-configcenter-nacos`. Reading the first recorded provenance
  called the version dev and dropped a genuine production finding out of the count and out
  of the `--fail-on` gate.
- **The overlay records provenance per module even when the version is already known.**
  It used to `continue` on the first module to contribute a version, so a second module
  resolving the same version at a different scope left no trace at all — which is exactly
  what made the previous item invisible.
- **A DECLARED version now wins over any transitive provenance for the same version.**
  `xstream:1.4.10` is declared outright in `dubbo-registry-eureka` *and* reached as a
  test-scoped transitive of `dubbo-config-api`; letting the transitive provenance win
  demoted 35 findings, one of them KEV, into the dev chapter. A manifest that writes
  `<version>` for a coordinate is the authority on that version.

### Previously fixed
- **The transitive closure of a test-scoped dependency was never scanned.** Maven's scope
  matrix says `test → compile = test`: the compile dependencies of a test-scoped dependency
  are on the test classpath, and so are theirs, recursively (only `test → test` is omitted).
  `expandWithTransitives` passed test-scoped roots into resolution (`includeTestDeps`, on
  unless `--ignore-test`) but `resolveTransitiveDeps` then filtered accepted propagated
  scopes to `compile/runtime/provided`, so **every child of a test root was discarded at the
  first hop**. Net effect: the dev chapter only ever listed *directly declared* test
  dependencies, never their transitives. On Apache Dubbo 2.7.8 this hid
  `spring-boot:1.5.17.RELEASE` and `spring-boot-autoconfigure:1.5.17.RELEASE`, four hops down
  `registry-test → registry-server-integration → spring-boot-starter`, all of which
  `mvn dependency:tree` reports at scope=test.
- **Scope is now widened, never narrowed, when a coord is reached by several paths.** This is
  the half of the fix above that matters most. The traversal dedupes by `g:a` and keeps the
  first chain walked, so marking everything under a test root as dev let **BFS order decide
  the scope**: a coordinate reachable from *both* a test root and a compile root got stamped
  test if the test path happened to be walked first. Measured: 6 production findings
  (`spring-core:4.3.16.RELEASE`, `commons-lang:2.6`, …) silently moved into the dev chapter,
  dropping out of the production count **and out of the `--fail-on` gate**. A false negative
  on the production classpath is worse than the gap being fixed. A revisit now upgrades
  `test` to the wider propagated scope and never the reverse. Locked by
  `test/transitive-test-scope.test.js` (6 tests, including the both-paths case and the
  `test → test` omission).
  Net on Dubbo: **575 → 579** recovered pairs, production findings **unchanged at 650**, dev
  findings 7 → 11.
- **Maven hard-pin versions (`[1.2.3]`) are now normalised to the bare version.**
  Maven's `[x]` syntax means *exactly* x — a concrete version wearing range brackets —
  and real upstream POMs use it (`io.grpc:grpc-netty:1.22.1` declares
  `<version>[4.1.35.Final]</version>`). fad kept the brackets verbatim, so the coordinate
  was wrong **everywhere downstream**: the report, the purl, and every SBOM/CSAF/SARIF/JSON
  export carried `netty-codec-http2@[4.1.35.Final]`, which cannot be joined with any other
  tool's output for the same dependency. Fixed by `lib/maven-version.js#normalizeHardPin`,
  applied on both paths that produce a version — `cve-match.js#resolveDepVersion` (declared
  deps, after `${…}` interpolation, so `[${netty.version}]` works) and `lib/transitive.js`
  (deps read out of upstream POMs, which is where this actually came from). A **genuine
  range keeps its brackets**: choosing a version out of `[1.0,2.0)` is resolution, not
  normalisation, and it must keep surfacing as unresolved rather than silently becoming
  concrete. Found by the new public benchmark, where it cost **9 recovered findings**
  (566 → 575 of OSV-Scanner's reference set on Apache Dubbo 2.7.8). Note that the OSV cache
  is keyed by coordinate **and** version, so this fix invalidates entries warmed under the
  old string — an offline re-run needs a cache re-warm to see the corrected coordinate.
- **Docs referenced a `--transitive` flag that does not exist.** Transitive resolution is
  **on by default**; `--no-transitive` disables it. Corrected in `ARCHITECTURE.md` and
  `COMPARISON.md`.

### Added
- **`docs/BENCHMARK.md` — a reproducible air-gapped recall benchmark.** Replaces the
  unverifiable private-project figure that headlined the README. Measured on **Apache Dubbo
  2.7.8** (105-module reactor, pinned commit), with both scanners run under `unshare -rn` in
  a namespace with **no network interface**, and graded against **OSV-Scanner's own online
  output** as the reference set (657 distinct `package@version | vulnerability` pairs) rather
  than against fad's own notion of a finding: **fad-checker recovers 575 (87.5%)**,
  **OSV-Scanner recovers 37 (5.6%)**. Documents the exact commands, the tool versions, the
  82 pairs fad misses **and why** (version-mediation divergence, plus two genuinely
  unresolved `spring-boot` coordinates), and the caveats — a warmed cache is required, and
  one project is one shape.

### Changed
- `docs/COMPARISON.md`: four competitor cells corrected after re-verification against
  upstream docs and source. Syft **does** have Maven transitive resolution
  (`java.resolve-transitive-dependencies`, opt-in, off by default); Trivy consults a local
  `~/.m2` before the network; Trivy **does** report end-of-service-life, but only for OS
  distributions (the EOL row is now scoped to *application* frameworks); and the
  "scan without exposing the codebase" row now concedes the SBOM-then-scan-online route,
  keeping only the two differences that are sourceable. Adds a version stamp for every tool
  compared and an explicit note that no ⚠️/❌ cell means "unmaintained".

### Previously fixed
- **External `<parent>` POMs (spring-boot-starter-parent) now backfill their managed
  versions.** A versionless dep whose version is inherited from an external `<parent>`
  (e.g. `spring-boot-starter-actuator` under `spring-boot-starter-parent`, whose own
  parent `spring-boot-dependencies` holds the version table) was left unresolved and
  **dropped from the CVE/OSV/EOL/outdated scans** — the mainline backfill (`lib/maven-bom.js`)
  only handled `<scope>import</scope>` BOMs, never the `<parent>` case, so this failed
  even online (the `--transitive` overlay resolved the parent but couldn't backfill the
  primary version). `collectExternalParents()` now feeds external parents through the same
  `effectivePom` → `backfillVersions` path as import BOMs (import BOMs win on precedence),
  stamped `versionSource={via:"parent",…}` → report "version managed by … (parent POM)".
  It runs in the **mainline** flow (not just `--transitive`), so the warmed cache always
  captures the parent POMs for **offline/air-gapped** reuse. **Child property overrides are
  honored** (Maven semantics): a project that redefines `<log4j2.version>2.17.1</log4j2.version>`
  to patch a CVE resolves the managed coord to `2.17.1`, not the framework default
  (`collectPropertyOverrides()` → `effectivePom`'s new `propertyOverrides`; import-BOM-managed
  coords are correctly left un-overridden). The "missing parent POM — potentially private"
  warning now **partitions** parents fad resolves from Maven Central/cache (public) from the
  truly-unresolvable ones (private), instead of flagging every external parent as suspect.
- **Anonymized descriptor closes the versionless-Spring-Boot round-trip in one exchange.**
  The `fad-deps/1` descriptor now carries a `maven` hints block (`externalParents[]` +
  `importBoms[]` coords + version `propertyOverrides{}`) so a no-source-tree online
  `--import-anonymized` run can resolve the versionless deps' versions and warm their
  `coord+version`-keyed CVE caches — previously that needed a second air-gapped exchange.
  Only public coords + version strings travel (a private parent listed is a harmless online
  no-op); the source tree never leaves the enclave.
- **CVE-index recall: real-world pre-2023 records were dropped (incl. Log4Shell).**
  `isMavenRelevant()` only accepted CVE 5.x records carrying machine-readable Maven
  metadata (`packageName`/`collectionURL`/`versionType:"maven"`) or an EXACT-match
  known vendor — but CNAs publish legal-entity vendors ("Apache Software Foundation")
  and display products ("Apache Log4j2"), so **CVE-2021-44228 was absent from the
  index** and an offline scan of `log4j-core:2.14.0` reported no Log4Shell. The filter
  now tokenises vendors, strips leading vendor words from products, and consults the
  curated `data/cpe-coord-map.json` — which also **backfills `packageName`** on
  product-only records so they match at tier-1. `versions[].changes[]` timelines
  (how 44228 encodes its affected windows) are expanded into plain affected windows,
  placeholder bounds (`lessThan:"log4j-core*"`, `"*"`, `"unspecified"`) no longer
  poison comparisons (fail-closed preserved), and `fixVersion` picks the **highest**
  version-like upper bound instead of the first (multi-branch advisories suggested a
  downgrade). Rebuilt index: **6 589 → 15 236 CVE (+131 %)**. Regression-tested against
  the real cvelistV5 record (`test/fixtures/cve-samples/cve-2021-44228-real.json`).
- **OSV offline: warmed cache older than the 12 h TTL was silently discarded.**
  `--offline` now bypasses the OSV cache TTL (same rule as the NVD cache): on an
  air-gapped box the warmed cache is the only source, and expiring it reported
  "0 OSV vulns" for every ecosystem. Online behaviour is unchanged.
- **Go: `replace` directives are now applied** (module→module replaces rewrite the
  scanned coordinate — a `replace` downgrade was invisible; directory replaces are
  dropped with a chapter-0 `local-replace` warning), and **pre-1.17 modules merge the
  `go.sum` graph** (their `go.mod` lists direct deps only — transitives were skipped).
- **PyPI: `pip-compile --generate-hashes` output parsed correctly.** The trailing
  `\` of hash-pinned lines (and inline ` --hash=…` options) made every dep of such a
  requirements file silently skipped. `uv.lock` no longer inventories the project's
  own virtual/editable package. Same-name deps pinned to different versions across
  files now ALL land in `versions[]` (every distinct version scanned, as Maven does).
- **NuGet: `Directory.Packages.props` is resolved by walking UP the tree** (MSBuild
  semantics — nearest wins). Before, only the csproj's own directory was searched, so
  a root-level CPM solution collected **zero** deps. Also: `VersionOverride` support,
  exact-range pins `[1.2.3]` accepted as concrete, distinct resolved versions across
  projects/TFMs all scanned, and **paged registration indexes** (Newtonsoft.Json-class
  packages) have the needed pages fetched instead of returning empty findings.
- **Registry caches (go/pypi/nuget): offline runs no longer re-stamp cache freshness**
  (a stale cache would then look fresh to the next online run and skip its refetch).

### Changed
- **Report chapters reorganised into a two-level hierarchy.** Related chapters are now
  grouped under six **root chapters**, each whose header carries a breakdown count:
  **1. CVE** (`X direct, Y indirect, Z dev` — sub: Production, Vendored JS vulns, Dev,
  Likely false positives) · **2. Unmanaged / unversioned components** (`X embedded,
  Y native, Z vendored JS` — sub: embedded JAR/WAR/EAR, native binaries, vendored JS) ·
  **3. Maintenance / lifecycle** (`X EOL, Y obsolete, Z outdated`) · **4. Licenses** ·
  **5. Fix Recommendations** · **6. Scan context & limitations** (sub: scanned
  descriptors, ignored dirs, methodology). **0. Warnings** and **Δ. Changes since
  baseline** stay pinned at the top. The table of contents is now hierarchical
  (roots + indented sub-chapters).

### Added
- **Certificate & key-material scanner (report chapter 2.4).** A new standalone scanner
  (`lib/certs/`, on by default, `--no-certs` to disable) walks the source tree for
  committed cryptographic material and surfaces it in a dedicated report chapter, the
  JSON export (`certificates` array + `summary.certificates`/`certPrivateKeys`) and SARIF
  (`FAD-*` rules). It detects **X.509 certificates** (PEM/DER, parsed with Node's built-in
  `crypto.X509Certificate`) and flags **expired**, **expiring** (within `--cert-expiry-days`,
  default 90), **weak key** (RSA<2048 / weak EC curve), **weak signature** (MD5/SHA1) and
  **self-signed**; **private & public keys** — every key explicitly labelled **private**
  (a committed secret → critical) or **public** (low) — across PEM (PKCS#1/8/SEC1),
  **OpenSSH of every algorithm** (RSA/DSA/ECDSA/Ed25519 incl. FIDO `-sk`), PuTTY `.ppk`,
  PGP and one-line SSH (`*.pub`, `authorized_keys`, `known_hosts`); and **keystores**
  (JKS/JCEKS by magic byte, PKCS#12 by extension). Detection is by extension **and**
  conventional SSH filename. **100% offline** — no network, no decryption — inventory-only
  (does not affect the `--fail-on` gate).
- **Scan-provenance manifest + Methodology chapter (audit reproducibility).** Every
  report now carries a provenance manifest — tool version, run mode (offline/online),
  the findings-affecting configuration, and the **freshness of every data source**
  (CVE index, OSV, NVD, KEV, EPSS, endoflife, registry caches) read from
  `~/.fad-checker/`. Surfaced in the JSON export's `provenance` block and in the
  report's new **chapter 12 — "Methodology, data sources & limitations"**, which also
  states explicitly **what fad-checker does *not* assess** (reachability, runtime
  config, secrets/IaC, first-party code, malware beyond the OSV/CIRCL signal, legal
  license advice). New `lib/provenance.js`.
- **Differential audits (`--baseline` / `fad diff`).** Diff a scan against a prior
  findings JSON: the report gains a **"Δ Changes since baseline"** chapter, the JSON
  export gains a `diff` block (summary + new/fixed CVEs), and CI can gate on **new**
  findings with `--fail-on-new` (exit 1 on any new production CVE). Standalone
  `fad-checker diff <baseline.json> <current.json> [--report-json <out>] [--fail-on-new]`
  for ad-hoc comparison. Finding identity = CVE id + ecosystem + coord + version. New
  `lib/diff.js`.
- **Report integrity manifest.** A standard `SHA256SUMS` is written beside the report
  artifacts (verifiable with `sha256sum -c`); `--no-checksums` disables it. New
  `lib/report-integrity.js`.
- **Private registries for NuGet and Composer** (previously the only registry-backed
  ecosystems without private-feed support). NuGet custom feeds speak the v3
  registration API (a service-index `…/index.json` is auto-resolved to its
  `RegistrationsBaseUrl`); Composer custom feeds are queried via the v2
  `<base>/p2/<vendor>/<pkg>.json` metadata API. Same `--add-repo nuget|composer …`
  CRUD + auth as the other ecosystems.
- **Custom registries for npm, PyPI, Ruby and Go** (previously Maven-only). Point
  fad-checker at private Verdaccio/Artifactory/GitHub Packages (npm), devpi (PyPI),
  Gemfury/Geminabox (Ruby) or a private GOPROXY/Athens (Go). They are tried in
  declared order, the public registry last; auth via `--auth user:pass` (→ Basic)
  or `--token TOK` (→ Bearer), inline `https://user:pass@host/` also accepted.
  CRUD: `--add-repo <eco> <name> <url>`, `--remove-repo <eco> <name>`,
  `--list-repos` (grouped by ecosystem); one-off repeatable `--repo <eco>=<url>`.
  New `lib/registries.js`; per-codec fetchers honour `opts.registries`.
- **Layered configuration.** Defaults can come from a JSON config file
  (`--config <file.json>`, else auto-discovered `./.fad-env.json`) and from the
  `FAD_CHECKER_ENV` environment variable (a string of CLI flags). Precedence:
  **CLI flag > config file > `FAD_CHECKER_ENV` > `~/.fad-checker/config.json` >
  defaults**; `registries` are unioned across every layer. New `lib/options-env.js`.
- **`--source` alias** for `-s`/`--src` (and the JSON config key `"source"`/`"src"`).
- **Vendored-JS inventory (report chapter 1D + JSON `vendoredJs`).** retire.js now
  runs with `--verbose`, so fad lists **every** identified standalone JS library
  committed into the tree (jQuery, Bootstrap, PDF.js, …) — **vulnerable or not** —
  as a cyber-hygiene inventory of unmanaged third-party code (the JS twin of the
  native-binary chapter 1C). Each entry: component, version, file, detection
  method, and vulnerability status. Vulnerable libs remain detailed in chapter 2.
  On by default; `--no-vendored-js-inventory` keeps only the vulnerable findings.
- **`--exclude-path <glob...>`** — ignore sub-paths during the directory walk,
  gitignore-style (matched relative to `--src`, prunes the dir + its subtree),
  across every ecosystem. Repeatable; also `excludePath: [...]` in `.fad-env.json`,
  unioned across config layers. **`--no-default-excludes`** walks the normally
  pruned dirs (`node_modules`, `vendor`, `target`, `.git`, …). New `lib/path-filter.js`.
- **Ignored-directories appendix (report chapter 11 + JSON `excludedDirs`).** The
  HTML/`.doc` report now ends with an appendix listing the ACTUAL directories the
  scan did not walk — resolved by re-walking `--src` once under the same prune
  policy the codecs use (the default-exclude set at any depth + your
  `--exclude-path` rules), each path shown relative to the scan root and tagged
  with the rule that pruned it (`default` vs `--exclude-path`). Surfaced in the
  findings JSON as `excludedDirs[]` + `summary.excludedDirs`. New
  `collectExcludedDirs()` in `lib/path-filter.js`.

### Changed
- **BREAKING:** the persisted-registry store moved from the Maven-only
  `maven_repos` config key + 2-arg `--add-repo <name> <url>` to a per-ecosystem
  `registries` map + `--add-repo <ecosystem> <name> <url>`. `--repo` now requires
  the `<ecosystem>=<url>` form (a bare URL is rejected). Re-add any private Maven
  repos with `--add-repo maven <name> <url>`.

### Fixed
- **A failing `--snyk` run is no longer silently reported as "0 findings".** Snyk
  exits 2 on a command error (e.g. not authenticated) and 3 when it detects no
  supported project — but in `--json` mode it still writes a JSON document to
  **stdout**, shaped `{ ok:false, error:"…" }`. `runSnykTest`'s catch block treated
  *any* stdout on a non-zero exit as "vulns found (exit 1)", so that error JSON was
  parsed to zero vulnerabilities and surfaced as a green `Snyk: 0 findings merged`,
  hiding the failure. It now distinguishes real results (a `vulnerabilities` array or
  `ok:true`) from error stubs and **throws the snyk error message** (deduped, joined),
  which the orchestrator shows as a `Snyk run failed: …` warning. A snyk crash with no
  stdout now surfaces `stderr` instead of `execFile`'s generic "Command failed", and a
  timeout is reported as such. New pure helper `snykOutputError()` (unit-tested).
- **retire.js now skips the same dirs as the rest of the scan.** The vendored-JS
  scan walks the tree itself and was handed a bare `--ignore node_modules,…` list,
  which retire `path.resolve()`s against its **own working directory** — so a
  `node_modules` (or `target`/`dist`/…) nested anywhere under `--src` was scanned
  whenever fad-checker ran from a different directory than the source tree. retire
  is now driven by a generated `--ignorefile` anchored to `--src` that prunes the
  default SKIP dirs **at any depth** and honors `--exclude-path` /
  `--no-default-excludes`, matching `lib/path-filter.js`.
- **Offline NVD enrichment (incl. CWEs) no longer silently dropped.** The NVD cache
  enforces a 7-day TTL and a schema version; offline, a TTL-expired or older-schema
  entry was treated as a miss — and since an air-gapped box can't re-fetch, the CVE
  lost **all** its NVD enrichment (CWE list, CVSS vector, references, CPE configs).
  That was the "offline scan was missing some CWE titles that the online scan had".
  Offline now reads the warmed cache regardless of age/schema (a missing field just
  stays missing — strictly better than dropping everything); online still enforces
  TTL + schema so it re-fetches and upgrades. CWE IDs were already persisted in the
  cache body (`_schema:2`) and travel in `--export-cache`; CWE *titles* come from the
  bundled `data/cwe-names.json` (identical online/offline).

## [2.1.0]

### Added
- **Embedded-binary scanning (chapter 1B).** The Maven codec now discovers Maven
  coordinates inside committed `.jar`/`.war`/`.ear` archives — vendored libs,
  Spring-Boot fat-jars, shaded uber-jars — by unzipping them **in memory** (via
  `fflate`, recursing into nested jars without touching disk, so there is no
  zip-slip risk). Each artifact's coordinate is read from
  `META-INF/maven/.../pom.properties` → `MANIFEST.MF` → file name; unidentifiable
  archives are flagged in chapter 0 rather than scanned blindly. Findings carry
  `provenance:"embedded"`, report in a dedicated **Embedded binaries** chapter
  (grouped by containing archive), feed the `--fail-on` gate, and are labelled in
  the SBOM (`fad:provenance`/`fad:location` + unique `bom-ref`), SARIF
  (`provenance` + nested-jar location) and JSON exports. Auto when archives are
  present; `--no-jars` disables it.

### Changed
- **Unified output flags.** Every output now has its own `--report-<type>` flag
  taking an OPTIONAL path (omit it → a default name under `--report-output`):
  `--report-html`, `--report-doc`, `--report-sbom`, `--report-csaf`,
  `--report-json`, `--report-sarif`. With no `--report-*` flag, HTML + `.doc` are
  written as before; selecting any flag writes exactly that set.
  **BREAKING:** the old `--export-sbom`/`--export-csaf`/`--export-json`/`--export-sarif`
  flags are removed — use `--report-sbom`/`-csaf`/`-json`/`-sarif`. (The unrelated
  `--export-cache` / `--export-anonymized` flags are unchanged.)
- **`--no-report` now writes NO output files at all** (gate-only / CI mode) — the
  scan, terminal summary and `--fail-on` gate still run. Previously it
  short-circuited the whole flow, so `--no-report --fail-on …` silently passed.

### Fixed
- **Catastrophic data loss**: `--target` being a *parent* of `--src` passed the
  guardrail and `rimraf`'d the source tree. The guard now rejects overlap in both
  directions.
- **Missed npm/yarn/pnpm CVEs**: only the highest version of a duplicated package
  was scanned; nested-`node_modules` lower versions are now accumulated.
- **CPE false negatives**: AND-configurations with a `vulnerable:false` platform
  node wrongly dropped real findings.
- **VEX over-suppression**: an unmappable product id suppressed a CVE for every
  dependency.
- **CSAF/SBOM/SARIF scoring**: OSV CVSS *vectors* were mis-read as the score
  (`3.1`), the NVD CVSS version label was malformed (`CVSS:V31`), and an NVD record
  without metrics clobbered an OSV-derived vector — so CSAF emitted no scores and
  SBOM showed `method:other`. CVSS v3 base scores are now computed from the vector,
  labels normalised, and exports stay schema-valid (no empty `known_affected`, no
  `UNKNOWN` baseSeverity, no v4 vector under a v3 score).
- **CI / parsing**: an invalid `--fail-on <level>` (typo) now hard-fails instead of
  silently disabling the gate; Maven version ordering for dot-aligned qualifiers
  (`5.0.0.RC1` vs `5.0.0.5`) corrected; classic poetry.lock `category="dev"` and
  `go.sum` highest-version selection fixed.

## [2.0.1]

### Fixed
- **EOL detection for PyPI / NuGet** used dead endoflife.date product slugs
  (`fastapi`, `aspnetcore`, `efcore` → HTTP 404), so no .NET / FastAPI EOL was ever
  flagged. NuGet ASP.NET Core / EF Core packages now map to the `dotnet` product
  (their versions track .NET cycles); `fastapi` removed (no endoflife.date source).

### Added
- Detailed capability test suite (`test/codec-capabilities.test.js`): end-to-end EOL
  per ecosystem (seeded cycles), registry findings (abandoned / yanked / inactive /
  deprecation) + outdated gating, cycle-matching logic, fix recipes, and report
  rendering of EOL/Obsolete/Outdated. Plus a guard asserting every eol-mapping product
  slug is a known-valid endoflife.date product.

## [2.0.0]

Major release: **codec architecture** + three new ecosystems.

### Added
- **Codec abstraction** (`lib/codecs/`): every ecosystem now lives behind a single
  interface (`detect` / `collect` / `coordKey` / `formatCoord` / `osvPackageName` /
  `checkRegistry` / `resolveEolProduct` / `recipe` / `nativeScanners`) discovered through
  a registry. OSV, NVD, CPE refinement and endoflife.date are shared, ecosystem-agnostic
  services. Adding an ecosystem is adding a codec — no orchestrator changes.
- **Composer (PHP)** codec — `composer.lock` / `composer.json`, Packagist `abandoned`,
  EOL (Laravel/Symfony/Drupal), `composer require` fix recipe.
- **PyPI (Python)** codec — `poetry.lock` / `Pipfile.lock` / `uv.lock` / `pdm.lock` /
  `requirements.txt`, PEP 503 name normalisation, PyPI `yanked` + "Inactive" classifier,
  EOL (Django/NumPy/FastAPI), `pip install` fix recipe.
- **NuGet (C#/.NET)** codec — `packages.lock.json` / `*.csproj` (+ Central Package
  Management via `Directory.Packages.props`) / `packages.config`, NuGet `deprecation`,
  EOL (.NET/ASP.NET Core/EF Core), `dotnet add package` fix recipe.
- `--ecosystem` is now a **list** (`auto` | `all` | comma list) and per-codec opt-outs
  `--no-maven` / `--no-npm` / `--no-yarn` / `--no-nuget` / `--no-composer` / `--no-pypi`.
- Generalized `depRecord` (`ecosystem` / `namespace` / `name` / `coordKey`).
- Dependency: `smol-toml` (TOML lockfile parsing).

### Changed
- **npm no-lockfile behaviour (contract change)**: a `package.json` without a sibling
  `package-lock.json` / `yarn.lock` is now parsed **best-effort** (pinned exact versions
  scanned, ranges skipped, `no-lockfile` warning) instead of being skipped entirely. The
  same lockfile-first, best-effort fallback applies to Composer / PyPI / NuGet.
- The orchestrator now loops over detected codecs; report sections, labels, coordinate
  formatting and fix recipes are driven by the codec registry.
- Maven CVE-index (cvelistV5) and retire.js are now `nativeScanners` owned by their codec.
- `--no-js` is retained as an alias for `--no-npm` + `--no-yarn`.

### Notes
- Maven map keys stay bare `g:a` (collision-free against the prefixed `npm:` / `nuget:` /
  `composer:` / `pypi:` keyspaces) to keep transitive resolution and existing behaviour intact.
- Verified non-regression against a real Maven + npm project: identical findings modulo
  upstream advisory drift.

## [1.x]
- Maven + npm/Yarn + vendored-JS scanning; CVEProject + OSV + NVD + CPE; EOL / obsolete /
  outdated; HTML + Word report; private-dep cleanup for Snyk.
