# USAGE

Every flag, every common workflow, with copy-pasteable commands.

## Synopsis

```text
fad-checker -s <src> [-t <target>] [-e <regex>] [other options]
```

- `-s, --src <src>` — **required**. Root of the source tree to scan. Contains `pom.xml` and/or `package(-lock).json` / `yarn.lock`.
- `-t, --target <dir>` — optional. **Extraction mode.** Write a parallel directory of "cleaned" POMs (private/excluded deps stripped, reactor modules linked to each other) to `<dir>` **and mirror every non-Maven lockfile/manifest** (`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`, `composer.lock`/`symfony.lock`, `poetry.lock`/`Pipfile.lock`/…, `*.csproj`/`packages.lock.json`, `go.mod`/`go.sum`, `Gemfile.lock`, …) into it — so **any** scanner pointed at `<dir>` (`snyk test --all-projects` among them) sees **every** ecosystem, not just Maven. Each POM is reduced to the dependency-relevant nodes (coordinates, `properties`, `dependencyManagement`, `dependencies`, `modules`), reactor parents are rewired to their real in-tree `relativePath`, and `${…}` is resolved in coordinates. The run then **stops**: the only network action is the Maven-repository *existence* check, which is also what **identifies your private/internal modules** (coordinates that exist in no configured repository) — skipped under `--offline`, or when no repository answers a 5 s preflight. No CVE/EOL/outdated pass, no report — add `--snyk`, a `--report-<type>`, `--fail-on`/`--fail-on-new` or `--baseline` to also run the scan. A non-empty target requires `--force` because its contents are replaced. Without `-t`, the run is read-only and produces the full report.

## Output

By default the HTML report and a `findings.json` land in `./fad-checker-report/` (the JSON so the next run can `--baseline` against it; add `--report-doc` for the Word file). Override with `--report-output <dir>`.

## Ecosystem selection

```bash
# Auto-detect (default): scan whatever pom.xml / package(-lock).json / yarn.lock exists
fad-checker -s .

# Pick ecosystems (codecs). --ecosystem is a list: auto (default) | all | comma list.
# Codec ids: maven, gradle, npm, yarn, composer, pypi, nuget, go, ruby.
fad-checker -s . --ecosystem maven            # Maven only
fad-checker -s . --ecosystem gradle           # Gradle only
fad-checker -s . --ecosystem maven,npm,go     # several, even if only one is auto-detected
fad-checker -s . --ecosystem all              # every supported codec
fad-checker -s . --ecosystem both             # legacy alias for maven,npm

# Opt out of specific codecs (combine freely)
fad-checker -s . -d npm                       # skip npm
fad-checker -s . -d js                        # alias: skip npm + yarn (Maven-only)
fad-checker -s . -d gradle                    # skip Gradle
fad-checker -s . -d pypi,nuget                # skip Python + C#
fad-checker -s . -d go,ruby                   # skip Go + Ruby
fad-checker -s . -d jars                      # skip embedded .jar/.war/.ear scanning
fad-checker -s . -d binaries                  # skip committed native-binary scanning
fad-checker -s . -d certs                     # skip certificate / key-material scanning
fad-checker -s . -d nvd,epss,certs -a licenses,typosquat -o ./audit   # the general shape

fad-checker -s . -a eol-support               # also flag "security-only" frameworks (e.g. Symfony 5.4 LTS since 2024-11-30)
fad-checker -s . --cert-expiry-days 30        # warn on certs expiring within 30 days (default 90)
```

> The individual `--no-npm`, `--licenses`, … flags still work; they are hidden from `--help`
> to keep it to one screen. `--help-all` lists them.

> **Embedded JARs**: committed `.jar`/`.war`/`.ear` archives (vendored libs, Spring-Boot fat-jars, shaded uber-jars) are unzipped in-memory and their Maven coordinates — read from `META-INF/maven/.../pom.properties`, then `MANIFEST.MF`, then the file name — are reported in their own **Embedded binaries** section, grouped by containing archive. The section is a **full inventory** of every embedded coordinate — vulnerable or not (the JAR counterpart of the native-binary and vendored-JS inventories) — with a CVE-status column per coord and the full CVE detail for vulnerable ones. So a committed fat-jar shows up even when nothing inside it is currently vulnerable. Auto when archives are present; `--no-jars` disables it. Archives with no resolvable coordinate are listed in chapter 0.

> **Committed native binaries**: `.dll`/`.exe`/`.so`/`.dylib` files are detected by extension **and** magic-byte confirmation (PE/ELF/Mach-O — images/fonts/assets are rejected even with a spoofed extension), hashed (SHA-1 + SHA-256) and **identified by checksum** online: **deps.dev** maps the hash to an exact package coordinate (byte-identical to a published artifact → *pristine*, and a candidate to declare as a real dependency); **CIRCL hashlookup** recognises known OS/distro/CDN/NSRL files (*known-good*) and carries a free `KnownMalicious` flag. Files no source knows are *unknown*; a filename disagreeing with the resolved identity is *name≠checksum*. Reported in the **Unmanaged / vendored binaries** section and the JSON export (`unmanaged` array). Cached + `--offline`-aware; the binary scan is on by default in `auto` mode and disabled with `--no-binaries`. No malware/AV lane.

> **Certificates & key material**: committed cryptographic files are inventoried in the unmanaged-components chapter and the JSON export (`certificates` array) + SARIF (`FAD-*` rules). Detected by extension (`.pem`/`.crt`/`.cer`/`.der`/`.key`/`.pub`/`.p12`/`.pfx`/`.jks`/`.keystore`/`.ppk`/`.asc`/`.gpg`) **and** conventional SSH filenames (`id_rsa`/`id_ed25519`/…/`authorized_keys`/`known_hosts`), then classified by content: **X.509 certificates** (parsed with Node's built-in `crypto.X509Certificate` — flagged `expired`, `expiring` within `--cert-expiry-days` (default 90), `weak key` RSA<2048 / weak EC curve, `weak signature` MD5/SHA1, `self-signed`); **keys** — every one labelled **private** (a committed secret → *critical*) or **public** (*low*, inventory) — covering PEM (PKCS#1/PKCS#8/SEC1), **OpenSSH of every algorithm** (RSA/DSA/ECDSA/Ed25519 incl. FIDO `-sk`), PuTTY `.ppk`, PGP, and one-line SSH public keys; and **keystores** (JKS/JCEKS by magic, PKCS#12 by extension — contents not decrypted, hashed + flagged *medium*). **100% offline** — no network, no decryption. On by default; `--no-certs` disables it, `--cert-expiry-days <n>` sets the expiry window. (Inventory only — these findings don't affect the `--fail-on` gate.)

> **PHP runtime**: for every Composer project the declared PHP constraint is read (`composer.lock` `platform-overrides.php` › `composer.json` `config.platform.php` › `composer.lock` `platform.php` › `composer.json` `require.php`). A finding is emitted **only** when the constraint proves an end-of-life runtime — an exact pin, or a bounded range such as `^7.4` (= `<8.0`) whose newest allowed PHP is EOL. An open constraint (`>=7.2.5`) proves nothing about the deployed runtime and produces no finding and no warning — the deployed PHP must be checked against endoflife.date/php outside the scan. Symfony/Laravel components are reported as **one row per framework** (the anchor package + a component count), never one row per component.

> **EOL detail panel**: in the HTML report, **click an EOL row** to expand the exact references of the descriptors it is defined in — for every component of the finding: the descriptor path **with the line number** (`web/pom.xml:34`), its module, and the declaration itself (the `<dependency>` block, the `package.json` entry, the lockfile header, …). A transitive finding lists **every** chain that pulls it in plus where the direct dependency to bump is declared; a BOM / parent-POM-managed version names that BOM. A descriptor in which the coordinate has no textual declaration (a POM that inherits it from a parent or reactor module) says so instead of guessing a line. The `.doc` prints every panel open.

> **npm without a lockfile**: a `package.json` lacking a sibling
> `package-lock.json`/`yarn.lock` is now scanned **best-effort** — pinned exact
> versions are checked, ranges (`^1.0.0`) are skipped, and a `no-lockfile` warning
> flags the partial coverage. Run `npm install`/`yarn install` for full coverage.

> **Gradle**: a Gradle dependency *is* a Maven coordinate, so Gradle findings flow through
> the **same** Maven services (CVE index, OSV `Maven`, transitive resolution, outdated, EOL)
> and get their **own "Gradle" report chapter + `constraints { }` fix recipe**. Sources, in
> order of authority: **`gradle.lockfile`** (exact, resolved, transitives included — enable
> Gradle [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html)
> for the best coverage); **`gradle/libs.versions.toml`** version catalogs; and a
> **best-effort** parse of `build.gradle`/`build.gradle.kts` (Groovy **and** Kotlin DSL — string
> & map notation, `libs.*` catalog accessors, `$var`/`gradle.properties` resolution),
> including the `buildSrc/` convention plugins. A `platform("…")` / `enforcedPlatform("…")`
> BOM (e.g. `spring-boot-dependencies`) is resolved exactly like a Maven `<scope>import</scope>`
> BOM, **backfilling the versions of the versionless starters** declared against it. A
> backfilled dep's resolved version isn't written anywhere in your source, so the report
> discloses where it came from: under the dep's `defined in:` footer it shows
> **`version managed by: <bom-coord> (BOM)`** (e.g. `org.springframework.boot:spring-boot-dependencies:4.0.6`),
> and the findings JSON carries it as `dep.versionSource = { via: "bom", bom: "<coord>" }`. Versions
> that can't be resolved statically (programmatic/dynamic deps) are listed in chapter 0 and
> excluded from CVE matching (never assumed vulnerable); `--no-gradle` disables the codec.

## Filtering deps

`-e <regex>` filters out coords whose **groupId** (Maven) or **name** (npm) matches the regex. Useful for private/internal libs that you know aren't on a public registry.

```bash
fad-checker -s . -e "^(com\.acme|org\.private)\."
fad-checker -s . -e "^@acme/"
```

The excluded coords are listed at the end of the run so you can audit the regex.

### Ignoring sub-paths (`--exclude-path`)

`-e` drops *dependencies* by coordinate; `--exclude-path` prunes the directory **walk** itself — nothing under a matched path is read, for every ecosystem. Patterns are gitignore-style globs (via `minimatch`, `dot:true`) matched against the path **relative to `--src`**; a pattern matches both the directory and its whole subtree.

This applies to the **retire.js vendored-JS scan** too: retire skips the same default dirs (`node_modules` etc.) at **any depth** and honors your `--exclude-path` / `--no-default-excludes`, anchored to `--src` — so a deeply-nested `node_modules` is never scanned.

All patterns are **anchored to the `--src` root** — `truc`, `/truc` and `./truc` are equivalent (a leading `/` or `./` is stripped). To match a name at any depth, use `**/` (e.g. `**/fixtures/**`).

```bash
fad-checker -s . --exclude-path "packages/legacy/**" --exclude-path "**/fixtures/**"
fad-checker -s . --exclude-path "apps/*/e2e"          # repeatable
fad-checker -s . --no-default-excludes                # also walk node_modules/vendor/target/.git/…
```

| Flag | Effect |
| --- | --- |
| `--exclude-path <glob...>` | Prune matching sub-paths (relative to `--src`). Repeatable; also settable as `excludePath: [...]` in `.fad-env.json` and unioned across all config layers. |
| `--no-default-excludes` | Don't prune the built-in ignored dirs (`node_modules`, `bower_components`, `vendor`, `dist`, `build`, `out`, `target`, `.git`, `.gradle`, `__pycache__`, …). Walks everything — slower, but nothing is hidden. |

For full transparency about what was *not* scanned, the report includes an **"Ignored directories" section** in scan context listing the actual directories the scan skipped — relative to `--src`, each tagged with the rule that pruned it (`default` vs `--exclude-path`). The same list is in the findings JSON as `excludedDirs[]`.

## Per-source toggles

Each data source can be disabled independently:

| Flag | Effect |
| --- | --- |
| `--no-report` | Write **no output files at all** (gate-only / CI mode) — the scan, terminal summary and `--fail-on` gate still run. See **Outputs** for the per-type `--report-*` flags |
| `--no-transitive` | Don't fetch transitive Maven deps from Maven Central |
| `--no-all-libs` | Don't query Maven Central for latest versions (skips the Outdated section and the "missing on Central" check) |
| `--no-osv` | Skip OSV.dev (Google + GitHub aggregated feed) |
| `--no-packagist-audit` | Skip the Packagist security-advisories lane for Composer deps — the endpoint `composer audit` queries. OSV misses CVEs it carries only as CVEProject entries without composer coordinates (twig/twig CVE-2026-46636/46627, knp-snappy CVE-2026-46643 on the real-instance corpus); this lane matches them with the official constraints. Only package names are sent |
| `--no-nvd` | Skip NVD enrichment (no full CVSS, no CPE refinement) |
| `--no-epss` | Skip EPSS (FIRST.org) exploit-prediction enrichment |
| `--no-kev` | Skip CISA KEV (known-exploited) enrichment |
| `--no-euvd` | Skip ENISA EUVD (EUVD id + ENISA exploited flag). Two bulk reads (mapping dump + exploited catalogue), 24h cache, no CVE id sent. The exploited flag is reported in the detail panel and every export; it does not move the priority band or the `--fail-on kev` gate |
| `--no-certfr` | Skip CERT-FR (ANSSI) advisory references. fad keeps a local CVE → advisory index: the first run reads every advisory once (~18 000 small JSON, ~75 s), later runs only the new or revised ones; no CVE id sent. GCVE ids need no source (`GCVE-0-…` is the CVE id by the GCVE rules) |
| `--licenses` | Run license detection + the copyleft-policy chapter (**off by default**; legacy `--no-licenses` is a no-op) |
| `--no-retire` | Skip retire.js vendored-JS scan |
| `--no-vendored-js-inventory` | Keep only **vulnerable** vendored JS (the CVE chapter); skip the full **inventory** of all identified standalone JS libs (under unmanaged components). The inventory is a cyber-hygiene constat — unmanaged third-party JS regardless of CVEs — on by default. |
| `--no-jars` | Skip scanning embedded `.jar`/`.war`/`.ear` binaries for Maven coordinates (the unmanaged-components chapter) |
| `--no-binaries` | Skip scanning committed native binaries (`.dll`/`.exe`/`.so`/`.dylib`) — no checksum identity/integrity (the unmanaged-components chapter) |
| `--no-certs` | Skip the certificate / key-material scan (the unmanaged-components chapter) — committed certs, private/public keys and keystores |
| `--cert-expiry-days <n>` | Window for the certificate **expiring-soon** warning (default `90`) |
| `-d, --disable <list>` | Turn features off, comma-separated: `eol nvd nvd-mirror osv epss kev retire transitive all-libs checksums osv-db report vendored-js-inventory default-excludes` and any ecosystem (`maven gradle npm yarn nuget composer pypi go ruby js jars binaries certs`). Replaces the `--no-*` flags, which still work but are hidden from `--help` |
| `-a, --activate <list>` | Turn on what is off by default: `licenses eol-support typosquat snyk osv-db nvd-cpe-match cve-refresh cve-offline osv-db-refresh retire-refresh` |
| `-r, --report <list>` | Outputs to write: `html doc xlsx sbom csaf json sarif` (default `html,json`). `--report-<type> <file>` still takes an explicit path |
| `-o, --report-output <dir>` | Report output directory |
| `--help-all` | Every option, including the individual flags `-d`/`-a`/`-r` replace and the cache / registry / config commands |
| `--lang <en\|fr>` | Language of the HTML / Word report (default `en`). Translates the report's own chrome — **all of it**: chapter titles and their counts, table headers, scope chips, every intro paragraph, every status pill, the warning headings, the licence categories, the methodology limitations, the per-ecosystem fix recipes, the empty states, and the executive summary both on screen and as the 📋 button pastes it — plus the CWE titles. **Not** the evidence: CVE descriptions, advisory text and registry reasons stay as published, and a CVSS severity keeps NVD's own wording where it is a finding's value. French CWE titles are fad's own (MITRE publishes English only) and carry MITRE's original with them |
| `--no-eol` | Skip the end-of-life check (endoflife.date) — the flag the run suggests when that source is unreachable |
| `--no-nvd-mirror` | NVD only. By default, **without an NVD API key** the CVE records are read FIRST from the mirror below (in parallel — NVD without a key allows 5 requests / 30 s) and only the CVEs it does not hold yet are asked of NVD, which must then answer (full retry schedule; the run stops otherwise); **with a key**, NVD stays first and, when it does not answer (throttled 403/429, 5xx, network), the CVE record is read from the [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) mirror (daily copy of the NVD API 2.0, same JSON, no key, no rate limit — records fetched there carry `via: "fkie-cad/nvd-json-data-feeds"` in the NVD cache) and the run aborts only if both fail; a cached record past its TTL is served rather than dropped. This flag (or `-d nvd-mirror`) disables the fallback and restores NVD's own retry schedule |
| `--retries <n>` | Retries before a data source that does not answer stops the run (default `5`, waiting 5+n s each: 6, 7, 8, 9, 10 s). `0` = no retry — the first failed answer declares the source down. Shared per source, so one dead host runs ONE schedule however many lookups hit it. Requests whose caller rotates across mirrors/registries are not retried (the rotation moves on). Also settable as `"retries"` in `.fad-env.json` |
| *(exit code 2)* | **A data source was unreachable (after `--retries` attempts) and the cache didn't cover it.** Not a findings failure: nothing was written, because the report would have been incomplete. The message names the domain, the codes, the failing URL and the flag that skips that source. Only online; `--offline` never aborts. |
| *(EOL + paid support)* | When endoflife.date lists **paid** support past the open-source end of life (`extendedSupport` — e.g. Broadcom for Spring 5.3/6.x), the EOL row stays an EOL finding (those fixes are builds from the vendor's private repository, for subscribers) and states: the support end date, the build of the dependency's own branch that fixes the CVEs found (`A 5.3 build > 5.3.40 fixes 7 of the 9 CVEs found`), and — when the vendor repository is configured with `--add-repo maven <name> <url> --token <TOKEN>` — the newest vendor build of the branch. A project already on a vendor build (newer than the branch's last public release and absent from Maven Central) is not reported as EOL; chapter 0 notes it. |
| `--eol-support` | Also report frameworks/runtimes whose **active (bug-fix) support has ended** while security fixes are still provided (endoflife.date `support` field) — rendered as an "Out of active support" band under the maintenance chapter, status `unsupported` in the JSON. Off by default: the default EOL set is unchanged. |
| `--ignore-test` | Drop test-scoped Maven deps and dev npm deps from the scan entirely (the dev-CVE section will be absent) |
| `--proxy-cache <url>` | Route every public data-source request through a shared `fad-checker serve-cache` server — one upstream call per requested resource for all instances, persisted across restarts. Private registries always go direct. See **Shared proxy-cache server** |
| `--proxy <url>` | Route ALL outbound requests through a corporate forward proxy (`http://host:port`; Node >= 24 or bun). See **Corporate forward proxy** |

If Packagist answers successfully but omits a package from its advisory data, the scan
continues and names that package in a report warning; omission is never treated as a
clean result. An unreachable Packagist endpoint or malformed response still stops an
online scan before writing a report when this lane is enabled.

## Application inventory (experimental)

The bundled `symfony`, `wordpress`, `drupal`, `laravel`, `joomla`, `prestashop`, `typo3`, and `magento` application plugins are currently experimental in capability, but a present CMS/framework is **activated by the default `--app-plugins auto`**: any recognized layout is inventoried automatically, with honest per-capability coverage (advisories stay `not-run (CMS_PROVIDER_UNCONFIGURED)` until their source is configured — never silently clean). Detection requires conjunctive positive evidence per product (e.g. WordPress needs `wp-load.php` + `wp-includes/version.php` + `wp-admin/index.php`; Symfony needs a kernel/front-controller marker *and* `symfony/framework-bundle` in that tree's lock; a bare `require` constraint never creates an application) — verified on real bare libraries (guzzle, laravel/framework as a package, the symfony/symfony monorepo, composer/composer): zero phantom applications. `--app-plugins none` disables every application plugin; `all` is an explicit synonym of the default; a comma list restricts to specific plugins. `--list-app-plugins` shows the available plugins.

Every subtree is also scanned through its supported dependency descriptors. If its CMS layout is recognized, dependency findings are shown under that CMS instance; otherwise those findings remain in the ordinary dependency sections.

```bash
fad-checker -s ./project --app-plugins symfony --offline --report-json
fad-checker -s ./project --app-plugins wordpress --private-component site/wp-content/plugins/acme --offline
fad-checker -s ./project --app-plugins wordpress --wordfence-feed ./wordfence-production.json --public-component site/wp-content/plugins/example=example --offline
fad-checker -s ./project --app-plugins drupal --offline --fail-on-incomplete inventory,advisories
fad-checker -s ./project --app-plugins drupal --drupal-advisories ./drupal-advisories.json --offline
fad-checker -s ./shop --app-plugins prestashop,typo3 --prestashop-advisories ./ps-advisories.json --typo3-advisories ./t3-advisories.json --offline
fad-checker -s ./shop --app-plugins prestashop,typo3 --prestashop-advisories-live --typo3-advisories-live
fad-checker -s ./project --app-plugins wordpress --wp-checksums-live
fad-checker -s ./project --app-plugins wordpress --wp-checksums ./wp-checksums-6.4.2-en_US.json --wp-checksums-locale en_US --offline
fad-checker -s ./project --app-plugins laravel --offline --report-json
fad-checker -s ./my-wordpress-plugin --app-plugins wordpress --scan-context component --offline --report-json
fad-checker -s ./shop --app-plugins magento --offline --report-json
fad-checker -s ./cms --app-plugins joomla,prestashop,typo3 --offline --report-json
```

Wave 2 recognizes these product layouts and component metadata:

| Plugin | Tested source files / layout | Version authority | Advisory coverage |
| --- | --- | --- | --- |
| Joomla | 5.4.1 core manifest plus `libraries/src/Version.php`; typed extension XML under components, modules, plugins and templates | Runtime version constants, corroborated with the core manifest; extension `<version>` is its own version | Application advisories not yet qualified; Composer packages use the standard OSV/Packagist lanes |
| PrestaShop | 8.2.1 source `composer.json`, `config/config.inc.php` and installer version; installed `config/settings.inc.php`, static module PHP metadata, `config/theme.yml` | Installed `_PS_VERSION_` ahead of the installer source version; module `$this->version` and theme `version` | Application advisories not yet qualified; Composer/npm scans remain separate |
| TYPO3 | 13.4.2 source `typo3/sysext/core/ext_emconf.php`; Composer installation with `typo3/cms-core` lock; classic extensions | Locked `typo3/cms-core` for Composer sites, otherwise the literal core `ext_emconf.php` version | Application advisories not yet qualified; locked public Composer packages use OSV/Packagist |
| Magento / Adobe Commerce | 2.4.7-p3 Magento source markers; Composer product edition lock, `app/code` modules and `app/design` themes | Exact locked `magento/product-*` version, including `-pN`; a module's XML `setup_version` is a database schema version, not its code version | Adobe product bulletins are not parsed as a complete machine feed; application advisories remain not-run |

A missing `composer.lock` leaves package versions and dependency origins incomplete. The four wave-2 plugins also mark product lifecycle as `not-run`: community support, paid support and deployed patches need separate evidence. Magento product packages from `repo.magento.com` are not queried against Packagist; their publisher bulletins require separate review. Components found on disk do not prove activation, and no plugin infers that a patch file was applied. `--scan-context component` also recognizes a standalone extension for each wave-2 CMS when its local metadata is valid.

`--private-component` takes a path relative to `--src` and can be repeated. A WordPress plugin with an `Update URI` header is also classified as private automatically, even if a public slug was declared; [WordPress documents this header for third-party updates](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/). A private WordPress plugin or custom Drupal module stays separate from public catalogue identities; Composer CVEs in its own lockfile are attributed to that component. Shared dependencies retain one physical finding with multiple proven owners. WordPress classic and Bedrock layouts and Drupal Composer and Drupal 7 layouts are recognized. Components found on disk are inventoried even when runtime activation cannot be established.

`--scan-context component` treats `--src` as a standalone WordPress plugin or theme directory when its root header identifies it. It inventories that component and its Composer dependencies without inventing a WordPress core installation. The default `source` and explicit `installation` contexts describe how the input was obtained; neither proves runtime activation or a deployed configuration.

`--wordfence-feed` reads a local JSON snapshot of the Wordfence Intelligence v3 **production** feed. It makes no network request. `--public-component path=slug` explicitly declares the public WordPress catalogue slug for an installed plugin or theme; it can be repeated. This declaration is recorded as `user-declared`, not independently verified. A directory name or display name alone never authorizes a public advisory match. Private components are never matched to that catalogue and retain incomplete advisory coverage. A feed snapshot supplied by the operator must be complete and current for its `no-match` results to be meaningful; fad-checker cannot prove those properties from the JSON file alone. Coverage records retain its SHA-256 and local file modification time, which do not establish its download date. Advisory records retain Wordfence identifiers, references and copyright notices. See the [Wordfence v3 feed documentation](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) for obtaining a key and the feed usage terms.

`--drupal-advisories` reads a local snapshot of the [official Drupal Composer security-advisories response](https://packages.drupal.org/8/packages.json). Save it as `{ "queriedPackages": ["drupal/core", ...], "advisories": { ... } }`; `queriedPackages` must list every package requested from the API, including those omitted from its response because no advisory was returned. Unlisted packages retain `CMS_PACKAGE_NOT_QUERIED` and no negative conclusion. Drupal 7 remains outside the current community security-advisory coverage. Drupal's advisory ratings are kept separately from CVSS scores; the report shows their original rating and the derived gate severity.

`--prestashop-advisories <file>` and `--typo3-advisories <file>` read a local snapshot of the vendor's own [GitHub repository security advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories) (PrestaShop/PrestaShop, TYPO3/typo3), the machine-readable channel those publishers maintain themselves. Save the API's array as `{ "advisories": [ ... ], "_fadSnapshot": { "collectedAt": "..." } }` (a bare array is accepted too, but then `--max-advisory-age` will refuse it until a collection date is declared). The whole repository feed is fetched once and matched per inventoried composer coordinate: `prestashop/prestashop` for the PrestaShop core, `typo3/cms-core` and the `typo3/cms-*` system extensions for TYPO3. The publishers' range spellings are normalized before the shared Composer evaluation — PrestaShop's "< 8.2.6 and < 9.1.1" (two affected branches, one fix each) versus ">= 8.0.0 and < 8.1.1" (one interval), TYPO3's comma-joined hyphen intervals "13.0.0-13.4.33, 14.0.0-14.3.5" (alternative branches) — and the ~30 2020-era PrestaShop records whose package identity is empty in the official feed are attributed to the PrestaShop core coordinate with a documented inference, never silently dropped. An unbounded published range ("> 1.7.0.0") is only decidable through its `patched_versions` bound; a version at or above the publisher's patched release is fixed, never flagged. Joomla and Magento/Adobe Commerce have no machine-readable publisher feed (verified 2026-09-23: empty GitHub advisory lists; their bulletins are HTML pages), so those lanes stay `not-run (CMS_ADVISORY_NOT_QUALIFIED)`.

`--wp-checksums <file>` reads a local snapshot of the official [api.wordpress.org core checksums](https://developer.wordpress.org/rest-api/reference/core-checksums/) (`{ "checksums": { "<file>": "<md5>" }, "version": "...", "locale": "..." }`) and compares the WordPress core files of every inventoried instance against it. `--wp-checksums-live` fetches that reference live, pinned to each instance's observed core version and `--wp-checksums-locale` (default `en_US`). Divergences are **diagnostics, never CVE findings**: `CMS_FILE_MODIFIED` (the file differs from the official distribution), `CMS_FILE_MISSING` (the reference file is absent from the tree — a source checkout is not the distribution archive, so this does not flip the verdict), `CMS_FILE_EXTRA` (an unexpected file inside `wp-admin/` or `wp-includes/`, the controlled perimeter; `wp-content/` is user land and is never flagged), reported under the `integrity` capability with `affected` only on modified or unexpected core-directory files. A reference pinned to another version (`CMS_CHECKSUMS_REFERENCE_MISMATCH`) produces no verdict rather than fake divergences.

An explicitly configured advisory file requires its corresponding `--app-plugins` selection. Invalid JSON, an invalid feed schema, or an unreadable configured file exits with code `2` before any report is written.

`--max-advisory-age <duration>` (e.g. `72h`, `30d`) bounds the age of every configured advisory snapshot. A snapshot's file modification time proves nothing about when it was collected, so the date must be declared **inside the snapshot file**: a top-level `collectedAt` or `generatedAt` ISO 8601 string, or a reserved `_fadSnapshot: { "collectedAt": "..." }` object (the Wordfence v3 feed is a flat UUID-keyed map, so the reserved key is the only metadata it tolerates). A snapshot without a declared date, a malformed date, or one older than the limit exits with code `2` before any report is written. A declared date also travels with the coverage provenance (`sourceSnapshot.collectedAt`) whether or not the limit is set.

Live sources are the alternative to operator-supplied files. `--spip-advisories-live` queries NVD's SPIP product CVEs (`cpe:2.3:a:spip:spip`) — the only machine-readable SPIP source that exists (no publisher API, no Packagist package); an NVD API key is optional and only lifts the rate limit. `--drupal-advisories-live` queries the official `https://packages.drupal.org/8/security-advisories` endpoint (announced by the packages.drupal.org Composer descriptor; no authentication) for exactly the inventoried public `drupal/*` identities — private components are never sent. `--prestashop-advisories-live` and `--typo3-advisories-live` page the publishers' GitHub advisory feeds (unauthenticated, subject to GitHub's rate limits), and `--wp-checksums-live` fetches the official api.wordpress.org checksums reference; each can take an optional URL override for a mirror of the same API. Wordfence publishes a [free production feed with bearer authentication](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/). Set `WORDFENCE_API_KEY` (recommended, to keep it out of the process command line) or pass `--wordfence-api-key <key>`; the key alone selects the official production endpoint, or `--wordfence-feed-url <url>` can override its URL. A live Wordfence request without a key stops with code `2` and an explanatory warning. A WordPress instance without either a local feed or a live key gets an explicit warning and incomplete advisory coverage. A fetched snapshot is stamped `_fadSnapshot.collectedAt` at collection time (so `--max-advisory-age` accepts it by construction), written atomically to `~/.fad-checker/advisory-snapshots/<provider>.json` for offline reuse, and recorded in coverage with `completeness: "tool-fetched"`. Those cached snapshots are consumed **automatically — in every mode**: the lanes a scan runs are a function of the cache state, not of online/offline, so `fad-checker -s <proj>` online and `fad-checker -s <proj> --offline` in the air-gapped enclave (same command, same options, warmed by the same phase 2) produce identical reports — no `--drupal-advisories` / `--prestashop-advisories` / `--typo3-advisories` / `--wp-checksums` flag needed. The files travel with `--export-cache` / `--import-cache`; `--import-anonymized` **warms them from the descriptor alone** (its `applications` section carries the public product identities — type, core version, inventoried public components — the phase-1 export emits): the Drupal feed for the union of the lock's `drupal/*` coordinates and the inventoried public identities, the PrestaShop/TYPO3 repository feeds, one WordPress checksums reference per declared core version (pinned by the warming run's `--wp-checksums-locale`, so both phases must agree on it), and the Wordfence catalogue when the warming machine holds an API key (the key itself never travels — the enclave reads the snapshot back without one). An explicit flag or live URL always wins, the fallback only engages when the source's application plugin is selected, and the file goes through the same schema and `--max-advisory-age` validation as an operator-supplied one. The WordPress checksums reference is pinned by version and locale, so its fallback resolves per instance. Live sources refuse to run under `--offline` (exit `2`); an air-gapped scan supplies a local feed snapshot — the tool's own cache counts as one. A failed or invalid live response stops the scan before any report, and a live source still requires its `--app-plugins` selection.

Symfony Flex `symfony.lock` recipes and `extra.symfony.require` are context. Installed package versions come from `composer.lock`. Extraction with `-t` also mirrors `symfony.lock`. The Symfony and Laravel application-advisory capabilities are currently recorded as `not-run (CMS_ADVISORY_NOT_QUALIFIED)`: their CVEs come from the standard Composer lane (OSV/Packagist), and a capability that never ran never becomes a clean result. WordPress and Drupal advisories run through the Wordfence and Drupal sources configured above. `--fail-on-incomplete` exits with code 2 after writing the partial report when a requested capability is incomplete. The default capability set is `inventory,advisories`.

Report subsections with no results are omitted, and the remaining ones are numbered in order. CMS/framework CVEs appear first under CVE when present; application inventory and coverage remain in scan context even when no advisory matches. The six root chapters remain visible.

## Outputs

Every output has its own `--report-<type>` flag, each taking an **optional** path. Give a path to write there; omit the path to use a default name under `--report-output` (default dir `./fad-checker-report`). **If you pass no `--report-*` flag, HTML + `findings.json` are written by default**; pass `--no-report` to write nothing (gate-only / CI). Selecting any `--report-*` flag writes exactly that set — e.g. `--report-sbom` alone writes only the SBOM, no HTML.

| Flag | Default name | Effect |
| --- | --- | --- |
| `--report-html [file]` | `cve-report.html` | The self-contained HTML report (inline CSS, no external assets). |
| `--report-doc [file]` | `cve-report.doc` | The same report as a Word-compatible `.doc`. |
| `--report-xlsx [file]` | `findings.xlsx` | Excel workbook with a summary and one sheet per populated category, including application ownership, coverage, warnings, provenance and diff when present. Text is stored as text, never evaluated as a formula; an explicit path must end in `.xlsx`. |
| `--report-sbom [file]` | `sbom.cdx.json` | A **CycloneDX 1.6** SBOM with `vulnerabilities` inline (a VDR). Components carry purls + detected licenses (+ `fad:provenance`/`fad:location` for embedded-jar coords); vulnerabilities carry CVSS ratings, CWEs, affected purls, and `fad:epss` / `fad:kev` / `fad:priorityBand` properties. |
| `--report-csaf [file]` | `csaf-vex.json` | A **CSAF 2.0 VEX** (`csaf_vex`) document: a `product_tree` of every dep (purl-identified) plus per-CVE `product_status.known_affected`, `cvss_v3` scores, a KEV `exploited` flag, and prioritization notes. |
| `--report-json [file]` | `findings.json` | A flat **findings JSON** (fad's own format): every chapter (CVE/EOL/obsolete/outdated/licenses/vendored) + an `unmanaged` array (native-binary inventory with identity/integrity/signals), an `embedded` array (every JAR/WAR/EAR coordinate, vuln or not, with `vulnCount`/`maxSeverity`), EOL entries carrying their `productSlug`/`via`/`viaKey` origin + `status`/`cycle`/`support` and, for grouped frameworks, `anchor`/`components[]` (each component with its own `manifestPaths`, or `scope:"transitive"` + `via` chain), + a summary, easy to diff between audits and post-process. |
| `--report-sarif [file]` | `fad.sarif` | A **SARIF 2.1.0** log for GitHub Code Scanning / GitLab: one rule per CVE with `security-severity` (drives GitHub's severity), KEV tags, and the manifest (or embedding jar) as the result location. |
| `--report-output <dir>` | `./fad-checker-report` | Base directory for any output left at its default name. |

```bash
# default: HTML + findings.json into ./fad-checker-report
fad-checker -s ./proj

# only the machine artifacts, default names under a custom dir
fad-checker -s ./proj --report-output ./out --report-sbom --report-csaf --report-json --report-sarif

# explicit paths
fad-checker -s ./proj --report-sbom sbom.cdx.json --report-sarif fad.sarif
fad-checker -s ./proj -r html,json,xlsx            # add an Excel workbook to the default pair
```

All honour `--offline` (they render from whatever the scan already resolved).

## CI gating & triage

| Flag | Effect |
| --- | --- |
| `--fail-on <level>` | Exit non-zero when a **production or embedded-binary** finding meets the level: `low`/`medium`/`high`/`critical` (severity) or `kev` (only CISA-known-exploited). Default `none`. Outputs are written first, so artifacts always land. An invalid level hard-fails (exit 2) rather than silently disabling the gate. |
| `--fail-on-new` | Exit non-zero when the scan introduces any **new production CVE finding** vs `--baseline` (see *Differential audits*). Combinable with `--fail-on` — either condition fails the build. |
| `--ignore <file>` | Suppress findings. One rule per line: `CVE-2021-44228` (anywhere), `CVE-… org.apache.*` (coord/purl glob), `* npm:lodash` (any CVE for a coord); text after `#` is the reason. |
| `--vex <file>` | Ingest a **CSAF VEX**: CVEs marked `known_not_affected` / `fixed` are suppressed (products mapped back to coords by purl — round-trips fad's own `--report-csaf`). |

Suppressed findings are dropped from the report chapters and from `--fail-on`, but kept (flagged `suppressed`) in the JSON/XLSX/SBOM/CSAF/SARIF exports, and the count is noted in chapter 0.

```bash
# Fail the pipeline only on exploited-in-the-wild vulns, minus accepted risks
fad-checker -s . --fail-on kev --ignore .fadignore --report-sarif fad.sarif
```

## Differential audits (`--baseline` / `fad diff`)

Repeat audits care about **what changed**. Diff the current scan against a prior
findings JSON (from `--report-json`): the report gains a **"Δ Changes since baseline"**
chapter, the JSON export gains a `diff` block, and CI can gate on *new* findings.

| Flag / command | Effect |
| --- | --- |
| `--baseline <file>` | Diff this scan against a prior `findings.json`. Adds the Δ chapter to the report + a `diff` block (summary + new/fixed CVEs) to `--report-json`. |
| `--fail-on-new` | Exit non-zero if any **new production CVE finding** appeared vs the baseline. |
| `fad diff <baseline.json> <current.json>` | Standalone diff of two exports (no scan). Prints new/fixed/unchanged per category + the new CVEs; `--report-json <out>` writes a `fad-diff/1` document; `--fail-on-new` sets exit 1 on new production CVEs. |

A finding's identity is `CVE id + ecosystem + coordinate + version`, so a version bump
shows the old finding *resolved* and the new one *added*. Suppressed / CPE-filtered CVEs
are diffed but excluded from the `--fail-on-new` signal.

```bash
# CI: fail only when this build introduces NEW vulnerabilities vs main's last report
fad-checker -s . --report-json this.json --baseline main.json --fail-on-new

# Ad-hoc comparison of two historical reports
fad-checker diff audit-q1.json audit-q2.json --report-json delta.json
```

## Report integrity & methodology

Every run aimed at a deliverable is **reproducible** and **tamper-evident**:

- **Provenance manifest** — each report (and the JSON export's `provenance` block) records
  the tool version, run mode (offline/online), the findings-affecting configuration, and
  the **freshness of every data source** (CVE index, OSV, NVD, KEV, EPSS, endoflife, the
  registry caches) read from `~/.fad-checker/`. An `--offline` re-run against the same cache
  (ship it with `--export-cache`) reproduces the findings.
- **Methodology chapter** — appendix 12 of the HTML/`.doc` report renders that source table
  plus an explicit statement of **what fad-checker does *not* assess** (reachability,
  runtime config, secrets/IaC, first-party code, malware beyond the OSV/CIRCL signal, legal
  license advice) — the audit's scope, stated up front.
- **Integrity manifest** — a standard **`SHA256SUMS`** is written beside the artifacts,
  verifiable with `sha256sum -c SHA256SUMS`. `--no-checksums` disables it. (Sign the
  manifest with your own key for a full chain of custody.)

## Supply-chain risk (malware / typosquat)

Two signals beyond known CVEs:

- **Known-malicious packages** — any OSV `MAL-…` / malicious advisory that matches a
  resolved dep is flagged `malicious` in the report + JSON, and **always blocks the gate**
  (any `--fail-on` level, like a compromise). Always on; no flag needed.
- **Typosquats** (`--typosquat`, opt-in) — a *heuristic*: flags an npm/PyPI dependency
  whose name is one Damerau edit (incl. an adjacent transposition: `lodahs`↔`lodash`) from
  a popular package in `data/popular-packages.json`. Catches typosquat/"slopsquat" names
  no vuln DB knows yet. Conservative (distance 1, length ≥ 5, non-scoped) — on a clean
  25-module project it flagged 0 of 1331 deps — but it **is** a heuristic: review each
  hit, and add legitimate near-misses to the popular list to suppress them.

```bash
fad-checker -s . --typosquat                       # add the typosquat heuristic
fad-checker -s . --fail-on critical                # malware blocks even below 'critical'
```

## Offline / cache control

```bash
# Use cached data only, no network (works for everything)
fad-checker -s . --offline

# Per-source offline
fad-checker -s . --cve-offline                  # use cached CVE index only
fad-checker -s . --cve-refresh                  # force re-download of CVE bundle
fad-checker -s . --retire-refresh               # force re-scan with retire.js (ignore cache)

# Offline-COMPLETE OSV (Maven): import the full OSV database once, then match offline
# regardless of the per-dep OSV cache (the OSV-Scanner air-gap model).
fad-checker -s . --osv-db                        # online: download (~9 MB) + match
fad-checker -s . --osv-db --offline              # offline: match against the imported DB
fad-checker -s . --osv-db --osv-db-refresh       # force re-download of the OSV DB

# Cache export / import (useful for air-gapped boxes)
fad-checker --export-cache fad-cache.tar.gz
fad-checker --export-cache fad-cache.tar.gz --include-config   # bundle NVD key too
fad-checker --import-cache fad-cache.tar.gz                    # merge into the existing cache
fad-checker --import-cache fad-cache.tar.gz --replace           # wholesale swap, previous kept as .bak
fad-checker --import-cache fad-cache.tar.gz --replace --force   # wholesale swap, no backup
```

The cache archive bundles everything under `~/.fad-checker/` (except `config.json`),
including retire.js findings **and** the warmed retire.js signature DB, so an importing
machine can scan vendored JavaScript fully offline.

**Import merges, it doesn't overwrite.** An enclave is usually already warm from earlier
air-gapped runs, so `--import-cache` unions the archive with what's there rather than
swapping it in: per-key caches (OSV/NVD/POM/retire entries) merge file by file, the
`entries{}` maps (versions, registry answers, EOL, EPSS, …) merge key by key with the
fresher value winning, and whole-corpus snapshots (KEV, the `cve-data/` index) take the
freshest side as a block — so importing a *stale* archive can't roll a fresher enclave
back. `config.json` is never touched: it holds the machine's own NVD key and private
registry credentials, and `--export-cache` doesn't bundle it, so an import could only
ever lose it. Pass `--replace` for the old wholesale swap (previous cache kept as
`~/.fad-checker.bak-<timestamp>`), or `--replace --force` to swap without a backup.

### Zero-data-sent guarantee (air-gap)

Under `--offline`, `fad-checker` makes **zero network calls** — it reads only the warmed
caches under `~/.fad-checker/` and never transmits any dependency, path, hostname or
finding off the machine. This is the property a regulated / air-gapped engagement needs, and it
is enforced two ways:

- **Regression-tested** (`test/offline-guarantee.test.js`): the network-heavy Maven paths
  (`fetchPom`, `effectivePom`, `resolveTransitiveDeps`, the per-module Maven resolution) are run on
  a *cold* cache with a tripwire fetcher that throws if touched — so any future change that
  sneaks a network call into the offline path fails CI.
- **Auditor-reproducible** — run the scan inside a network namespace that has **no
  interfaces at all** and confirm the output is byte-identical to a normal offline run:

  ```bash
  # true air-gap: no network device exists inside the namespace
  unshare -rn node fad-checker.js -s ./proj --offline --report-json /tmp/airgap.json
  # → exit 0, and /tmp/airgap.json is identical to a normal `--offline` run
  ```

  (Measured on a 25-module Spring/JSF project: identical findings, ~1.8 s.)

> **Compiled binary, no `node`/`retire` needed:** the bun-compiled single binary
> (`dist/fad-checker`, `.exe`, `-macos`) statically bundles the retire.js CLI and
> re-execs itself to run it — so vendored-JS scanning works from the
> lone binary on an air-gapped box with no Node.js and no `retire` on `PATH`. The only
> input it needs is the signature DB warmed in phase 2 (carried in the cache archive).
> If retire still can't run, the failure is reported as a chapter-0 warning (run `-v`
> for the exact reason) instead of an empty chapter.

## Shared proxy-cache server (`serve-cache` / `--proxy-cache`)

A scan of a real project makes hundreds of registry / advisory lookups — and every
machine that scans makes them again. `serve-cache` turns one machine into the cache
point for the others: one upstream call per provider resource per TTL for the whole fleet, on a
persistent on-disk base that survives restarts. The server's store lives in its **own
root** (`~/.fad-checker-proxy-cache/`), deliberately outside the scan's `~/.fad-checker/`
cache dir — the client caches and the shared base are two different roles and are never
bundled, swapped or merged together by `--export-cache` / `--import-cache`.

```bash
# Terminal 1 — start the server (default 127.0.0.1:8321, store ~/.fad-checker-proxy-cache/)
fad-checker serve-cache
fad-checker serve-cache --port 9000 --host 0.0.0.0 --token s3cret   # shared across machines
fad-checker serve-cache --nvd-key <key> --wordfence-key <key> --github-token <t>
fad-checker serve-cache --upstream-proxy http://corp-proxy:3128     # the server itself behind a corporate proxy

# Then every scan (same machine, CI runners, other developers) points at it:
fad-checker -s ./proj --proxy-cache http://127.0.0.1:8321
FAD_PROXY_CACHE_TOKEN=s3cret fad-checker -s ./proj --proxy-cache http://cache-host:9000
```

| Flag (serve-cache) | Effect |
| --- | --- |
| `--port <n>` / `--host <h>` | Listen address (default `127.0.0.1:8321`; `0.0.0.0` to share — use `--token`) |
| `--cache-dir <dir>` | Store location (default `~/.fad-checker-proxy-cache/` — its own root, never inside the scan's `~/.fad-checker/` caches) |
| `--ttl <seconds>` | Override every per-source TTL (defaults: OSV 12h, NVD + endoflife.date 7d, registries/EPSS/KEV/deps.dev 24h) |
| `--swr` / `--no-swr` | An expired entry is served stale while a refresh runs in the background (default ON; `--no-swr` makes expiry a blocking refetch) |
| `--max-body-mb <n>` | Persistence limit per response (default 32 MiB); larger responses use a temporary spool, retired after 30 s when readers finish. CVE archives have a separate 1 GiB persistence limit |
| `--max-transfer-mb <n>` | Hard upstream body limit, including chunked bodies (default 1024 MiB); JSON batches additionally cap at 32 MiB |
| `--max-store-mb <n>` | Combined metadata, body and spool budget (default 2048 MiB); evicts the oldest collected unpinned entries, refuses writes if space cannot be freed |
| `--max-entries <n>` | Persistent entry limit (default 10000) |
| `--upstream-timeout <seconds>` | Deadline covering upstream headers and body, including background and batch requests (default 120 s) |
| `--max-concurrent <n>` | Maximum active upstream transfers (default 16); excess distinct requests fail, cached readers continue |
| `--nvd-key` / `--wordfence-key` / `--github-token` | API keys the **server** injects upstream (flags > `NVD_API_KEY` / `WORDFENCE_API_KEY` / `GITHUB_TOKEN` env > `--set-nvd-key` config). NVD/GitHub clients can use the server credentials. `--wordfence-live` activates the official feed using the server key alone, including `--import-anonymized` warming. Custom feed URLs still require a client key. Without a server key, a client-sent credential is forwarded as-is |
| `--upstream-proxy <url>` | Route the server's own upstream fetches through a corporate forward proxy |
| `--token <t>` | Require a token on every endpoint except `__health`; scans send it via `FAD_PROXY_CACHE_TOKEN` or `--proxy-cache-token` without replacing source credentials |

Behaviour worth knowing:

- **Only fad's public data sources are routed and cached by scanner clients** (npm/PyPI/Packagist/NuGet/RubyGems/Go
  proxy/Maven Central, OSV, NVD, EPSS, KEV, endoflife.date, deps.dev, CIRCL,
  GitHub publisher advisories, Wordfence and WordPress checksums). Private registry
  requests go direct from the scanner.
- **Single-flight**: ten instances requesting the same packument make one upstream call. OSV package/version, Packagist advisory package, and EPSS CVE score each have their own key even when requests arrive in overlapping batches.
- **Stale-if-error**: a failed connection, broken response body or upstream 403/429/5xx serves the stale copy instead of failing
  (`x-fad-proxy: stale`); a definitive 404 is mirrored as-is (that is how private
  packages are detected). With no cached copy, the client receives the upstream failure.
- The scanner sends `POST /v1/resource` with a provider, data type and subject. The server builds the upstream request and caches by resource identity. OSV, Packagist and EPSS batches are split into individual cache entries; custom/private registry URLs go direct through the same router.
- Resource responses carry `x-fad-proxy` (including `pass`/`error` for failures); `GET /__stats`
  shows the counters, `POST /__clear` wipes the base.
- A dead proxy-cache server uses the local resource cache when that cache covers the request. Otherwise the source-health retry schedule runs and the scan aborts with exit 2 for a required source.
- `--proxy-cache` and `--offline` are exclusive (offline makes no requests at all).

GitHub pagination links are retained in both caches. Entries created before this
metadata was preserved are fetched again; an old headerless GitHub page cannot
establish a complete feed. CMS snapshots retain the upstream collection time
reported by the cache, and `--max-advisory-age` checks live as well as local data.
Without that option, stale fallback has no maximum age.

Transfers are spooled with stream backpressure before a successful response is
sent. A disconnected requester does not cancel shared work needed by followers;
that work remains bounded by the upstream deadline and transfer/store budgets.
Cached readers use streaming backpressure and an inactivity timeout. Limits are
reported by `GET /__stats` with `storeBytes`, `bodyBytes` and `activeUpstream`.
Sizes use binary MiB; the store budget accounts for payload and metadata bytes,
not filesystem block allocation. Leave filesystem headroom for directories and
block overhead. Large individual JSON batches have an additional 32 MiB bound.

One server owns each store directory (`server.lock`). Startup removes abandoned
spools and unreferenced body generations. A dead owner's PID allows recovery;
an unreadable lock or a reused PID requires the operator to verify no server uses
that directory before removing the lock. Do not share this directory with a second
server or a scanner process. Metadata is published only after its body is complete.

A shared token grants resource access and cache administration. HTTP does not
encrypt that token or forwarded source credentials; terminate TLS when crossing
an untrusted network.

```bash
fad-checker serve-cache --wordfence-key <key> --max-store-mb 4096 --upstream-timeout 180
fad-checker -s ./wordpress --proxy-cache http://127.0.0.1:8321 --wordfence-live
fad-checker --import-anonymized deps.json --proxy-cache http://127.0.0.1:8321 --wordfence-live
```

When neither client nor server has a Wordfence key, the server refuses the request
before contacting Wordfence. The key is never exported with snapshots.
CMS snapshot imports compare the declared collection date, even if a copy has a
newer filesystem date. Semantic cache imports publish each body/metadata pair
atomically; interruption preserves the previous committed entry. This is a
per-entry guarantee, not a transaction spanning the entire imported cache.

### Corporate forward proxy (`--proxy`)

```bash
fad-checker -s ./proj --proxy http://corp-proxy:3128
```

Routes **every** outbound request through a corporate forward proxy (Node >= 24 or
bun — Node only honours `HTTP(S)_PROXY` with `NODE_USE_ENV_PROXY` set at process
start, so fad re-execs itself with the environment applied; verified: a mid-run
`process.env` change is silently ignored). A `--proxy-cache` URL in the same command
is added to `NO_PROXY` — traffic to the shared cache is local and stays out of the
tunnel. For the server-side equivalent see `serve-cache --upstream-proxy` above.

## Anonymized descriptor (air-gapped audits)

For an offline/confidential system that can't reach the vuln databases, split the scan
across machines using dependency coordinates and filtered version hints. Manifest paths
and registry URLs are removed. Private coordinates cannot be identified offline: exclude
internal dependencies and review the complete descriptor before transfer. The detailed
report is produced **back offline**.

```bash
# Phase 1 — OFFLINE (audited machine): export the anonymized descriptor, then stop.
#   -e excludes private/internal packages (offline we can't classify private vs public).
fad-checker -s ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   deps.json is plain JSON (schema "fad-deps/1") — review it before transfer.

# Phase 2 — ONLINE (any machine, NO --src): warm the coordinate-keyed caches.
fad-checker --import-anonymized deps.json     # OSV/NVD/CVE/registry/EOL + retire signatures
fad-checker --export-cache fad-cache.tar.gz   # carry the warmed caches back

# Phase 3 — OFFLINE (audited machine): full report with real paths/manifests.
fad-checker --import-cache fad-cache.tar.gz   # merged into the enclave's own cache
fad-checker -s ./proj --offline               # re-collect locally + cache hits → full report
```

Why it works: fad-checker's caches are keyed by *coordinate* / *vuln id*, never by path,
so warming them online and replaying offline yields cache hits. The descriptor keeps
`ecosystem`/`ecosystemType`/`namespace`/`name`/`version`/`versions`/`scope`/`isDev` and
drops manifest paths, registry URLs, integrity hashes and parent chains. The phase-2
report is itself path-free; vendored-JS (retire.js) findings come from phase 3 (retire
needs the actual `.js` files), using the signature DB warmed in phase 2.

### Versionless Spring Boot deps across the enclave

A dep whose version is managed by an external `<parent>` (`spring-boot-starter-parent`)
or import BOM (`spring-boot-dependencies`) is declared **without a version**, and the CVE
cache is keyed by `coordinate + version` — so `spring-boot-starter-actuator` can't warm
its cache until something resolves `2.7.18`. In Phase 2 there's no source tree to derive
that from, which would otherwise force **two** round-trips (one to learn the version, one
to warm its CVEs). To avoid that, the descriptor also carries a small `maven` hints block:

```json
"maven": {
  "externalParents": [{ "groupId": "org.springframework.boot", "artifactId": "spring-boot-starter-parent", "version": "2.7.18" }],
  "importBoms": [],
  "propertyOverrides": { "log4j2.version": "2.17.1" }
}
```

Phase 2 replays the parent/BOM backfill from these coords (resolving them from Maven
Central), so the versions — **including a `<log4j2.version>` you patched**, honored via
`propertyOverrides` — resolve and their CVE caches warm in **one** exchange. Parent/BOM
coordinates may themselves be private; review them before transfer. Version properties
are filtered by name and value, excluding credentials, URLs, paths and unrelated build
settings. Custom property names referenced by local version expressions are retained
when their values pass the version filter. A custom override used only inside an
uncached external parent may be omitted: review the exported hints and resolved versions
in that case. If your enclave policy prefers it, you can still run two exchanges instead.

> **If instead your online/warming machine DOES have the source tree** (the common
> `--export-cache` workflow, not the anonymized one), none of this applies: the parent
> POMs are fetched and cached during the online run, and the offline `-s ./proj --offline`
> re-parses the real POMs and backfills from the cached parents. One exchange, no hints
> needed. The hints exist only for the source-never-leaves-the-enclave case above.

## Custom registries (private repos)

`fad-checker` queries each ecosystem's public registry by default. Register private ones for **`maven`, `npm`, `pypi`, `ruby`, `go`, `nuget`, `composer`** so transitive resolution, outdated/deprecation and license lookups reach them.

| Flag | Effect |
| --- | --- |
| `--add-repo <eco> <name> <url> [--auth user:pass] [--token TOK]` | Persist a registry (in `~/.fad-checker/config.json` under `registries.<eco>`). |
| `--remove-repo <eco> <name>` | Remove a persisted registry. |
| `--list-repos` | List configured registries, grouped by ecosystem (auth masked). |
| `--repo <eco>=<url>` | One-off, not persisted; **repeatable**; auth via inline `https://user:pass@host/`. |

```bash
fad-checker --add-repo maven   nexus     https://nexus.acme.com/repository/maven-public/ --auth alice:s3cr3t
fad-checker --add-repo npm     verdaccio https://npm.acme.com/                            --token "$NPM_TOKEN"
fad-checker --add-repo nuget   azure     https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json --token "$AZ_TOKEN"
fad-checker --add-repo composer satis    https://composer.acme.com/                       --auth alice:s3cr3t
fad-checker --list-repos
fad-checker -s ./proj --repo npm=https://npm.acme.com/ --repo maven=https://nexus.acme.com/repository/maven-public/
```

Registries are tried **in declared order, the public registry last** (first 2xx wins). `--auth user:pass` → `Basic <base64>`; `--token TOK` → `Bearer TOK`. Responses are cached per coordinate. Same-API constraint per ecosystem: **PyPI/Ruby** custom bases must expose the same JSON API as the public one (`<base>/<pkg>/json`, `<base>/<gem>.json`), not a bare PEP 503 simple index; **NuGet** bases speak the v3 registration API — a service index (`…/index.json`) is auto-resolved to its `RegistrationsBaseUrl`; **Composer** bases are queried via the v2 metadata API (`<base>/p2/<vendor>/<pkg>.json`).

## Configuration file & environment

Reusable defaults come from (lowest priority first): **`~/.fad-checker/config.json`** (global) → **`FAD_CHECKER_ENV`** (a CLI-flag string) → **config file** (`--config <file.json>`, else `./.fad-env.json`, JSON) → **CLI flags** (always win). A file/env value only fills an option you did not pass on the CLI; `registries` are unioned across all layers.

```bash
fad-checker --config ./ci/fad-env.json                         # JSON file of defaults
FAD_CHECKER_ENV='--fail-on high --no-nuget' fad-checker -s ./proj   # flag string of defaults
```

```jsonc
// ./.fad-env.json — keys mirror the CLI options (camelCase)
{
  "source": "./my-project",            // alias of --src / "src"
  "exclude": "^(com\\.acme|client)\\.",
  "excludePath": ["packages/legacy/**", "**/fixtures/**"],
  "failOn": "high",
  "noNuget": true,
  "offline": true,
  "registries": {
    "npm":   [{ "name": "verdaccio", "url": "https://npm.acme.com/", "token": "…" }],
    "maven": [{ "name": "nexus", "url": "https://nexus.acme.com/repository/maven-public/", "auth": "user:pass" }]
  }
}
```

The source directory accepts `-s`, `--src`, `--source` and the JSON key `"source"`/`"src"` interchangeably.

## NVD API key

NVD's public rate limit is 5 requests / 30s without a key. The free key bumps it to 50 / 30s — **10× faster** for the enrichment step.

```bash
# Get a key in 30 seconds: https://nvd.nist.gov/developers/request-an-api-key
fad-checker --set-nvd-key YOUR_KEY      # stored in ~/.fad-checker/config.json (mode 0600)
fad-checker --show-config               # confirm it's persisted (key masked)
```

Or pass it ad-hoc via the `NVD_API_KEY` env var.

## Snyk integration

If you have `snyk` installed and authenticated, `fad-checker` can drive it:

```bash
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk
```

This:
1. Generates the cleaned POM tree at `../proj-clean/`.
2. Runs `snyk test --all-projects --json` against it.
3. Merges Snyk's findings into the report — entries present in both `fad-checker` and Snyk are tagged `source: "both"`.

`--snyk` requires `-t` (Snyk needs a real POM tree to scan).

If the snyk run itself **fails** — not authenticated, an unsupported project, a timeout — fad-checker now reports it as a `Snyk run failed: <reason>` warning and continues the scan with fad-checker's own findings. (Earlier versions parsed snyk's error-shaped `--json` output as zero vulnerabilities and printed a misleading `Snyk: 0 findings merged`.) A snyk exit of 1 is **not** a failure — it just means snyk found vulnerabilities, which are merged as usual.

## Read-only vs write mode

| Mode | Trigger | What runs | Disk writes |
| --- | --- | --- | --- |
| Read-only (scan) | `-t` omitted (default) | full scan + report | Only `~/.fad-checker/` caches and the report dir |
| Extraction | `-t <dir>` | walk + reactor linking + normalised descriptor tree + POM analysis (existence check → private-module list, when online), then stop | The normalised descriptor tree at `<dir>` (replaced only with `--force` if non-empty) + the existence cache |
| Extraction + scan | `-t <dir>` with `--snyk`, a `--report-<type>`, `--fail-on`, `--fail-on-new` or `--baseline` | both of the above | Both of the above |

The `--target` guardrails refuse:
- empty `--src`
- `--target` equal to or a subdirectory of `--src`
- `--target` containing `--src` (including via a symlinked parent)
- a non-empty `--target` unless `--force` is passed; a file or symlink target is always refused

## Verbosity

```bash
fad-checker -s . --verbose   # progress per source (OSV batches, NVD pages, retire scan, …)
```

## Help & version

```bash
fad-checker                  # no arguments: a mini help with the running version (exit 1 — nothing was scanned)
fad-checker -h, --help       # every option
fad-checker -v, --version    # the running version (-V still works; it was the version flag before)
```

> `--verbose` is **long-form only**: `-v` used to mean verbose and now means version, so an old
> `fad-checker -s . -v` prints the version and exits 0 **without scanning**. Grep CI for it.

## Shell completion

```bash
fad-checker --completion bash > /etc/bash_completion.d/fad-checker
fad-checker --completion zsh  > ~/.zsh/completions/_fad-checker
```

## All flags at a glance

```bash
fad-checker --help
```

## Recipes

### CI gate: fail the build on any CRITICAL prod CVE

`fad-checker` exits 0 even when CVEs are found (it's a reporter, not a gate). Wire your own:

```bash
fad-checker -s . --no-nvd > /dev/null
# Then grep the report or parse the structured output (planned).
```

(A `--fail-on critical` flag is a planned addition — track it in issues.)

### Diff two runs

Keep dated copies of the report:

```bash
fad-checker -s . --report-output reports/$(date +%F)
diff reports/2026-04-01/cve-report.html reports/2026-05-01/cve-report.html
```

### Air-gapped scan (anonymized descriptor)

The robust way: export an anonymized descriptor offline, warm caches online from it,
re-scan offline. Exclude private dependencies and review all exported coordinates and
version hints before they leave the secure machine.

```bash
# OFFLINE (audited machine)
fad-checker -s ./real-project -e "^(client|internal)\." --export-anonymized deps.json

# ONLINE (connected machine, no source needed)
fad-checker --import-anonymized deps.json      # warms ~/.fad-checker/ caches from the coords
fad-checker --export-cache fad-cache.tar.gz

# OFFLINE again — full report with real paths
fad-checker --import-cache fad-cache.tar.gz    # merged, the enclave keeps what it had
fad-checker -s ./real-project --offline
```

See the **Anonymized descriptor** section above for what the descriptor contains and why
the round-trip produces a complete report without leaking environment information.
