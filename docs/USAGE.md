# USAGE

The scan entry points are:

```bash
vigievuln scan <path|zip|descriptor.json> [options]
vigievuln system collect [root] -o collect.json
vigievuln system scan <inventory.json|path|docker-image|archive|disk> [options]
```

A system collection defaults to `/`. System scans first resolve an existing local path,
then a local Docker image, then download the image from its registry. `--offline`
requires local data. JSON inputs are identified by their schema. Dependency descriptors
and extracted project trees use `scan`; system inventories and publisher SBOMs use
`system scan`. ZIP project input is extracted to a temporary directory that is removed
after the scan. Air-gapped export, import, cache preparation and scan options keep their
existing meanings.


Every flag, every common workflow, with copy-pasteable commands.

## Synopsis

```text
vigievuln scan <src> [scan options]
vigievuln system scan <archive|rootfs|reference> [image options]
vigievuln login
vigievuln whoami
vigievuln watch <src> --name 'My Project'
vigievuln watch <src> --export fichier.json
vigievuln logout

# Compatible flag-based scan syntax:
vigievuln scan <src> [-t <target>] [-e <regex>] [other options]
```

`vigievuln scan ./code` scans a source tree and writes the usual reports. It accepts the existing scan options. The old collect, analyse, image commands and source flags have been removed.

- `scan <path|zip|descriptor.json>` selects a source tree, project ZIP or dependency descriptor. Contains `pom.xml` and/or `package(-lock).json` / `yarn.lock` or other supported manifests.
- `-t, --target <dir>` — optional. **Extraction mode.** Write a parallel directory of "cleaned" POMs (private/excluded deps stripped, reactor modules linked to each other) to `<dir>` **and mirror every non-Maven lockfile/manifest** (`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`, `composer.lock`/`symfony.lock`, `poetry.lock`/`Pipfile.lock`/…, `*.csproj`/`packages.lock.json`, `go.mod`/`go.sum`, `Gemfile.lock`, …) into it — so **any** scanner pointed at `<dir>` (`snyk test --all-projects` among them) sees **every** ecosystem, not just Maven. Each POM is reduced to the dependency-relevant nodes (coordinates, `properties`, `dependencyManagement`, `dependencies`, `modules`), reactor parents are rewired to their real in-tree `relativePath`, and `${…}` is resolved in coordinates. The run then **stops**: the only network action is the Maven-repository *existence* check, which is also what **identifies your private/internal modules** (coordinates that exist in no configured repository) — skipped under `--offline`, or when no repository answers a 5 s preflight. No CVE/EOL/outdated pass, no report — add `--snyk`, a `--report-<type>`, `--fail-on`/`--fail-on-new` or `--baseline` to also run the scan. A non-empty target requires `--force` because its contents are replaced. Without `-t`, the run is read-only and produces the full report.

## Output

Add `--images` or `-a images` to include referenced container images in a project
scan (off by default). See [Native images and Linux binaries](IMAGES.md) for this
workflow, then the dedicated `vigievuln system scan` command for archives, registry
images, root filesystems, publisher SBOMs and offline inventories.
Discovered references that cannot be inspected are identified in coverage warnings.

By default the HTML report and a `findings.json` land in `./vigievuln-report/` (the JSON so the next run can `--baseline` against it; add `--report-doc` for the Word file). Override with `--report-output <dir>`.

## Ecosystem selection

```bash
# Auto-detect (default): scan whatever pom.xml / package(-lock).json / yarn.lock exists
vigievuln scan .

# Pick ecosystems (codecs). --ecosystem is a list: auto (default) | all | comma list.
# Codec ids: maven, gradle, npm, yarn, composer, pypi, nuget, go, ruby.
vigievuln scan . --ecosystem maven            # Maven only
vigievuln scan . --ecosystem gradle           # Gradle only
vigievuln scan . --ecosystem maven,npm,go     # several, even if only one is auto-detected
vigievuln scan . --ecosystem all              # every supported codec
vigievuln scan . --ecosystem both             # legacy alias for maven,npm

# Opt out of specific codecs (combine freely)
vigievuln scan . -d npm                       # skip npm
vigievuln scan . -d js                        # alias: skip npm + yarn (Maven-only)
vigievuln scan . -d gradle                    # skip Gradle
vigievuln scan . -d pypi,nuget                # skip Python + C#
vigievuln scan . -d go,ruby                   # skip Go + Ruby
vigievuln scan . -d jars                      # skip embedded .jar/.war/.ear scanning
vigievuln scan . -d binaries                  # skip committed native-binary scanning
vigievuln scan . -d certs                     # skip certificate / key-material scanning
vigievuln scan . -d nvd,epss,certs -a licenses,typosquat -o ./audit   # the general shape

vigievuln scan . -a eol-support               # also flag "security-only" frameworks (e.g. Symfony 5.4 LTS since 2024-11-30)
vigievuln scan . --cert-expiry-days 30        # warn on certs expiring within 30 days (default 90)
```

> The individual `--no-npm`, `--licenses`, … flags still work; they are hidden from `--help`
> to keep it to one screen. `--help-all` lists them.

> **Embedded JARs**: committed `.jar`/`.war`/`.ear` archives (vendored libs, Spring-Boot fat-jars, shaded uber-jars) are unzipped in-memory and their Maven coordinates — read from `META-INF/maven/.../pom.properties`, then `MANIFEST.MF`, then the file name — are reported in their own **Embedded binaries** section, grouped by containing archive. The section is a **full inventory** of every embedded coordinate — vulnerable or not (the JAR counterpart of the native-binary and vendored-JS inventories) — with a CVE-status column per coord and the full CVE detail for vulnerable ones. So a committed fat-jar shows up even when nothing inside it is currently vulnerable. Auto when archives are present; `--no-jars` disables it. Archives with no resolvable coordinate are listed in chapter 0.

> **Committed native binaries**: supported PE/ELF/Mach-O files are identified by their content, including extensionless ELF executables, then hashed (SHA-1 + SHA-256). Bounded PE/ELF metadata and Go build information can provide additional evidence. Online checksum lookups use **deps.dev** and **CIRCL hashlookup**; missing or unverified evidence does not establish identity. Results appear in the unmanaged binaries section and JSON export, are cache-aware, and can be disabled with `--no-binaries`. This is not an antivirus scan. Python environments (`.venv`, `venv`, `.tox`, `site-packages`) are excluded from this source-project pass by default; `--no-default-excludes` restores their traversal. ELF core dumps are not executables and are excluded before hashing. Raw binary identification, including a missing identity or a product/version without a package coordinate, does not by itself cancel publication. Dependencies extracted with explicit package coordinates (for example Go build metadata) retain the required advisory-source checks.

Native files over 512 MiB and unreadable files produce a coverage warning with their path; other files remain scanned. Hashing uses bounded buffers. Failed POM parsing likewise marks dependency coverage incomplete and does not count the failed module as parsed.

> **Certificates & key material**: committed cryptographic files are inventoried in the unmanaged-components chapter and the JSON export (`certificates` array) + SARIF (`FAD-*` rules). Detected by extension (`.pem`/`.crt`/`.cer`/`.der`/`.key`/`.pub`/`.p12`/`.pfx`/`.jks`/`.keystore`/`.ppk`/`.asc`/`.gpg`) **and** conventional SSH filenames (`id_rsa`/`id_ed25519`/…/`authorized_keys`/`known_hosts`), then classified by content: **X.509 certificates** (parsed with Node's built-in `crypto.X509Certificate` — flagged `expired`, `expiring` within `--cert-expiry-days` (default 90), `weak key` RSA<2048 / weak EC curve, `weak signature` MD5/SHA1, `self-signed`); **keys** — every one labelled **private** (a committed secret → *critical*) or **public** (*low*, inventory) — covering PEM (PKCS#1/PKCS#8/SEC1), **OpenSSH of every algorithm** (RSA/DSA/ECDSA/Ed25519 incl. FIDO `-sk`), PuTTY `.ppk`, PGP, and one-line SSH public keys; and **keystores** (JKS/JCEKS by magic, PKCS#12 by extension — contents not decrypted, hashed + flagged *medium*). **100% offline** — no network, no decryption. On by default; `--no-certs` disables it, `--cert-expiry-days <n>` sets the expiry window. (Inventory only — these findings don't affect the `--fail-on` gate.)

> **PHP runtime**: for every Composer project the declared PHP constraint is read (`composer.lock` `platform-overrides.php` › `composer.json` `config.platform.php` › `composer.lock` `platform.php` › `composer.json` `require.php`). A finding is emitted **only** when the constraint proves an end-of-life runtime — an exact pin, or a bounded range such as `^7.4` (= `<8.0`) whose newest allowed PHP is EOL. An open constraint (`>=7.2.5`) proves nothing about the deployed runtime and produces no finding and no warning — the deployed PHP must be checked against endoflife.date/php outside the scan. Symfony/Laravel components are reported as **one row per framework** (the anchor package + a component count), never one row per component.

> **EOL detail panel**: in the HTML report, **click an EOL row** to expand the exact references of the descriptors it is defined in — for every component of the finding: the descriptor path **with the line number** (`web/pom.xml:34`), its module, and the declaration itself (the `<dependency>` block, the `package.json` entry, the lockfile header, …). A transitive finding lists **every** chain that pulls it in plus where the direct dependency to bump is declared; a BOM / parent-POM-managed version names that BOM. A descriptor in which the coordinate has no textual declaration (a POM that inherits it from a parent or reactor module) says so instead of guessing a line. The `.doc` prints every panel open.

> **npm without a lockfile**: a `package.json` lacking a sibling
> `package-lock.json`/`yarn.lock` is scanned **best-effort** — pinned exact
> versions are checked, ranges (`^1.0.0`) are skipped, and a `no-lockfile` warning
> flags the partial coverage. A current lockfile improves coverage but does not by itself
> establish the contents of every deployed environment.

> **Python without a lockfile**: exact pins in supported requirements files and
> `pyproject.toml` are collected best-effort; ranges and unsupported declarations may be
> skipped. The scanner does not execute pip or resolve the transitive Python dependency
> graph. Use a supported resolved lockfile or independently inspect the installed environment.

> **Gradle:** reads `gradle.lockfile`, version catalogs and supported Groovy/Kotlin
> declarations. Literal variables and supported BOMs supply managed versions;
> unresolved versions are reported and excluded from CVE matching. Findings use Maven
> advisory sources and appear in a dedicated Gradle chapter; `--no-gradle` disables it.
>
> Without a lock, POM traversal can differ from native Gradle resolution and produce
> omissions or false positives. Locks cover only recorded configurations and can mix
> runtime, tests and tooling. Use [Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html)
> for the relevant classpaths. See [architecture](ARCHITECTURE.md) for inference rules
> and [benchmarks](BENCHMARK.md) for measured coverage.

## Filtering deps

`-e <regex>` filters out coords whose **groupId** (Maven) or **name** (npm) matches the regex. Useful for private/internal libs that you know aren't on a public registry.

```bash
vigievuln scan . -e "^(com\.acme|org\.private)\."
vigievuln scan . -e "^@acme/"
```

The excluded coords are listed at the end of the run so you can audit the regex.

### Ignoring sub-paths (`--exclude-path`)

Maven/Gradle lookups try configured repositories first, Maven Central and its mirrors next, then the public Google Maven repository (`https://dl.google.com/dl/android/maven2/`) as the last fallback. Google Maven has its own catalogue; it is not treated as a redundant Central mirror. No Android-project detection or build execution is required.

A coordinate confirmed absent (404/410) from every configured registry keeps the existing private-package classification and does not require public advisory-source coverage. Available cached advisories are still matched. A timeout, authentication error, 405, 429 or server failure does not establish absence. This also applies to POMs: a confirmed 404/410 from every repository produces an alert without cancelling publication. Cached absence is valid only for the same repository configuration; an unavailable POM with no such evidence remains a resolution failure.

Legacy clib/C manifests also named `package.json` are recognized from their C-specific metadata and reported as outside npm assessment; their GitHub coordinates are not queried as npm packages.

`-e` drops *dependencies* by coordinate; `--exclude-path` prunes the directory **walk** itself — nothing under a matched path is read, for every ecosystem. Patterns are gitignore-style globs (via `minimatch`, `dot:true`) matched against the path **relative to the scanned source root**; a pattern matches both the directory and its whole subtree.

This applies to the **retire.js vendored-JS scan** too: retire skips the same default dirs (`node_modules` etc.) at **any depth** and honors your `--exclude-path` / `--no-default-excludes`, anchored to `--src` — so a deeply-nested `node_modules` is never scanned.

All patterns are **anchored to the `--src` root** — `truc`, `/truc` and `./truc` are equivalent (a leading `/` or `./` is stripped). To match a name at any depth, use `**/` (e.g. `**/fixtures/**`).

```bash
vigievuln scan . --exclude-path "packages/legacy/**" --exclude-path "**/fixtures/**"
vigievuln scan . --exclude-path "apps/*/e2e"          # repeatable
vigievuln scan . --no-default-excludes                # also walk node_modules/vendor/target/.git/…
```

| Flag | Effect |
| --- | --- |
| `--exclude-path <glob...>` | Prune matching sub-paths (relative to the scanned source root). Repeatable; also settable as `excludePath: [...]` in a trusted file selected with `--config` and unioned across all config layers. |
| `--no-default-excludes` | Don't prune the built-in ignored dirs (`node_modules`, `bower_components`, `vendor`, `dist`, `build`, `out`, `target`, `.git`, `.gradle`, `__pycache__`, …). Walks everything — slower, but nothing is hidden. |

For full transparency about what was *not* scanned, the report includes an **"Ignored directories" section** in scan context listing the actual directories the scan skipped — relative to the scanned source root, each tagged with the rule that pruned it (`default` vs `--exclude-path`). The same list is in the findings JSON as `excludedDirs[]`.

## Per-source toggles

Each data source can be disabled independently:

| Flag | Effect |
| --- | --- |
| `--no-report` | Write **no output files at all** (gate-only / CI mode) — the scan, terminal summary and `--fail-on` gate still run. See **Outputs** for the per-type `--report-*` flags |
| `--no-transitive` | Don't fetch transitive Maven deps from Maven Central |
| `--no-all-libs` | Don't query Maven Central for latest versions (skips the Outdated section and the "missing on Central" check) |
| `--no-osv` | Skip OSV.dev (Google + GitHub aggregated feed) |
| `--advisory-query-ttl <hours>` | Refresh advisory consultations after this many hours (integer 0–8760, default 4). `0` revalidates on each online scan; offline scans still use available observations and report their age. Sources have different coverage scopes: OSV can answer a package/version, while others may provide a package or feed snapshot. |
| `--reuse-stable-advisories` / `--no-reuse-stable-advisories` | Enabled by default: reuse individually cached advisory records whose last source modification is at least 365 days old. The negative flag restores normal cache lifetimes. Package queries and catalogues retain their own refresh policies; KEV and EPSS remain independently refreshed. |
| `--stable-advisory-age-days <days>` | Set the minimum age for advisory reuse (1–36500 days; default 365). Records with missing or future source dates are refreshed normally. |
| `--force-update` | Revalidate consulted online sources, including eligible individual records, regardless of stable reuse. Unavailable sources retain cached data with their provenance. Incompatible with `--offline`. |
| `--images` / `-a images` | Enable image discovery and analysis in source scans and descriptor preparation (off by default). |
| `--proxy-rate-limit-wait-ms <milliseconds>` | Maximum proxy retry wait per request (default 45000 ms). |

When using the VigieVuln service, reviewed and published VigieVuln advisories for the Maven and npm packages in the scan are refreshed by package under this same consultation TTL, independently of OSV. No global seed is required. Project cache preparation includes the relevant cached advisories and consultations for offline scans; proposals awaiting human review are never served as published advisories.
| `--no-packagist-audit` | Skip the Packagist security-advisories lane for Composer deps — the endpoint `composer audit` queries. OSV misses CVEs it carries only as CVEProject entries without composer coordinates (twig/twig CVE-2026-46636/46627, knp-snappy CVE-2026-46643 on the real-instance corpus); this lane matches them with the official constraints. Only package names are sent |
| `--no-nvd` | Skip NVD enrichment (no full CVSS, no CPE refinement) |
| `--no-epss` | Skip EPSS (FIRST.org) exploit-prediction enrichment |
| `--no-kev` | Skip CISA KEV (known-exploited) enrichment |
| `--no-euvd` | Skip ENISA EUVD (EUVD id + ENISA exploited flag). Direct mode uses bulk reads and a 4h cache without sending CVE ids; hosted proxy mode sends matched CVE ids to the proxy for targeted lookup. The exploited flag is reported in the detail panel and every export; it does not move the priority band or the `--fail-on kev` gate |
| `--no-gcve` | Skip the independent GCVE advisory collection and local matching. Partial coverage and unsupported version comparisons are reported as warnings. |
| `--gcve-offline` | Use the local GCVE data without contacting its feeds, while other enabled sources remain online. Missing or stale GCVE data is reported. |
| `--no-certfr` | Skip CERT-FR (ANSSI) advisory references. fad keeps a local CVE → advisory index: direct mode builds a local index without sending CVE ids; hosted proxy mode sends matched CVE ids to the proxy and receives only their advisory references. GCVE ids need no source (`GCVE-0-…` is the CVE id by the GCVE rules) |
| `--licenses` | Run license detection + the copyleft-policy chapter (**off by default**; legacy `--no-licenses` is a no-op) |
| `--image-retire` | Opt in to RetireJS inspection of deployed image JavaScript; excludes package stores and OS-owned files. Requires `--images` in source scans. |
| `--no-retire` | Skip retire.js vendored-JS scan |
| `--no-vendored-js-inventory` | Keep only **vulnerable** vendored JS (the CVE chapter); skip the full **inventory** of all identified standalone JS libs (under unmanaged components). The inventory is a cyber-hygiene constat — unmanaged third-party JS regardless of CVEs — on by default. |
| `--no-jars` | Skip scanning embedded `.jar`/`.war`/`.ear` binaries for Maven coordinates (the unmanaged-components chapter) |
| `--no-binaries` | Skip scanning committed native binaries (`.dll`/`.exe`/`.so`/`.dylib`) — no checksum identity/integrity (the unmanaged-components chapter) |
| `--no-certs` | Skip the certificate / key-material scan (the unmanaged-components chapter) — committed certs, private/public keys and keystores |
| `--cert-expiry-days <n>` | Window for the certificate **expiring-soon** warning (default `90`) |
| `-d, --disable <list>` | Turn features off, comma-separated: `eol nvd nvd-mirror osv packagist-audit epss kev euvd gcve certfr retire transitive all-libs checksums osv-db report vendored-js-inventory default-excludes` and any ecosystem (`maven gradle npm yarn nuget composer pypi go ruby js jars binaries certs`). Replaces the `--no-*` flags, which still work but are hidden from `--help` |
| `-a, --activate <list>` | Turn on what is off by default: `licenses eol-support typosquat snyk osv-db nvd-cpe-match cve-refresh cve-offline osv-db-refresh retire-refresh` |
| `-r, --report <list>` | Outputs to write: `html doc xlsx sbom csaf json sarif` (default `html,json`). `--report-<type> <file>` still takes an explicit path |
| `-o, --report-output <dir>` | Report output directory |
| `--help-all` | Every option, including the individual flags `-d`/`-a`/`-r` replace and the cache / registry / config commands |
| `--lang <en\|fr>` | Language of the HTML / Word report (default `en`). Translates the report's own chrome — **all of it**: chapter titles and their counts, table headers, scope chips, every intro paragraph, every status pill, the warning headings, the licence categories, the methodology limitations, the per-ecosystem fix recipes, the empty states, and the executive summary both on screen and as the 📋 button pastes it — plus the CWE titles. **Not** the evidence: CVE descriptions, advisory text and registry reasons stay as published, and a CVSS severity keeps NVD's own wording where it is a finding's value. French CWE titles are fad's own (MITRE publishes English only) and carry MITRE's original with them |
| `--no-eol` | Skip the end-of-life check (endoflife.date) — the flag the run suggests when that source is unreachable |
| `--no-nvd-mirror` | Disable the [fkie-cad NVD mirror](https://github.com/fkie-cad/nvd-json-data-feeds). Without an NVD API key the mirror is queried first; with a key it is the fallback. Cached stale data may be used with a warning. Missing CVE enrichment is reported separately from discovery coverage. |
| `--retries <n>` | Retries before a data source is marked unavailable (default `5`, waiting 5+n s each: 6, 7, 8, 9, 10 s). `0` = no retry — the first failed answer declares the source down. For direct 429/503 responses the scanner honors Retry-After. If the requested delay exceeds the remaining time budget (two minutes or the configured schedule, whichever is longer), it reports the exhausted budget and stops retrying. Shared per source, so one dead host runs ONE schedule however many lookups hit it. Requests whose caller rotates across mirrors/registries are not retried (the rotation moves on). Also settable as `"retries"` in a trusted file selected with `--config` |
| *(source unavailable)* | **A scan with missing dependency structure, package advisory discovery or CVE record evidence still publishes its reports, marked incomplete**: a banner and chapter 0 list each gap, `summary.scanReliable` is `false` in the JSON export, and the terminal names the checks that did not complete. The scan is cancelled (exit 2, no report) only when it has no inventory at all or when no advisory source assessed any package. `--fail-on-incomplete [inventory,advisories,sources]` restores cancellation for the listed capabilities. This applies in every source profile, including offline scans. Invalid configuration and unusable explicitly supplied local snapshots still fail. |
| *(EOL + paid support)* | When endoflife.date lists **paid** support past the open-source end of life (`extendedSupport` — e.g. Broadcom for Spring 5.3/6.x), the EOL row stays an EOL finding (those fixes are builds from the vendor's private repository, for subscribers) and states: the support end date, the build of the dependency's own branch that fixes the CVEs found (`A 5.3 build > 5.3.40 fixes 7 of the 9 CVEs found`), and — when the vendor repository is configured with `--add-repo maven <name> <url> --token <TOKEN>` — the newest vendor build of the branch. A project already on a vendor build (newer than the branch's last public release and absent from Maven Central) is not reported as EOL; chapter 0 notes it. |
| `--eol-support` | Also report frameworks/runtimes whose **active (bug-fix) support has ended** while security fixes are still provided (endoflife.date `support` field) — rendered as an "Out of active support" band under the maintenance chapter, status `unsupported` in the JSON. Off by default: the default EOL set is unchanged. |
| `--ignore-test` | Drop test-scoped Maven deps and dev npm deps from the scan entirely (the dev-CVE section will be absent) |
| `--proxy-cache <url\|vigievuln\|default>` | Use a shared cache URL or the official VigieVuln proxy for this scan. |
| `--set-proxy-cache <url\|vigievuln\|default>` | Save the proxy cache for future scans. Use `--unset-proxy-cache` to remove it. |
| `--proxy <url>` | Route ALL outbound requests through a corporate forward proxy (`http://host:port`; Node >= 24 or bun). See **Corporate forward proxy** |

If Packagist answers successfully but omits a package from its advisory data, the scan
continues and names that package in a report warning; omission is never treated as a
clean result. An unreachable Packagist endpoint or malformed response produces a
source-unavailable warning. The report is then published marked incomplete; with
`--fail-on-incomplete` these discovery failures cancel publication and return code 2.

## Application inventory (experimental)

The experimental application plugins identify supported CMS and framework instances
from product-specific markers and inventory their components. `--app-plugins auto`
selects recognized layouts, `none` disables all plugins, `all` enables all, and a
comma-separated list selects specific plugins. Use `--list-app-plugins` to list them.
See [CMS & frameworks](CMS-FRAMEWORKS.md) for detection and coverage by product.

Every subtree is also scanned through its supported dependency descriptors. Findings with proven component ownership are attributed to the CMS instance; findings without proven ownership remain in the ordinary dependency sections.

```bash
vigievuln scan ./project --app-plugins symfony --offline --report-json
vigievuln scan ./project --app-plugins wordpress --private-component site/wp-content/plugins/acme --offline
vigievuln scan ./project --app-plugins wordpress --wordfence-feed ./wordfence-production.json --public-component site/wp-content/plugins/example=example --offline
vigievuln scan ./project --app-plugins drupal --offline --fail-on-incomplete inventory,advisories
vigievuln scan ./project --app-plugins drupal --drupal-advisories ./drupal-advisories.json --offline
vigievuln scan ./shop --app-plugins prestashop,typo3 --prestashop-advisories ./ps-advisories.json --typo3-advisories ./t3-advisories.json --offline
vigievuln scan ./shop                                   # CMS detected and their publisher advisories consulted
vigievuln scan ./project --app-plugins wordpress --wp-checksums-live
vigievuln scan ./project --app-plugins wordpress --wp-checksums ./wp-checksums-6.4.2-en_US.json --wp-checksums-locale en_US --offline
vigievuln scan ./project --app-plugins laravel --offline --report-json
vigievuln scan ./my-wordpress-plugin --app-plugins wordpress --scan-context component --offline --report-json
vigievuln scan ./shop --app-plugins magento --offline --report-json
vigievuln scan ./cms --app-plugins joomla,prestashop,typo3 --offline --report-json
```

Additional supported layouts and advisory coverage:

| Plugin | Tested source files / layout | Version authority | Advisory coverage |
| --- | --- | --- | --- |
| Joomla | 5.4.1 core manifest plus `libraries/src/Version.php`; typed extension XML under components, modules, plugins and templates | Runtime version constants, corroborated with the core manifest; extension `<version>` is its own version | Application advisories not yet qualified; Composer packages use the standard OSV/Packagist lanes |
| PrestaShop | 8.2.1 source `composer.json`, `config/config.inc.php` and installer version; installed `config/settings.inc.php`, static module PHP metadata, `config/theme.yml` | Installed `_PS_VERSION_` ahead of the installer source version; module `$this->version` and theme `version` | Publisher GitHub advisories when configured; Composer/npm scans remain separate |
| TYPO3 | 13.4.2 source `typo3/sysext/core/ext_emconf.php`; Composer installation with `typo3/cms-core` lock; classic extensions | Locked `typo3/cms-core` for Composer sites, otherwise the literal core `ext_emconf.php` version | Publisher GitHub advisories when configured; locked public Composer packages use OSV/Packagist |
| Magento / Adobe Commerce | 2.4.7-p3 Magento source markers; Composer product edition lock, `app/code` modules and `app/design` themes | Exact locked `magento/product-*` version, including `-pN`; a module's XML `setup_version` is a database schema version, not its code version | Adobe product bulletins are not parsed as a complete machine feed; source-only components remain not-run and Composer components use dependency sources |

A missing `composer.lock` leaves package versions and dependency origins incomplete. These four plugins also mark product lifecycle as `not-run`: community support, paid support and deployed patches need separate evidence. Magento product packages from `repo.magento.com` are not queried against Packagist; their publisher bulletins require separate review. Components found on disk do not prove activation, and no plugin infers that a patch file was applied. `--scan-context component` also recognizes a standalone extension for each of these CMSs when its local metadata is valid.

`--private-component` takes a path relative to the scanned source root and can be repeated. A WordPress plugin with an `Update URI` header is also classified as private automatically, even if a public slug was declared; [WordPress documents this header for third-party updates](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/). A private WordPress plugin or custom Drupal module stays separate from public catalogue identities; Composer CVEs in its own lockfile are attributed to that component. Shared dependencies retain one physical finding with multiple proven owners. WordPress classic and Bedrock layouts and Drupal Composer and Drupal 7 layouts are recognized. Components found on disk are inventoried even when runtime activation cannot be established.

`--scan-context component` treats the scan input as a standalone WordPress plugin or theme directory when its root header identifies it. It inventories that component and its Composer dependencies without inventing a WordPress core installation. The default `source` and explicit `installation` contexts describe how the input was obtained; neither proves runtime activation or a deployed configuration.

WordPress scans use [WPVulnerability](https://docs.wpvulnerability.com/) automatically when no Wordfence source is selected. No API key is required. The core version and every plugin and theme are assessed by default, with no option to set: an extension is queried under the slug of its official WordPress.org header URL, otherwise under the name of its directory, which is its catalogue slug in a standard installation. Only the slug and extension type are sent. An extension the catalogue does not know, one carrying an `Update URI` header, and one declared with `--private-component` are treated as private components: they are listed with the private packages of the other ecosystems and do not mark the report incomplete. Validated responses are included in cache exports and reused offline. A failed query marks the report incomplete; `--fail-on-incomplete` cancels publication instead.

`--wordfence-feed` reads a local JSON snapshot of the Wordfence Intelligence v3 **production** feed. It makes no network request. `--public-component path=slug` is only needed when an extension was installed under a renamed directory: it declares the catalogue slug to use instead of the directory name, is recorded as `user-declared`, and can be repeated. Private components are never matched to that catalogue; they are listed as private. A feed snapshot supplied by the operator must be complete and current for its `no-match` results to be meaningful; vigievuln cannot prove those properties from the JSON file alone. Coverage records retain its SHA-256 and local file modification time, which do not establish its download date. Advisory records retain Wordfence identifiers, references and copyright notices. See the [Wordfence v3 feed documentation](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) for obtaining a key and the feed usage terms.

`--drupal-advisories` reads a local snapshot of the [official Drupal Composer security-advisories response](https://packages.drupal.org/8/packages.json). Save it as `{ "queriedPackages": ["drupal/core", ...], "advisories": { ... } }`; `queriedPackages` must list every package requested from the API, including those omitted from its response because no advisory was returned. Unlisted packages retain `CMS_PACKAGE_NOT_QUERIED` and no negative conclusion. Drupal 7 remains outside the current community security-advisory coverage. Drupal's advisory ratings are kept separately from CVSS scores; the report shows their original rating and the derived gate severity.

`--prestashop-advisories <file>` and `--typo3-advisories <file>` read snapshots
of the publishers' [GitHub security advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories).
Use `{ "advisories": [ ... ], "_fadSnapshot": { "collectedAt": "..." } }`;
a bare array is accepted when `--max-advisory-age` is not set. Findings are matched
to the inventoried PrestaShop core, TYPO3 core and TYPO3 system-extension coordinates.
Publisher range syntax is normalized. Some PrestaShop records lack a package identity;
the core association is reported as an inference. A range that cannot be evaluated
is indeterminate, not evidence of safety. Joomla and Magento have no dedicated
publisher advisory lane; source-only components retain `CMS_ADVISORY_NOT_QUALIFIED`.

`--wp-checksums <file>` reads a local snapshot of the official [api.wordpress.org core checksums](https://developer.wordpress.org/rest-api/reference/core-checksums/) (`{ "checksums": { "<file>": "<md5>" }, "version": "...", "locale": "..." }`) and compares the WordPress core files of every inventoried instance against it. `--wp-checksums-live` fetches that reference live, pinned to each instance's observed core version and `--wp-checksums-locale` (default `en_US`). Divergences are **diagnostics, never CVE findings**: `CMS_FILE_MODIFIED` (the file differs from the official distribution), `CMS_FILE_MISSING` (the reference file is absent from the tree — a source checkout is not the distribution archive, so this does not flip the verdict), `CMS_FILE_EXTRA` (an unexpected file inside `wp-admin/` or `wp-includes/`, the controlled perimeter; `wp-content/` is user land and is never flagged), reported under the `integrity` capability with `affected` only on modified or unexpected core-directory files. A reference pinned to another version (`CMS_CHECKSUMS_REFERENCE_MISMATCH`) produces no verdict rather than fake divergences.

An explicitly configured advisory file requires its corresponding `--app-plugins` selection. Invalid JSON, an invalid feed schema, or an unreadable configured file exits with code `2` before any report is written.

`--max-advisory-age <duration>` (e.g. `72h`, `30d`) bounds the age of every configured advisory snapshot. A snapshot's file modification time proves nothing about when it was collected, so the date must be declared **inside the snapshot file**: a top-level `collectedAt` or `generatedAt` ISO 8601 string, or a reserved `_fadSnapshot: { "collectedAt": "..." }` object (the Wordfence v3 feed is a flat UUID-keyed map, so the reserved key is the only metadata it tolerates). A snapshot without a declared date, a malformed date, or one older than the limit exits with code `2` before any report is written. A declared date also travels with the coverage provenance (`sourceSnapshot.collectedAt`) whether or not the limit is set.

An online scan consults the publisher advisories of each CMS it detects, with no option
to set. `--offline` never fetches and reuses the cached snapshots; a local snapshot file
(`--drupal-advisories <file>` …) replaces the query; the regional source profiles exclude
CMS plugins. The sources consulted:

- SPIP: NVD's SPIP core CPE. An NVD key is optional.
- Drupal: the official endpoint, for inventoried public `drupal/*` identities. Private
  components are excluded.
- PrestaShop and TYPO3: the publishers' GitHub advisory feeds; GitHub rate limits apply.

The `--spip-advisories-live`, `--drupal-advisories-live`, `--prestashop-advisories-live`
and `--typo3-advisories-live` options remain for a mirror URL of the same API.
- `--wp-checksums-live` fetches WordPress core checksums. These sources accept their
  documented URL override for a mirror of the same API.
- Wordfence requires `WORDFENCE_API_KEY` or `--wordfence-api-key <key>` in direct
  mode. `--wordfence-feed-url <url>` overrides the endpoint. With `--proxy-cache
  --wordfence-live`, the server key is sufficient and the client receives targeted
  advisory projections. See [Wordfence's feed documentation](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/).

Fetched snapshots record their collection date and are cached for offline reuse.
A warmed cache can supply Drupal, PrestaShop, TYPO3 and WordPress data without
separate snapshot flags. `cache prepare` can warm the supported publisher data from
an anonymized descriptor; Wordfence warming needs a key, which is not exported.
WordPress checksums are keyed by version and `--wp-checksums-locale`. Explicit
snapshot or live options take precedence, and the selected application plugin and
`--max-advisory-age` still apply. Live options cannot run with `--offline`. Failed,
invalid or missing data produces a warning and indeterminate coverage.

Symfony Flex `symfony.lock` recipes and `extra.symfony.require` provide context;
installed package versions come from `composer.lock`, and extraction with `-t` mirrors
`symfony.lock`. Symfony and Laravel use the standard Composer advisory sources. Their
`dependency-lanes` application coverage row is currently marked `completed` based on
inventory membership; it does **not** verify that OSV or Packagist evaluated each
package and version. The same limitation applies to dependency-lane rows for some
Joomla and Magento components. The mandatory discovery check separately requires OSV and a second advisory source for each package/version. Publisher lanes that are unconfigured or
unqualified remain `not-run` with their diagnostic. `--fail-on-incomplete` exits with code
2 before publication when a requested capability is incomplete; its default
capabilities are `inventory,advisories`.

Environment prerequisites in advisory configurations are assumed satisfied. OS, architecture and deployment restrictions remain documented in the source advisory. Matching still requires a vulnerable entry for the audited product and an affected version.

A source must assess the package/version, through a query or a verified local catalogue, to count toward discovery. Looking up a known CVE in NVD or EUVD only supplies record evidence. Each reported CVE requires one attributable advisory record, regardless of how many providers list it. Unavailable providers or missing cache entries never establish that a package cannot be checked. An inapplicable check needs an explicit reason. A cancelled scan leaves any previous report untouched and writes its reason to the terminal. A failure of a redundant record provider or of optional EPSS enrichment can leave a warning while the mandatory checks pass. JSON exports expose the outcome in `summary.scanReliable`.

Indeterminate comparisons from available advisory data are listed in scan context, with the affected packages; they are not source outages or proof that a package is safe. Image retrieval and advisory-source issues share one report warning, “Unavailable from public sources”, with per-image reasons. Actual failed consultations remain coverage gaps.

Report subsections with no results are omitted, and the remaining ones are numbered in order. CMS/framework CVEs appear first under CVE when present; application inventory and coverage remain in scan context even when no advisory matches. The six root chapters remain visible.

## Outputs

Every output has its own `--report-<type>` flag, each taking an **optional** path. Give a path to write there; omit the path to use a default name under `--report-output` (default dir `./vigievuln-report`). **If you pass no `--report-*` flag, HTML + `findings.json` are written by default**; pass `--no-report` to write nothing (gate-only / CI). Selecting any `--report-*` flag writes exactly that set — e.g. `--report-sbom` alone writes only the SBOM, no HTML.

| Flag | Default name | Effect |
| --- | --- | --- |
| `--report-html [file]` | `cve-report.html` | The self-contained HTML report (inline CSS, no external assets). |
| `--report-doc [file]` | `cve-report.doc` | The same report as a Word-compatible `.doc`. |
| `--report-xlsx [file]` | `findings.xlsx` | Excel workbook with a summary and one sheet per populated category, including application ownership, coverage, warnings, provenance and diff when present. Text is stored as text, never evaluated as a formula; an explicit path must end in `.xlsx`. |
| `--report-sbom [file]` | `sbom.cdx.json` | A **CycloneDX 1.6** SBOM with `vulnerabilities` inline (a VDR). Maven, npm and PyPI records export each known scanned version as a separate component; findings refer to their affected version. Coverage and scope depend on the input evidence. Components carry purls and detected licenses; vulnerabilities carry available CVSS, CWE and priority evidence. |
| `--report-csaf [file]` | `csaf-vex.json` | A **CSAF 2.0 VEX** (`csaf_vex`) document: a `product_tree` of every dep (purl-identified) plus per-CVE `product_status.known_affected`, `cvss_v3` scores, a KEV `exploited` flag, and prioritization notes. |
| `--report-json [file]` | `findings.json` | A flat **findings JSON** (fad's own format): every chapter (CVE/EOL/obsolete/outdated/licenses/vendored) + an `unmanaged` array (native-binary inventory with identity/integrity/signals), an `embedded` array (every JAR/WAR/EAR coordinate, vuln or not, with `vulnCount`/`maxSeverity`), EOL entries carrying their `productSlug`/`via`/`viaKey` origin + `status`/`cycle`/`support` and, for grouped frameworks, `anchor`/`components[]` (each component with its own `manifestPaths`, or `scope:"transitive"` + `via` chain), + a summary, easy to diff between audits and post-process. |
| `--report-sarif [file]` | `fad.sarif` | A **SARIF 2.1.0** log for GitHub Code Scanning / GitLab: one rule per CVE with `security-severity` (drives GitHub's severity), KEV tags, and the manifest (or embedding jar) as the result location. |
| `--report-output <dir>` | `./vigievuln-report` | Base directory for any output left at its default name. |

In the findings JSON, `summary.coverageIncomplete` counts incomplete application
capabilities plus warnings about dependency or source coverage and freshness. It is
a count of diagnostic signals, not distinct missing packages or sources: multiple
signals may describe the same gap. The component counts are available as
`summary.applicationCoverageIncomplete` and `summary.coverageWarnings`; see
`coverage[]` and `warnings[]` for details.

JSON source locations use the project basename and relative paths; structured paths outside the source root are marked `[external]/<basename>`. Advisory text, identifiers and URLs remain unchanged: this is not an anonymized export. Excel cells exceeding 32,767 characters are truncated with an explicit marker; export JSON alongside the workbook to retain their full values.

```bash
# default: HTML + findings.json into ./vigievuln-report
vigievuln scan ./proj

# only the machine artifacts, default names under a custom dir
vigievuln scan ./proj --report-output ./out --report-sbom --report-csaf --report-json --report-sarif

# explicit paths
vigievuln scan ./proj --report-sbom sbom.cdx.json --report-sarif fad.sarif
vigievuln scan ./proj -r html,json,xlsx            # add an Excel workbook to the default pair
```

All honour `--offline` (they render from whatever the scan already resolved).

## CI gating & triage

| Flag | Effect |
| --- | --- |
| `--fail-on <level>` | Exit non-zero when a **production or embedded-binary** finding meets the level: `low`/`medium`/`high`/`critical` (severity) or `kev` (only CISA-known-exploited). Default `none`. Requested outputs are attempted before the gate result. An invalid level hard-fails (exit 2) rather than silently disabling the gate. |
| `--fail-on-new` | Exit non-zero when the scan introduces any **new production CVE finding** vs `--baseline` (see *Differential audits*). Combinable with `--fail-on` — either condition fails the build. |
| `--ignore <file>` | Suppress findings. One rule per line: `CVE-2021-44228` (anywhere), `CVE-… org.apache.*` (coord/purl glob), `* npm:lodash` (any CVE for a coord); text after `#` is the reason. |
| `--vex <file>` | Ingest a **CSAF VEX**: CVEs marked `known_not_affected` / `fixed` are suppressed (products mapped back to coords by purl — round-trips fad's own `--report-csaf`). |

Suppressed findings are dropped from the report chapters, SARIF and `--fail-on`, but retained with triage metadata in JSON/XLSX/SBOM/CSAF, and the count is noted in chapter 0. SBOM carries component-scoped `vigievuln:triage` properties; CSAF carries triage notes and preserves explicit VEX `fixed` / `known_not_affected` assertions. An ignore rule accepts or hides a finding; it does not assert that the product is unaffected. A VEX without explicit, mapped clearance never suppresses a finding.

`--ignore` also matches recorded advisory aliases such as GHSA IDs, while retaining the package scope. A global `*` rule is allowed but emits a warning in the terminal and report. VEX exemptions continue to require an exact advisory ID and product PURL.

Exit `1` means a blocking finding; exit `2` means a scan/output error or a failed coverage requirement and takes precedence when both occur. A failed report destination does not prevent other requested formats from being written. Unexpected scan errors show a concise message; `--verbose` also includes the diagnostic stack. Findings with `UNKNOWN` severity do not meet a severity threshold, including `low`; they remain in the report and can still block `--fail-on kev` or `--fail-on-new` when applicable.

```bash
# Fail the pipeline only on exploited-in-the-wild vulns, minus accepted risks
vigievuln scan . --fail-on kev --ignore .fadignore --report-sarif fad.sarif
```

## Differential audits (`--baseline` / `vigievuln diff`)

Repeat audits care about **what changed**. Diff the current scan against a prior
findings JSON (from `--report-json`): the report gains a **"Δ Changes since baseline"**
chapter, the JSON export gains a `diff` block, and CI can gate on *new* findings.

| Flag / command | Effect |
| --- | --- |
| `--baseline <file>` | Diff this scan against a prior `findings.json`. Adds the Δ chapter to the report + a `diff` block (summary + new/fixed CVEs) to `--report-json`. |
| `--fail-on-new` | Exit non-zero if any **new production CVE finding** appeared vs the baseline. |
| `vigievuln diff <baseline.json> <current.json>` | Standalone diff of two exports (no scan). Prints new/fixed/unchanged per category + the new CVEs; `--report-json <out>` writes a `fad-diff/1` document; `--fail-on-new` sets exit 1 on new production CVEs. |

A finding's identity is `CVE id + ecosystem + coordinate + version`, so a version bump
shows the old finding *resolved* and the new one *added*. Suppressed / CPE-filtered CVEs
and development findings are diffed but excluded from the `--fail-on-new` signal (embedded binaries still count). A missing or invalid baseline, including `--fail-on-new` without `--baseline`, returns code 2. If current production findings cannot be classified as new because baseline coverage is incomplete, `--fail-on-new` returns 2. Findings absent during a source outage or incomplete inventory are marked unassessed rather than fixed. Any failed requested machine-readable export also returns code 2.

Different project names in the baseline and current report produce a warning. Comparison continues because a renamed checkout may still be the same project.

```bash
# CI: fail only when this build introduces NEW vulnerabilities vs main's last report
vigievuln scan . --report-json this.json --baseline main.json --fail-on-new

# Ad-hoc comparison of two historical reports
vigievuln diff audit-q1.json audit-q2.json --report-json delta.json
```

## Report integrity & methodology

Reports include evidence that helps reviewers assess provenance and integrity:

- **Provenance manifest** — each report (and the JSON export's `provenance` block) records
  the tool version, run mode (offline/online), the findings-affecting configuration, and
  the **freshness of every data source** (CVE index, OSV, NVD, KEV, EPSS, endoflife, the
  registry caches) read from `~/.vigie-vuln/`. An `--offline` re-run can reuse an exported
  cache, subject to the evidence and coverage available in that cache and the scanned inputs.
- **Methodology chapter** — appendix 12 of the HTML/`.doc` report renders that source table
  plus an explicit statement of **what vigievuln does *not* assess** (reachability,
  runtime config, secrets/IaC, first-party code, malware beyond the OSV/CIRCL signal, legal
  license advice) — the audit's scope, stated up front.
- **Integrity manifest** — a standard **`SHA256SUMS`** is written beside the artifacts,
  verifiable with `sha256sum -c SHA256SUMS`. `--no-checksums` disables it. A checksum
  manifest alone does not authenticate its contents; sign it separately when needed.

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
vigievuln scan . --typosquat                       # add the typosquat heuristic
vigievuln scan . --fail-on critical                # malware blocks even below 'critical'
```

## Large reports

A component with thousands of advisories (a kernel package carries more than 9 000) is
reported in full detail for its 100 highest-priority findings. The HTML and Word reports
count the others by severity. The JSON, Excel, SBOM, SARIF and CSAF exports still list
every finding, the ones beyond the limit as compact entries (`detail: "compact"`) with
their identity, component, rating, fix and distribution evidence but without advisory
texts; `summary.cve.compact` counts them. A distribution's per-CVE record
(`DEBIAN-CVE-…`) and the CVE it names are one finding, shown under the CVE id; a DSA or
DLA announcement whose CVEs are all listed for the package appears in their `related`
field.

With an NVD API key, a batch of more than 200 CVE records is read from the NVD mirror
first, then from NVD for what the mirror does not hold yet: NVD's limit of 50 requests
per 30 seconds would otherwise take about 100 minutes for 10 000 CVEs. An ENISA EUVD
record is requested for the findings reported in full detail and for any CVE still
lacking a score, a severity or a description; the EUVD identifier and exploitation
status are attached to every finding. `coverage[].durationMs` gives the time spent in
each enrichment source.

## Offline / cache control

```bash
# Use cached data only, no network (works for everything)
vigievuln scan . --offline

# Per-source offline
vigievuln scan . --cve-offline                  # use cached CVE index only
vigievuln scan . --cve-refresh                  # force re-download of CVE bundle
vigievuln scan . --retire-refresh               # force re-scan with retire.js (ignore cache)

# Matching uses the same stored advisories online and offline. Initialise a broad
# seed with setup; later online queries add/update advisory documents locally.
vigievuln setup
vigievuln scan . --offline
vigievuln scan . --osv-db-refresh                # revalidate package/version queries

# Cache export / import (useful for air-gapped boxes)
vigievuln cache export vigievuln-cache.tar.gz
vigievuln cache import vigievuln-cache.tar.gz                    # merge into the existing cache
vigievuln cache import vigievuln-cache.tar.gz --replace           # replace, keeping a SQLite backup
vigievuln cache import vigievuln-cache.tar.gz --replace --force   # replace without a backup
```

The archive contains one preindexed SQLite database. Retire.js findings and its warmed
signature database are stored there; local `config.json` and account sessions remain on
the importing machine. VigieVuln 1.2.0 does not import older filesystem cache archives.
At startup it removes old cache files while preserving configuration and account sessions.

**Import merges by default.** SQLite updates advisory records, package observations and
cached responses according to their source timestamps. Whole-corpus snapshots such as
KEV and the CVE lookup use the fresher snapshot. Pass `--replace` to install the incoming
database as a whole and keep the previous one as `~/.vigie-vuln.bak-<timestamp>.sqlite`.
Add `--force` to omit that backup; without `--replace`, `--force` has no effect and the import still merges.
Configuration and API keys are never part of the bundle (`--include-config` is accepted for compatibility and ignored).

### Offline operation

`--offline` makes no network requests and uses available local caches under
`~/.vigie-vuln/`. Missing or stale data is reported; an offline scan is only as
complete as the evidence prepared for it. To run in a network-free namespace:

```bash
unshare -rn node vigievuln.js scan ./proj --offline --report-json /tmp/airgap.json
```

The compiled binary includes retire.js and does not require Node.js or a separate
`retire` executable. Its signature database must be prepared in the cache; if the
vendored-JavaScript scan fails, the report includes a warning. Use `--verbose` for
diagnostics.

## Hosted VigieVuln proxy

Create and verify your account at `https://www.vigievuln.fr/account`, then sign in
and run:

```bash
vigievuln login             # selects the official proxy if none is configured
vigievuln scan ./project    # creates a proxy key interactively when needed
# Or for just one scan:
vigievuln scan ./project --proxy-cache default
```

Both `vigievuln` and `default` select `https://api.vigievuln.fr`. Authentication is checked before scanning. Invalid,
expired or revoked keys stop the scan with exit code 2. `--offline` makes no network request,
including no authentication preflight, and does not require a token.

The proxy may require a minimum CLI version. If yours is too old, the scan stops
before collection with update instructions; upgrade the npm package or your standalone binary.

This routes supported public provider requests through the shared cache. Private
registries still use their configured direct connections. The proxy sees requested
package coordinates and vulnerability identifiers; this option does not upload
your source code or create a monitored project. A failed proxy request does not
silently switch to direct upstream access.

The CLI paces requests to the hosted proxy. When it receives HTTP 429 or a proxy
upstream-budget denial, it reports each wait and respects `Retry-After`. The
default limit is 15 retries within 45 seconds of scheduled waits per request.
Temporary server and transport failures get up to two retries within that budget.
If the next wait exceeds the remaining budget, the request stops and the report
can indicate incomplete coverage.
The server's retained mirror can supply older NVD data when the primary source is
unavailable or rate-limited; the report marks that data as stale.

Proxy-confirmed responses are cached locally per proxy origin for at most four hours
from the source fetch time. Repeated scans reuse fresh entries without a request;
expired entries are revalidated through the proxy. If a source cannot be refreshed,
the last available data may be used with a stale-data warning. A cold scan can still
make many individual requests, and custom/private registries use their own routes.

The setting also works in layered JSON configuration as `"proxyCache": "vigievuln"`.
The older `--vigievuln-proxy [fr|com]` remains available for compatibility.
Hosted online mode revalidates package/version queries through the selected proxy. The complete seed is downloaded separately during setup.
`vigievuln login` selects the official proxy when none is configured. If a custom proxy is already configured, login uses its account API and saves a key tied to that server. A local server may allow anonymous access, in which case setup and an optional seed need no login. HTTP sends passwords and keys without encryption: setup requests confirmation before contacting the server and remembers it for that exact origin. For unattended setup, add `--allow-insecure-http`; scans and `login` also accept this flag for one invocation. An existing unconfirmed HTTP configuration must be confirmed interactively or use the flag. For the official proxy, a dedicated key is created on the first scan when needed. Keys are stored in `~/.vigie-vuln/config.json` (mode 0600), separately from the account session.
Published VigieVuln advisories are queried by Maven/npm package through the official proxy, matched even with `--no-osv`, and cached for offline use. `VV:CVE-…` identifies the advisory; incomplete version evidence leaves other versions unknown. Each [public advisory](https://www.vigievuln.fr/advisories/vigievuln?lang=en) identifies its sources and AI-assisted reconciliation. Failed refreshes produce a coverage warning.

An existing key can be saved with `--set-proxy-cache-token <key>` and removed with
`--unset-proxy-cache-token`. Non-interactive runs require a saved key or the
`VIGIEVULN_PROXY_CACHE_TOKEN` environment variable; no password prompt is attempted.
Keep credentials outside checked-in configuration. See the server's deployment instructions when running your own
instance; the following section covers a custom cache URL.

## Project monitoring

Create and verify your account at `https://www.vigievuln.fr/account` and explicitly accept the [terms of service dated 2026-10-28](https://www.vigievuln.fr/terms). Use the short commands to sign in and register a project:

```bash
vigievuln login
vigievuln whoami
vigievuln watch ./project --name 'My Project'
vigievuln project status
vigievuln logout
```

`watch` collects dependencies locally, then uploads the inventory once. It does not run a vulnerability scan, resolve dependencies over the network or start a background watcher. Running it again with the same unique project name updates that project using its current revision. To select an existing project explicitly, use its ID from `project status`:

```bash
vigievuln watch ./project --id <project-id>
```

`--id` updates the inventory without renaming the project. If the account already contains a differently named project, `watch --name` refuses to replace it implicitly: choose the intended ID explicitly. Upload requires an account session; when needed, an interactive terminal prompts for login. Non-interactive use requires signing in beforehand. Invoking `watch` without `--export` authorises upload; there is no separate `--yes` flag or upload confirmation.

The free tier watches **one project, up to 100 distinct direct dependency coordinates and a 0.5 MB descriptor**, for **one calendar month renewed by each upload**; expiry deletes the monitoring data and triggers an email.

When acceptance of the current terms is pending, the CLI displays their link and requests explicit acceptance in an interactive terminal. Non-interactive use requires accepting them first with an interactive `vigievuln login`.

### Export locally before uploading

```bash
vigievuln watch ./project --export fichier.json
```

`--export` is **export only**: it prepares the descriptor locally and offline, without login, account access or upload. It writes `fichier.json` for review. Paths, source code and registry URLs are omitted, but package coordinates and versions remain visible in the file and can identify private packages. Review and exclude private dependencies before any upload.

`--name` is optional for export; `--id` cannot be combined with `--export`. Both export and upload accept dependency filters:

```bash
vigievuln watch ./project --export fichier.json -e '^@acme/' --exclude-path '**/fixtures/**'
vigievuln watch ./project --name 'My Project' --ecosystem maven,npm
```

Use `-e` / `--exclude` for a coordinate regex, `--exclude-path` for source paths, and `--ecosystem` to select ecosystems. Review the export before using the upload command with the same filters.

After reviewing the file, upload it explicitly with the compatible command:

```bash
vigievuln login
vigievuln project push --file fichier.json --name 'My Project'
```

### Compatible commands

The existing authentication and two-step preparation/upload workflow remains supported:

```bash
vigievuln auth login
vigievuln scan ./project --prepare-project ./project-deps.json
vigievuln project push --file ./project-deps.json --name "My project"
vigievuln project status
# For an existing project, use the id from `project status`:
vigievuln project push --file ./project-deps.json --id <project-id>
vigievuln auth logout
```

`login`, `whoami` and `logout` correspond to `auth login`, `auth status` and `auth logout`. Preparation is offline; use `-e` where applicable to exclude private coordinates. The CLI counts versions whose direct relationship is unknown. Account sessions are stored separately from proxy keys; no password is stored.

Directness is determined from supported project and lockfile evidence, including Maven, npm, Composer, Go, NuGet and Bundler. Some inventories, including Python and Gradle, cannot yet establish directness reliably and therefore have incomplete monitoring coverage.

Monitoring reports newly appearing high or critical vulnerabilities affecting direct dependencies (CVSS 7 or above), and known exploited vulnerabilities; alerts can be enabled in the account. The initial inventory establishes a baseline, and later changes are reported. Update the descriptor when your dependencies change.

## Shared proxy-cache server (`serve-cache` / `--proxy-cache`)

A scan of a real project makes hundreds of registry / advisory lookups — and every
machine that scans makes them again. `serve-cache` turns one machine into the cache
point for the others: one upstream call per provider resource per TTL for the whole fleet, on a
persistent on-disk base that survives restarts. The server's store lives in its **own
root** (`~/.vigie-vuln-proxy-cache/`), deliberately outside the scan's `~/.vigie-vuln/`
cache dir — the client caches and the shared base are two different roles and are never
bundled, swapped or merged together by `--export-cache` / `--import-cache`.

```bash
# Terminal 1 — start the server (default 127.0.0.1:8321, store ~/.vigie-vuln-proxy-cache/)
vigievuln serve-cache
vigievuln serve-cache --port 9000 --host 0.0.0.0 --token s3cret   # shared across machines
vigievuln serve-cache --nvd-key <key> --wordfence-key <key> --github-token <t>
vigievuln serve-cache --upstream-proxy http://corp-proxy:3128     # the server itself behind a corporate proxy

# Then every scan (same machine, CI runners, other developers) points at it:
vigievuln scan ./proj --proxy-cache http://127.0.0.1:8321
FAD_PROXY_CACHE_TOKEN=s3cret vigievuln scan ./proj --proxy-cache http://cache-host:9000
```

| Flag (serve-cache) | Effect |
| --- | --- |
| `--port <n>` / `--host <h>` | Listen address (default `127.0.0.1:8321`; `0.0.0.0` to share — use `--token`) |
| `--cache-dir <dir>` | Store location (default `~/.vigie-vuln-proxy-cache/` — its own root, never inside the scan's `~/.vigie-vuln/` caches) |
| `--ttl <seconds>` | Override every per-source TTL (defaults: OSV 12h, NVD + endoflife.date 7d, registries/EPSS/KEV/deps.dev 24h) |
| `--no-swr` | Disable serving an expired entry while refreshing it in the background (enabled by default); expiry becomes a blocking refetch |
| `--max-body-mb <n>` | Persistence limit per response (default 32 MiB); larger responses use a temporary spool, retired after 30 s when readers finish. CVE archives have a separate 1 GiB persistence limit |
| `--max-transfer-mb <n>` | Hard upstream body limit, including chunked bodies (default 1024 MiB); JSON batches additionally cap at 32 MiB |
| `--max-store-mb <n>` | Combined metadata, body and spool budget (default 2048 MiB); evicts the oldest collected unpinned entries, refuses writes if space cannot be freed |
| `--max-entries <n>` | Persistent entry limit (default 10000) |
| `--upstream-timeout <seconds>` | Deadline covering upstream headers and body, including background and batch requests (default 120 s) |
| `--max-concurrent <n>` | Maximum active upstream transfers (default 16); excess distinct requests fail, cached readers continue |
| `--nvd-key` / `--wordfence-key` / `--github-token` | API keys the **server** injects upstream (flags > `NVD_API_KEY` / `WORDFENCE_API_KEY` / `GITHUB_TOKEN` env > `--set-nvd-key` config). NVD/GitHub clients can use the server credentials. `--wordfence-live` activates targeted Wordfence queries using the server key alone, including `cache prepare` warming. Custom Wordfence feed URLs require direct mode and a client key. Without a server key, a client-sent credential is forwarded as-is |
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
- A dead proxy-cache server uses the local resource cache when that cache covers the request. Otherwise the source-health retry schedule runs and the scan writes a coverage warning. Failed required checks mark the report incomplete, or cancel the scan under `--fail-on-incomplete`.
- `--proxy-cache` and `--offline` are exclusive (offline makes no requests at all).

GitHub pagination links are retained in both caches; a headerless page cannot establish
a complete feed. CMS snapshots retain the upstream collection time
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
vigievuln serve-cache --wordfence-key <key> --max-store-mb 4096 --upstream-timeout 180
vigievuln scan ./wordpress --proxy-cache http://127.0.0.1:8321 --wordfence-live
vigievuln cache prepare deps.json --output cache.tar.gz --proxy-cache http://127.0.0.1:8321 --wordfence-live
```

When neither client nor server has a Wordfence key, the server refuses the request
before contacting Wordfence. The key is never exported with snapshots.

Wordfence proxy mode uses `wordfence/software`: at most 100 public `(type, slug)`
identities per request, without local paths or installed versions. The server fetches
and validates the production catalogue once per credential scope and TTL, retaining
it compressed in its own cache. The client receives only the requested software's
advisories, plus explicit queried identities and the original collection date. It
never retries a failed projection as a bulk or direct feed download. Custom feed
URLs cannot bypass this policy while a proxy is configured.

The targeted snapshot is stored separately as `wordfence-v3-targeted.json` and is
reused offline. An identity absent from its query list remains indeterminate.
On refresh failure, the server can serve its last validated catalogue with `stale`
metadata: positive findings remain visible, but advisory coverage is partial and
indeterminate. The collection date is never advanced; `--max-advisory-age` and
`--fail-on-incomplete advisories` apply. Merging snapshots keeps the oldest retained
collection date and conservatively retains a stale flag until that coverage is refreshed.
Bounds are 128 MiB for the upstream catalogue, the store's compressed-entry limit,
and 8 MiB for a client projection including merged batches; exceeding a limit fails
explicitly. An empty, malformed or truncated upstream catalogue cannot establish
negative coverage.

The hosted server's targeted Wordfence operation is provided by the shared resource
engine. It does not fall back to a client bulk-feed request when unavailable.

CMS snapshot imports compare the declared collection date, even if a copy has a
newer filesystem date. Semantic cache imports publish each body/metadata pair
atomically; interruption preserves the previous committed entry. This is a
per-entry guarantee, not a transaction spanning the entire imported cache.

### Corporate forward proxy (`--proxy`)

```bash
vigievuln scan ./proj --proxy http://corp-proxy:3128
```

Routes **every** outbound request through a corporate forward proxy (Node >= 24 or
bun — Node only honours `HTTP(S)_PROXY` with `NODE_USE_ENV_PROXY` set at process
start, so fad re-execs itself with the environment applied; verified: a mid-run
`process.env` change is silently ignored). A `--proxy-cache` URL in the same command
is added to `NO_PROXY` — traffic to the shared cache is local and stays out of the
tunnel. For the server-side equivalent see `serve-cache --upstream-proxy` above.

## Anonymized descriptor (air-gapped audits)

For an offline/confidential system that can't reach the vuln databases, split the scan
across machines using dependency coordinates, filtered version hints and eligible image
references with their requested platforms. Manifest paths, image declarations, build
contexts, variables and credentials are removed. Image references can contain private
registry hostnames or repository names; private coordinates and image references cannot
be identified offline. Exclude internal identities and review the complete descriptor
before transfer. The detailed report is produced **back offline**.

```bash
# Phase 1 — OFFLINE (audited machine): export the anonymized descriptor, then stop.
#   -e excludes private/internal packages (offline we can't classify private vs public).
vigievuln scan ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   deps.json is plain JSON (schema "fad-deps/1") — review it before transfer.

# Phase 2 — ONLINE (any machine, NO --src): prepare the project archive.
vigievuln cache prepare deps.json --output vigievuln-cache.tar.gz

# Phase 3 — OFFLINE (audited machine): full report with real paths/manifests.
vigievuln --import-cache vigievuln-cache.tar.gz   # merged into the enclave's own cache
vigievuln scan ./proj --offline               # re-collect locally + cache hits → full report
```

Why it works: vigievuln's caches are keyed by *coordinate* / *vuln id*, never by path,
so warming them online and replaying offline yields cache hits. The descriptor keeps
`ecosystem`/`ecosystemType`/`namespace`/`name`/`version`/`versions`/`scope`/`isDev` and
drops manifest paths, package download URLs, integrity hashes and parent chains. Eligible
image references and requested platforms are retained for online image preparation;
review private registry hosts and repository names before transfer. `--no-images` omits
them and skips image preparation. Dockerfiles remain offline and are not built online.
The phase-2
report is itself path-free; vendored-JS (retire.js) findings come from phase 3 (retire
needs the actual `.js` files), using the signature DB warmed in phase 2.

Maven descriptors include path-free per-module dependency and management hints so
the online preparation can resolve each module with its own versions and exclusions.
Review those hints along with the other coordinates before transfer. A descriptor without these hints produces a warning; regenerate it from the manifests
when they are available.
Preparation resolves the descriptor online and saves targeted OSV consultations;
it does not require or download a global OSV seed. Use the same resolution options
and unchanged manifests in both phases. Failed or depth-limited resolution can
leave dependencies undiscovered; a package or version found only during the offline
scan is reported as lacking verified OSV coverage unless an optional complete seed
is already available. Check the preparation and scan coverage warnings.

### Offline Docker integration check

Run `node scripts/test-offline-docker.cjs` with dependencies installed and the
`node:22-bookworm` image available locally. Set `VIGIEVULN_DOCKER_IMAGE` to use a
different image; `FAD_DOCKER_IMAGE` remains supported. The check exports a public
Maven fixture offline, warms its caches online, then scans it in a fresh container
with Docker's `--network none`. It verifies direct and transitive findings, report formats,
the expired-KEV gate and the absence of offline network attempts. It mounts no host
cache and excludes the full CVE index, EUVD and CERT-FR downloads; logs and reports
are retained in the printed temporary directory.

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

`vigievuln` queries each ecosystem's public registry by default. Register private ones for **`maven`, `npm`, `pypi`, `ruby`, `go`, `nuget`, `composer`** so transitive resolution, outdated/deprecation and license lookups reach them.

| Flag | Effect |
| --- | --- |
| `--add-repo <eco> <name> <url> [--auth user:pass] [--token TOK]` | Persist a registry (in `~/.vigie-vuln/config.json` under `registries.<eco>`). |
| `--remove-repo <eco> <name>` | Remove a persisted registry. |
| `--list-repos` | List configured registries, grouped by ecosystem (auth masked). |
| `--repo <eco>=<url>` | One-off, not persisted; **repeatable**; auth via inline `https://user:pass@host/`. |

```bash
vigievuln --add-repo maven   nexus     https://nexus.acme.com/repository/maven-public/ --auth alice:s3cr3t
vigievuln --add-repo npm     verdaccio https://npm.acme.com/                            --token "$NPM_TOKEN"
vigievuln --add-repo nuget   azure     https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json --token "$AZ_TOKEN"
vigievuln --add-repo composer satis    https://composer.acme.com/                       --auth alice:s3cr3t
vigievuln --list-repos
vigievuln scan ./proj --repo npm=https://npm.acme.com/ --repo maven=https://nexus.acme.com/repository/maven-public/
```

Registries are tried **in declared order, the public registry last** (first 2xx wins). `--auth user:pass` → `Basic <base64>`; `--token TOK` → `Bearer TOK`. Responses are cached per coordinate. Same-API constraint per ecosystem: **PyPI/Ruby** custom bases must expose the same JSON API as the public one (`<base>/<pkg>/json`, `<base>/<gem>.json`), not a bare PEP 503 simple index; **NuGet** bases speak the v3 registration API — a service index (`…/index.json`) is auto-resolved to its `RegistrationsBaseUrl`; **Composer** bases are queried via the v2 metadata API (`<base>/p2/<vendor>/<pkg>.json`).

## Configuration file & environment

The default cache and configuration directory is `~/.vigie-vuln/`.

Reusable defaults come from (lowest priority first): **`~/.vigie-vuln/config.json`** (global) → **`VIGIEVULN_ENV`** (a CLI-flag string; legacy `FAD_CHECKER_ENV` as fallback) → **config file** explicitly selected with `--config <file.json>` → **CLI flags** (always win). Files in the scanned repository are never loaded automatically: only select configuration you trust. A file/env value only fills an option you did not pass on the CLI; `registries` are unioned across all layers.

```bash
vigievuln --config ./ci/vigievuln-env.json                         # JSON file of defaults
VIGIEVULN_ENV='--fail-on high --no-nuget' vigievuln scan ./proj   # flag string of defaults
```

```jsonc
// ./.vigievuln-env.json — keys mirror the CLI options (camelCase)
{
  "source": "./my-project",            // or "src"; same as the path given to `vigievuln scan`
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

The source directory is the positional argument of `vigievuln scan <path>`; a configuration file may name it with the JSON key `"source"` or `"src"`. The former `-s`, `--src` and `--source` flags are rejected.

## NVD API key

NVD's public rate limit is 5 requests / 30s without a key. The free key bumps it to 50 / 30s — **10× faster** for the enrichment step.

```bash
# Get a key in 30 seconds: https://nvd.nist.gov/developers/request-an-api-key
vigievuln --set-nvd-key YOUR_KEY      # stored in ~/.vigie-vuln/config.json (mode 0600)
vigievuln --show-config               # confirm it's persisted (key masked)
```

Or pass it ad-hoc via the `NVD_API_KEY` env var.

## Snyk integration

If you have `snyk` installed and authenticated, `vigievuln` can drive it:

```bash
vigievuln scan ./proj -t ../proj-clean -e "^com\.acme\." --snyk
```

This:
1. Generates the cleaned POM tree at `../proj-clean/`.
2. Runs `snyk test --all-projects --json` against it.
3. Merges Snyk's findings into the report — entries present in both `vigievuln` and Snyk are tagged `source: "both"`.

`--snyk` requires `-t` (Snyk needs a real POM tree to scan).

If Snyk fails, the scan reports `Snyk run failed: <reason>` and continues with its own
findings. Snyk exit code 1 means vulnerabilities were found and is not a run failure.

## Read-only vs write mode

| Mode | Trigger | What runs | Disk writes |
| --- | --- | --- | --- |
| Read-only (scan) | `-t` omitted (default) | full scan + report | Only `~/.vigie-vuln/` caches and the report dir |
| Extraction | `-t <dir>` | walk + reactor linking + normalised descriptor tree + POM analysis (existence check → private-module list, when online), then stop | The normalised descriptor tree at `<dir>` (replaced only with `--force` if non-empty) + the existence cache |
| Extraction + scan | `-t <dir>` with `--snyk`, a `--report-<type>`, `--fail-on`, `--fail-on-new` or `--baseline` | both of the above | Both of the above |

The `--target` guardrails refuse:
- empty `--src`
- `--target` equal to or a subdirectory of `--src`
- `--target` containing `--src` (including via a symlinked parent)
- a non-empty `--target` unless `--force` is passed; a file or symlink target is always refused

## Verbosity

```bash
vigievuln scan . --verbose   # progress per source (OSV batches, NVD pages, retire scan, …)
```

## Help & version

```bash
vigievuln                  # no arguments: a mini help with the running version (exit 1 — nothing was scanned)
vigievuln -h, --help       # every option
vigievuln -v, --version    # print the running version (-V also works)
```

> `--verbose` is long-form only. `-v` prints the version and exits without scanning.

## Shell completion

```bash
vigievuln --completion bash > /etc/bash_completion.d/vigievuln
vigievuln --completion zsh  > ~/.zsh/completions/_vigievuln
```

## All flags at a glance

```bash
vigievuln --help
```

## Recipes

### CI gate: fail the build on any CRITICAL prod CVE

Use the severity gate; reports are written before the exit status is set:

```bash
vigievuln scan . --fail-on critical
```

Exit 1 means a blocking production or embedded-binary finding. Missing mandatory coverage returns code 2 and takes precedence over the findings threshold.

### Diff two runs

Keep dated copies of the report:

```bash
vigievuln scan . --report-output reports/$(date +%F)
diff reports/2026-04-01/cve-report.html reports/2026-05-01/cve-report.html
```

### Air-gapped scan (anonymized descriptor)

The robust way: export an anonymized descriptor offline, warm caches online from it,
re-scan offline. Exclude private dependencies and review all exported coordinates and
version hints before they leave the secure machine.

```bash
# OFFLINE (audited machine)
vigievuln scan ./real-project -e "^(client|internal)\." --export-anonymized deps.json

# ONLINE (connected machine, no source needed)
vigievuln cache prepare deps.json --output fad-cache.tar.gz

# OFFLINE again — full report with real paths
vigievuln --import-cache fad-cache.tar.gz    # merged, the enclave keeps what it had
vigievuln scan ./real-project --offline
```

See the **Anonymized descriptor** section above for what the descriptor contains and why
the round-trip prepares an offline report while retaining coverage warnings.

Proxy rate-limit retries use their own budget, independently of `--retries` for
source failures. They are capped at 15, with a minimum delay of three seconds
and a retry wait budget of 45 seconds **per request** by default. Only retry
delays scheduled for that request consume its budget; ordinary scanning and network
requests do not. Concurrent requests coordinate their cooldowns, but exhausting
one request’s budget does not disable retries for other requests. A longer Retry-After is
respected; if it exceeds the remaining budget, the available cached response is
retained. During a wait in an interactive terminal, press **S** or **Esc** to skip
further retries and continue using available data. Non-interactive runs never read
keyboard input. Skipping does not claim that missing consultations succeeded.
