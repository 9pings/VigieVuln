# vigievuln vs other tools — and how it stays build-free

`vigievuln` is **not** a Trivy/Grype competitor — those are container-and-SBOM supply-chain
scanners. It targets a narrower job: a **zero-setup, multi-ecosystem audit of a source
checkout, with an audit-ready report and a confidential / air-gapped workflow** — the kind
of thing a security consultant or a regulated / air-gapped engagement needs.

## At a glance

| | **vigievuln** | OSV-Scanner | Trivy | Grype + Syft | OWASP DC | Snyk OSS |
| --- | --- | --- | --- | --- | --- | --- |
| Ecosystems it targets¹ | Maven, **Gradle**, npm, Yarn, **pnpm**, Composer, PyPI, NuGet, Go, Ruby + vendored JS + **native binaries** | 13 langs / 28 lockfile & manifest types | 13 langs (+ 23 OS families) | 20+ | Java/.NET (others exp.) | many |
| Reads lockfiles without `install`/build | ✅ | ✅ | ✅ | ✅ | ⚠️ Java needs Maven Central/build | ⚠️ Maven & pip need a build; npm/Yarn/pnpm/Composer lockfiles read directly |
| Best-effort when **no lockfile** (pinned versions) | ✅ | ~ manifests best-effort (`pom.xml`, `requirements.txt`…) | ❌ | ❌ | ⚠️ | ⚠️ |
| Vulnerability sources | CVEProject + OSV + Packagist audit lane (Composer) + NVD + EPSS + KEV + retire.js (+ Snyk), merged | OSV.dev | Aqua DB | Anchore DB | NVD / CPE | Snyk DB |
| False-positive control | CPE/version cross-check | ecosystem-aware | ecosystem-aware | ecosystem-aware | ⚠️ CPE → noisy | ecosystem-aware |
| **EOL** of an application framework⁴ | ✅ endoflife.date | ❌ | ⚠️ OS distros only | ❌ | ❌ | ❌ |
| **Outdated / deprecated** | ✅ registries + curated | ~ deprecated/yanked only, experimental flag | ❌ | ❌ | ❌ | ⚠️ web UI only (npm deprecated) |
| Containers / OS packages | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| SBOM (CycloneDX/SPDX) | ✅ CycloneDX 1.6 (+ CSAF 2.0 VEX) | ✅ | ✅ | ✅ CycloneDX (SPDX via Syft) | ~ | ✅ Enterprise plans |
| License compliance | ✅ SPDX + copyleft policy | ✅ deps.dev allowlist (online) | ✅ | ~ Syft collects, no policy | ~ displayed, no policy | ✅ paid plans |
| EPSS / KEV prioritization | ✅ FIRST.org EPSS + CISA KEV | ❌ | ❌ not native⁶ | ✅ | ⚠️ KEV only | ⚠️ web/API, not in the CLI |
| CI gating (`--fail-on`) + triage | ✅ severity/KEV + ignore/VEX | ✅ | ✅ | ✅ | ✅ CVSS threshold + suppressions | ✅ |
| Malware / typosquat | ⚠️ OSV `MAL-` gate + `--typosquat` heuristic | ~ `MAL-*` via OSV.dev, undocumented | ❌ out of scope by design | ❌ | ❌ | ✅ |
| Auto-remediation / PRs | ❌ (fix recipes only) | ✅ `fix` (experimental; npm + Maven) | ❌ | ❌ | ❌ | ✅ fix PRs + Remediation Agent (early access) |
| Offline | ✅ cache | ✅ local DB | ✅ | ✅ | ✅ feed | ❌ (.NET only, since 1.1307) |
| Offline Maven **transitive** graph³ | ✅ cached POMs | ❌ disabled under `--offline` | ⚠️ needs a populated `~/.m2` | ⚠️ opt-in, off by default⁵ | ⚠️ mirror | ❌ |
| **Scan without exposing paths**² | ✅ anonymized descriptor | ❌ | ❌ | ⚠️ SBOM, carries paths | ❌ | ❌ |
| **Maven private-dep cleanup** (→ Snyk) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output | **HTML + Word `.doc`** + JSON / SARIF / CycloneDX / CSAF | table/markdown/HTML/JSON/SARIF/SPDX/CycloneDX | table/JSON/SARIF/CycloneDX/SPDX (HTML via template) | table/JSON/SARIF/CycloneDX | HTML/XML/CSV/JSON/JUnit/SARIF/GitLab | JSON/SARIF (+ `snyk-to-html`), cloud UI |

¹ Narrower language coverage — no Rust/Dart/Swift (Go and Ruby are now covered).

² Phase 1 exports only public coordinates; the online scan never sees your source tree
(see [Air-gapped](../README.md#air-gapped-audits)). Two honest qualifications. **(a)** You *can*
approximate this elsewhere by generating an SBOM on the isolated machine and scanning it online
(`grype sbom:./sbom.json`, `trivy sbom`). The difference is that a Syft SBOM is **not
anonymized**: its CycloneDX encoder stamps every component with `syft:location` file paths, so
the SBOM carries your internal tree layout off the machine. VigieVuln's `fad-deps/1` descriptor drops
paths, registry URLs, integrity hashes and parent chains by construction.
**(b)** The direction differs: in the SBOM route the *report* is produced online; VigieVuln brings a
cache back and produces the report, with real paths and manifests, **inside** the enclave.
Sources: [Syft CycloneDX encoder](https://github.com/anchore/syft/blob/main/syft/format/internal/cyclonedxutil/helpers/component.go),
[Grype README](https://github.com/anchore/grype/blob/main/README.md).

³ Measured on **Apache Dubbo 2.7.8** (105-module reactor, commit `0be2a1bb`), two ways, on
distinct `(coordinate@version | vulnerability)` pairs with GHSA/`SNYK-*` ids mapped to their CVE
alias and the project's own artifacts excluded on every side.

**At full capability** — every scanner online, best configuration, populated `~/.m2`. Union of
all findings: 908 pairs.

| Scanner | Found | Unique to it | Not reported |
| --- | --- | --- | --- |
| **vigievuln** | **790 (87.0%)** | 125 | 118 → **0 real** |
| OSV-Scanner 2.4.0 | 657 (72.4%) | 0 | 251 |
| Snyk 1.1302.1 (mvn build) | 603 (66.4%) | **117** | 305 |
| Trivy 0.72.0 | 546 (60.1%) | 0 | 362 |
| Grype 0.116.0 + Syft 1.49.0 | 45 (5.0%) | 0 | 863 |

**"Not reported" is union arithmetic, not a verified recall gap.** It counts pairs another tool
produced and this one did not, which is a miss only if the public record actually binds that
vulnerability to that coordinate and version. For vigievuln that was checked pair by pair
against OSV: **0 are recall bugs**, and roughly two thirds are Snyk contradicting the public
record — wrong artifact, or a version outside every declared affected range
([method and caveats](BENCHMARK.md#what-vigievuln-misses-and-why), reproduce with
`scripts/adjudicate-gap.js`). The other rows have **not** been adjudicated, so read their column
the same way. Snyk and Trivy at full capability both assume a real Maven build has happened; VigieVuln
and OSV-Scanner read the tree without one.

**With no network at all** (every tool under `unshare -rn`, against OSV-Scanner's *online* output
as the reference, 657 pairs): **vigievuln 657 (100%)**, Grype+Syft 45, Trivy 40 on a cold
`~/.m2`, OSV-Scanner 37 — its transitive resolution is disabled offline, per its own docs:
> "This feature is enabled by default when scanning, but it can be disabled using the
> `--no-resolve` flag. It is also disabled in the offline mode."
> — [supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

100% there means "recovers everything OSV-Scanner finds *with* network access", not "finds
everything that exists" — the first table is the honest answer to that. Full method, per-tool
configuration, the mirror trick for Maven Central rate limits, and every caveat →
[`BENCHMARK.md`](BENCHMARK.md).

⁴ Scoped deliberately to **application** frameworks and libraries (Spring Boot 2.x, AngularJS,
Django, a deprecated npm package). Trivy *does* compute an end-of-service-life status, but only
for **OS distributions** (`pkg/detector/ospkg/detect.go`). Snyk's Package Health Score exists
only on `security.snyk.io` package pages; its docs state that CLI, IDE and CI/CD integrations do
not display package health, so it can't gate a build on it.

⁵ Syft has `java.resolve-transitive-dependencies`, but it is **opt-in and `false` by default**:
the option lives on `ArchiveCatalogerConfig` and its doc comment reads "for java packages found
**within archives**". The `pom.xml` cataloger does receive the same config, but resolution then
depends on Maven Central (`java.use-network`, also `false` by default) or a populated
`~/.m2` — nothing is resolved offline. Measured on Dubbo 2.7.8, enabling both options changed
the result by zero findings (58 → 58). Syft's own tip is to run `mvn help:effective-pom` first,
which needs both Maven and a network. Source:
[`config.go`](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/java/config.go)
(unchanged as of Syft 1.51.1).

⁶ Trivy has no EPSS/KEV enrichment in the CLI (feature requests
[#10706](https://github.com/aquasecurity/trivy/discussions/10706) and
[#10840](https://github.com/aquasecurity/trivy/discussions/10840) are open); only the separate
"trivy reporting" web app adds EPSS. Malware is out of scope by its
[project principles](https://trivy.dev/docs/latest/community/principles/).

**Versions compared** (table last verified **2026-09-14**, every cell re-checked against the
upstream docs of that day): OSV-Scanner **v2.6.0** (on OSV-SCALIBR 0.5.2), Trivy **v0.74.0**,
Grype **v0.118.0** + Syft **v1.51.1**, OWASP Dependency-Check **v13.0.0**, Snyk CLI
**v1.1307.2**. The measured benchmark rows keep the version they were measured with. All of these
are actively maintained projects; none of the ⚠️/❌ cells above mean "abandoned". Every
competitor cell is meant to be checkable against the linked upstream doc. If one is wrong or has
gone stale, [open an issue](https://github.com/9pings/VigieVuln/issues) and it gets corrected.

**Where it fits:** a one-shot audit of a polyglot checkout you may not be able to build, a
presentable HTML/Word deliverable, and confidential / air-gapped engagements.

**Where it doesn't:** container/OS scanning and auto-fix PRs — reach for **Trivy** or
**Grype + Syft**.

**Reachability is a deliberate non-goal**, not a gap on the roadmap. A finding here is a vulnerable
version on the dependency graph, stated as such in the report's *Methodology, data sources &
limitations* chapter. Call-graph reachability answers a different question, needs the application
context an auditor has and a scanner doesn't, and an unreachable-therefore-ignored verdict is
exactly the kind of judgement an audit should not automate.

You don't have to choose — `vigievuln` takes Snyk's results as input (`--snyk`) and merges them.

## What moved in 2025–2026

Checked on 2026-09-14 against the projects' own repositories and docs. The five tools above are
still the right column set; these are the newcomers and shifts worth knowing about, and the
reason each one is or isn't in the table.

| Project | What changed | Overlap with vigievuln | In the table? |
| --- | --- | --- | --- |
| [OSV-SCALIBR](https://github.com/google/osv-scalibr) v0.5.2 (2026-08) | Google's extraction engine; OSV-Scanner 2.5+ runs on it end-to-end. Build-free `pom.xml` transitive resolver, deps.dev deprecation + license, 70+ secret detectors, Go/Java reachability, OS-only EOL ([inventory](https://github.com/google/osv-scalibr/blob/main/docs/supported_inventory_types.md)) | Direct — it is now the OSV-Scanner column. No EPSS/KEV, no framework EOL, no offline Maven graph | Via OSV-Scanner |
| [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) v6.3.0 (2026-07) + [cdxgen](https://github.com/CycloneDX/cdxgen) v13 | Reachability across 7 languages, CSAF 2.1 VEX/VDR, air-gapped vulnerability DB (`vdb --download-image`). cdxgen still states "Apache maven 3.x is required for parsing pom.xml", with a degraded pom fallback flagged by its own build-fidelity rule ([project types](https://github.com/CycloneDX/cdxgen/blob/master/docs/PROJECT_TYPES.md)) | Closest in spirit for air-gapped audits; Maven needs a build for the full graph, no EPSS/KEV, no EOL/outdated | Not yet — candidate for a 7th column |
| [OWASP cve-lite-cli](https://github.com/OWASP/cve-lite-cli) v1.34 (2026-09, [Lab project since 2026-07](https://owasp.org/blog/2026/07/06/cve-lite-cli-lab.html)) | New: JS/TS lockfiles only, OSV with offline sync, EPSS-tiered priority, parent-aware `--fix`, HTML/SARIF/CycloneDX/SPDX | npm slice of VigieVuln only; no Maven, no KEV, no EOL | No (single ecosystem) |
| [safedep vet](https://github.com/safedep/vet) v1.19 (2026-08) | Malicious-package analysis + CEL policy-as-code over npm/PyPI/Maven/Go/Ruby/Rust/PHP lockfiles, OpenSSF Scorecard, SARIF/HTML | Supply-chain policy rather than audit report; malware verdicts come from the SafeDep cloud | No (cloud-backed) |
| [GuardDog](https://github.com/DataDog/guarddog) v3.2 (2026-08) | Sandboxed malware heuristics (YARA + metadata) for PyPI/npm/Go/Rust/Ruby; no CVEs, no Maven | Complements VigieVuln's `MAL-` gate + typosquat heuristic; a different question | No (malware only) |
| [Dependency-Track](https://dependencytrack.org/news/dependency-track-5-1/) 5.1 (2026-08) | Platform rewrite; v4 EOL December 2026. Ingests SBOMs, adds EPSS + CISA/ENISA KEV, outdated-component and license policy | Not a scanner: VigieVuln's CycloneDX export is an input for it | No (SBOM-ingest platform) |
| [HeroDevs CLI](https://github.com/herodevs/cli) 2.0 (2026-07) | Package-level EOL/abandonment over a proprietary 12M-version dataset, cdxgen-based, login required | The only other CLI that answers VigieVuln's EOL question, on paid data | No (proprietary data) |
| [xeol](https://github.com/xeol-io/xeol) | Open-source EOL scanner over Syft: no release since v0.10.8 (2025-03), no commit since 2025-03 | Was the obvious EOL peer; dormant for 18 months | No (dormant) |
| Snyk CLI 1.1307 (2026-08/09) | `snyk agent` (experimental, token-optimised output for AI coding agents), Remediation Agent in early access, .NET scans fully offline, reachability without a build (source is uploaded) | Snyk column updated above | Yes |
| Trivy 0.73–0.74 (2026-08) | User-defined Maven mirrors in `trivy.yaml`, JAR licence URLs → SPDX ids. Still no EPSS/KEV in the CLI, malware out of scope | Trivy column updated above | Yes |

Left out on purpose: [bomber](https://github.com/devops-kung-fu/bomber) (last release 2024-09),
[Semgrep Supply Chain](https://docs.semgrep.dev/semgrep-supply-chain/getting-started), Socket,
Endor Labs and Aikido (proprietary or SaaS-gated CLIs), Dependabot / Renovate /
`dependency-review-action` (hosted bots, not local scanners), and a handful of 2026 zero-star
repositories (lockvet, IcebergSCA) that have not yet earned a comparison.

> Sources: [OSV-Scanner lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) ·
> [Trivy Java/`pom.xml` (Maven Central, `--offline-scan`)](https://trivy.dev/docs/latest/coverage/language/java/) ·
> [Syft `java-pom-cataloger` (source dirs)](https://github.com/anchore/syft/issues/676) ·
> [OWASP DC needs internet/build for Java](https://jeremylong.github.io/DependencyCheck/data/index.html) ·
> [Snyk requires building the project](https://docs.snyk.io/supported-languages/technical-specifications-and-guidance) ·
> [EOL/outdated "most tools skip" (Aikido)](https://www.aikido.dev/code/outdated-eol-software)

## Detection on presence: how the official tools select what to scan

vigievuln's application plugins are activated by the default `--app-plugins auto` — a
present CMS/framework is inventoried. Checked against each ecosystem's own tools
(2026-09-23): **automatic detection of what is present is the norm, opt-in per product is
the exception.**

| Tool | What it does when pointed at a tree |
| --- | --- |
| `composer audit` | Audits the `composer.lock` of the current directory — whatever is in it, no selection |
| [OSV-Scanner](https://google.github.io/osv-scanner/) `scan -r .` | Recursively scans **every** supported lockfile/manifest/SBOM it finds; auto-detection is the default subcommand |
| [Trivy](https://trivy.dev/) `fs .` | Auto-detects every language's lockfiles present; ships a `precise` (default) vs `comprehensive` (more findings, more false positives) detection mode |
| [Snyk](https://docs.snyk.io/scan-with-snyk/snyk-cli) `test` | Auto-detects the package manager of the current directory; `--all-projects` extends to auto-discovery of every manifest found |
| [drush](https://www.drush.org/) `pm:security` | Bootstraps the Drupal site it is in and checks every `drupal/*` package present — no opt-in |
| [WP-CLI](https://make.wordpress.org/cli/) (+ a vulnerability-scanner package) | Only runs **inside** a WordPress installation — the CMS being present is the tool's precondition |
| [WPScan](https://wpscan.com/) | Fingerprint-detects WordPress automatically; since 2026 its default enumerates only core + active theme, with plugins behind `-e ap` — an API-quota economy, not a detection gate |
| Wordfence | Only works on an installed WordPress at all |

The one tool that pulled automatic scope back (WPScan) did it to spare a cloud API's
request budget — its CMS *detection* stayed automatic. vigievuln's split matches that
logic without the constraint: local inventory (cheap, no network) is automatic on
detection, while the networked advisory sources stay behind their explicit configuration
and report `not-run (CMS_PROVIDER_UNCONFIGURED)` until then — never a silent clean
result. Experimental capabilities stay labelled as such (like Trivy's `[EXPERIMENTAL]`
flags), not hidden behind an opt-in. False-positive control is the analogue of Trivy's
`precise` mode: every plugin's detection is a conjunction of positive physical markers
(a bare `require` constraint never creates an application), verified on real bare
libraries (guzzle/guzzle, laravel/framework as a package, the symfony/symfony monorepo,
composer/composer): zero phantom applications.

## How it's autonomous (no build tools)

Because it doesn't need anything you don't already have on disk:

| You don't need | Why |
| --- | --- |
| Maven installed | `pom.xml` files are parsed directly with xml2js. Properties, profiles and local BOMs are resolved in-process. Transitive deps are fetched from Maven Central by default (cached forever); `--no-transitive` disables it. |
| `mvn dependency:tree` | Same as above. We walk the tree ourselves. |
| `npm install` / a `node_modules/` | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry/v2+) and `pnpm-lock.yaml` (v5/v6/v9) are parsed as text/JSON/YAML. Versions come from the lockfile — no installation. |
| `yarn install` / `pnpm install` | Same. We read `yarn.lock` (v1 + Berry) and `pnpm-lock.yaml` directly. |
| `composer install` | `composer.lock` is parsed directly (concrete versions + transitive). `composer.json` alone → best-effort on pinned versions + warning. |
| `pip` / `poetry` / a venv | `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock` are parsed for concrete versions; `pyproject.toml` (PEP 621 + poetry) and `requirements.txt` (following `-r`/`-c` includes) are best-effort on exact pins. Names normalised per PEP 503. |
| `dotnet restore` | `packages.lock.json` is parsed; otherwise `*.csproj`/`*.fsproj`/`*.vbproj` (+ `Directory.Packages.props` Central Package Management) and legacy `packages.config`, best-effort on pinned versions. |
| `go build` / a Go toolchain | `go.mod` is parsed (the full pruned graph on Go ≥1.17, `// indirect` → transitive); `go.sum` is the fallback. No module download. |
| `bundle install` | `Gemfile.lock` is parsed for the resolved gem set. No Ruby, no bundler. |
| `snyk` binary | Built-in CVE matching via CVEProject + OSV + NVD (merged), prioritised with EPSS + CISA KEV. Snyk is *optional* (`--snyk`). |
| A network connection | First run downloads CVE / OSV / EOL data; subsequent runs use cached copies (`--offline` to force). |

For each ecosystem it reads the **lockfile** (or, failing that, the manifest's pinned versions) straight off disk:

| Ecosystem | Read directly | Transitive versions come from |
| --- | --- | --- |
| Maven | `pom.xml` (+ parents, BOMs, profiles) | child POMs fetched from Maven Central (cached) — resolved **per-module** so a depMgmt pin in one module can't hide a vulnerable transitive in another |
| Gradle | `gradle.lockfile` → `gradle/libs.versions.toml` → `build.gradle(.kts)` best-effort (Groovy+Kotlin DSL, `libs.*` catalog, `buildSrc/`) | child POMs from Maven Central (same as Maven); `platform(...)` BOMs backfill versionless deps |
| npm / Yarn / pnpm | `package-lock.json` · `yarn.lock` (v1+Berry) · `pnpm-lock.yaml` | the lockfile itself |
| Composer | `composer.lock` (else `composer.json`) | the lockfile |
| PyPI | `poetry.lock` · `Pipfile.lock` · `uv.lock` · `pdm.lock` (else `pyproject.toml`/`requirements.txt`) | the lockfile |
| NuGet | `packages.lock.json` (else `*.csproj`/`packages.config`) | the lockfile |
| Go | `go.mod` (`// indirect` → transitive; `go.sum` fallback) | the module graph in `go.mod` |
| Ruby | `Gemfile.lock` (`specs:`) | the lockfile |
| Vendored JS / binaries | the committed `.js` / `.jar` / `.so` files themselves | n/a (read in place) |

Highlights of the matching layer: **four CVE sources merged** (CVEProject + OSV.dev + NVD +
the Packagist security-advisories endpoint `composer audit` queries, for Composer — measured
at exact parity with `composer audit` on the four real CMS/framework instances, closing the
class of CVEs OSV carries without composer coordinates),
**CPE/version cross-check** to drop false positives, **EPSS + CISA KEV** prioritisation,
lockfile-first with a **best-effort pinned-version fallback** when no lockfile, in-memory
**embedded-JAR** unzip (no disk, no zip-slip), and **checksum identity** for native binaries.
Pipeline and per-stage detail → [`ARCHITECTURE.md`](ARCHITECTURE.md).
