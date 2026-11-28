# Data sources & acknowledgments

`vigievuln` is glue around several outstanding public datasets. Each is used per its license terms.

| Source | What we use | License | API / endpoint |
| --- | --- | --- | --- |
| [CVEProject `cvelistV5`](https://github.com/CVEProject/cvelistV5) | CVE records used for Maven and explicitly identified native packages; coverage depends on collected records and package/version evidence | CC0-1.0 | GitHub release asset (zip), local index or configured proxy |
| [VigieVuln advisories](https://www.vigievuln.fr/advisories/vigievuln?lang=en) | Reviewed Maven/npm package and version evidence; `VV:CVE-…` identifies each CVE | Sources and AI-assisted reconciliation disclosed per advisory | Official authenticated proxy; cached for offline scans |
| [OSV.dev](https://osv.dev/) (Google + GitHub Security Lab) | Per-dep vulnerability lookup (Maven, npm, Packagist, PyPI, NuGet, …); full DB import via `--osv-db` | CC-BY 4.0 | `POST api.osv.dev/v1/querybatch`, `GET api.osv.dev/v1/vulns/{id}`, `Maven/all.zip` |
| [NIST NVD](https://nvd.nist.gov/) | Canonical CVE description + CVSS vectors + CPE configurations + CWE | US-gov public domain | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` — free [API key](https://nvd.nist.gov/developers/request-an-api-key) bumps the rate limit 10× |
| [FIRST.org EPSS](https://www.first.org/epss/) | Exploit-prediction score + percentile per CVE | CC-BY 4.0 | `GET api.first.org/data/v1/epss?cve=…` (batched) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited-vulnerability catalogue membership | US-gov public domain | `GET cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| [ENISA EUVD](https://euvd.enisa.europa.eu/) | EUVD id of each matched CVE + ENISA's exploited catalogue (reported, not gated) | ENISA legal notice — reproduction authorised, source acknowledged | `GET euvdservices.enisa.europa.eu/api/dump/cve-euvd-mapping` + `GET …/api/search?exploited=true&size=100&page=N` (bulk only, no CVE id sent) |
| [GCVE](https://gcve.eu/) (CIRCL) | Independent advisory collection and GCVE identifiers for CVEs | Public data | Proxy or local index; cached for offline scans |
| [CERT-FR (ANSSI)](https://www.cert.ssi.gouv.fr/) | The CERT-FR advisories and alerts citing each matched CVE, linked (never framed) | Licence Ouverte / Etalab 2.0 — source and date | `GET cert.ssi.gouv.fr/{avis,alerte}/json/` + one `…/<ref>/json/` per new or revised advisory (local index, no CVE id sent) |
| [endoflife.date](https://endoflife.date/) | Framework / runtime lifecycle — both the `eol` date (always) and the `support` date (`--eol-support`) | MIT | `GET endoflife.date/api/{product}.json` |
| [Packagist](https://packagist.org/) p2 metadata | **Dev-time only** — `replace: self.version` tables of `symfony/symfony` / `laravel/framework` to generate `data/eol-composer-frameworks.json` (`scripts/gen-composer-eol-map.js`). This p2 endpoint is not queried during a scan. | MIT (metadata) | `GET repo.packagist.org/p2/{vendor}/{pkg}.json` |
| [Packagist security advisories](https://packagist.org/apidoc#list-security-advisories) | Composer package advisories and affected version constraints, the source queried by `composer audit`; cached per package for offline scans | Packagist public API | `GET packagist.org/api/security-advisories/?packages[]=…` |
| [Ruby advisory database](https://github.com/rubysec/ruby-advisory-db) (rubysec) | RubyGems advisories with patched and unaffected version requirements, the data `bundler-audit` reads; carries advisories GitHub's reviewed database and OSV do not have for gems. One archive, cached for offline scans; no package name is sent | Public domain (advisories as published by their authors) | `GET codeload.github.com/rubysec/ruby-advisory-db/tar.gz/refs/heads/master` |
| [Wordfence Intelligence v3](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/) | WordPress core, public plugin and theme advisories; live production feed needs a free bearer API key, or an operator-supplied local snapshot | Wordfence Intelligence terms | `GET www.wordfence.com/api/intelligence/v3/vulnerabilities/production` |
| [Drupal security advisories](https://packages.drupal.org/8/packages.json) | Per-package Drupal core and public extension advisories, live or from a local snapshot | Drupal.org public API | `GET packages.drupal.org/8/security-advisories?packages[]=…` |
| [GitHub repository security advisories — PrestaShop](https://github.com/PrestaShop/PrestaShop/security/advisories) | PrestaShop core advisories as published by the vendor on its own repository (the machine-readable channel `composer audit` cannot see for a source tree); live or from a local snapshot | Publisher's own advisories | `GET api.github.com/repos/PrestaShop/PrestaShop/security-advisories` |
| [GitHub repository security advisories — TYPO3](https://github.com/TYPO3/typo3/security/advisories) | Per-package TYPO3 CMS advisories (`typo3/cms-core`, system extensions) as published by the vendor on its own monorepo; live or from a local snapshot | Publisher's own advisories | `GET api.github.com/repos/TYPO3/typo3/security-advisories` |
| [WordPress.org core checksums](https://developer.wordpress.org/rest-api/reference/core-checksums/) | MD5 reference of the official WordPress distribution, pinned per version and locale, for the core file-integrity capability | WordPress.org public API | `GET api.wordpress.org/core/checksums/1.0/?version=…&locale=…` |
| [Maven Central](https://search.maven.org/) | Latest-version lookups + transitive POM fetches | Free public service | Solr `search.maven.org/solrsearch/select?q=…` + `repo1.maven.org/maven2/<coord>` |
| [npm registry](https://registry.npmjs.org/) | Per-version `deprecated` + `dist-tags.latest` | Free public service | `GET registry.npmjs.org/<pkg>` |
| [Packagist](https://packagist.org/) | Latest stable + `abandoned` flag | Free public service | `GET packagist.org/packages/<vendor>/<pkg>.json` |
| [PyPI](https://pypi.org/) | Latest + `yanked` + "Inactive" classifier | Free public service | `GET pypi.org/pypi/<pkg>/json` |
| [NuGet](https://www.nuget.org/) | Latest stable + per-version `deprecation` | Free public service | `GET api.nuget.org/v3/registration5-gz-semver2/<id>/index.json` |
| [Go module proxy](https://proxy.golang.org/) | Latest module version and module version information | Free public service | `GET proxy.golang.org/<module>/@latest` and `/@v/<version>.info` |
| [Debian security tracker](https://security-tracker.debian.org/) and [Debian Sources](https://sources.debian.org/) | Distribution package advisories, historical tracker data and source-version evidence for image inventories | See each source's terms | Salsa security-tracker repository and `sources.debian.org/api/src/<name>/<version>/` |
| [Alpine security tracker](https://security.alpinelinux.org/) | Source-package and CVE status for Alpine image inventories | See source terms | `GET security.alpinelinux.org/srcpkg/<name>` and `/vuln/<CVE>` |
| [Freexian Extended LTS](https://deb.freexian.com/extended-lts/tracker/) | Extended-LTS tracker and ELA advisory evidence for eligible Debian image inventories | See source terms | `deb.freexian.com/extended-lts/tracker/` and `www.freexian.com/lts/extended/updates/` |
| [NGINX security advisories](https://nginx.org/en/security_advisories.html) | Publisher advisory evidence for identified NGINX image components | See source terms | `raw.githubusercontent.com/nginx/nginx.org/master/xml/en/security_advisories.xml` |
| [RubyGems](https://rubygems.org/) | Latest stable + licenses | Free public service | `GET rubygems.org/api/v1/gems/<gem>.json` |
| [deps.dev](https://deps.dev/) | Native-binary identity by checksum (→ package coordinate) | Free public API (CC-BY) | `GET api.deps.dev/v3/query?hash.type=SHA1&hash.value=<base64>` |
| [CIRCL hashlookup](https://hashlookup.circl.lu/) | Known-good file identity (NSRL/distro/CDN) + KnownMalicious | Free public service | `GET hashlookup.circl.lu/lookup/sha256/<hash>` |
| [retire.js](https://retirejs.github.io/retire.js/) | Vendored-JS signature DB + scanner | Apache-2.0 | npm package `retire`, executed locally |
| [Snyk](https://snyk.io/) (optional) | Additional CVE source via `snyk test --all-projects --json` | Per Snyk EULA; needs a Snyk account | Local CLI `snyk` |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness category links in the report | Free public reference | Linked by URL only, no API call |

Persistent caches (`~/.vigie-vuln/`) reduce source requests according to their TTL (full
table → [`USAGE.md`](USAGE.md)). Requests use the named source or the configured proxy;
the hosted proxy receives the requested package coordinates and vulnerability identifiers.
`--offline` makes no network requests.

Image scans may also consult the distribution and publisher sources above, Go module
version information and upstream GitHub security advisories when applicable. Explicit
registry acquisition or update checks contact the selected OCI registry and, when
challenged, its authentication service. Registry requests reveal the requested image
repository and reference; see [`IMAGES.md`](IMAGES.md) for authentication and offline
inventory workflows. Source availability and the evidence actually consulted are
recorded in the report; a source listed here is not necessarily consulted on every scan.

Application inventory reads local files. Configured PrestaShop and TYPO3 advisory
lanes also query the GitHub repository feeds listed above. SPIP core advisories use
NVD's product query (`virtualMatchString=cpe:2.3:a:spip:spip`), routed through the
shared proxy when configured. Joomla and Magento source-only components retain
unqualified publisher coverage; this implementation has no dedicated publisher
advisory lane for them. Public Composer dependencies still use OSV/Packagist. Adobe Commerce
packages distributed through `repo.magento.com` are excluded from Packagist audit
and its public package metadata lookup;
an omitted Packagist response is reported as unknown advisory coverage for that package;
it is never cached or treated as a clean advisory result.
