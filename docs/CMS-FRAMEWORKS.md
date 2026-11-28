# CMS & frameworks — the instance view

VigieVuln inventories supported CMS and framework instances, their components and
attributable dependency findings. Each instance has its own report section, with
coverage and unresolved ownership shown separately. See [`USAGE.md`](USAGE.md) for
commands and options.

## What gets detected, and how

Detection is a **conjunction of positive physical markers** — a bare `require` constraint
never creates an application, so a plain PHP library that happens to depend on
`symfony/framework-bundle` scans as exactly that: a library. Every recognized layout found
in the tree is activated by the default `--app-plugins auto`; `--app-plugins none` opts
out, `all` forces every plugin. Several instances of the same product in one tree are each
inventoried and reported separately, with shared occurrences detailed in every exposed
instance.

| Product | Requires | Core version evidence | Components inventoried |
| --- | --- | --- | --- |
| **Ghost** | root `ghost` npm package, `index.js` and `core/boot.js` | root package version | core and themes with a Ghost engine declaration |
| **Redmine** | `Gemfile`, `config/application.rb` and `lib/redmine/version.rb` | literal `Redmine::VERSION` constants | core and locked gem dependencies |
| **WordPress** | `wp-load.php` + `wp-includes/version.php` + `wp-admin/index.php` | `$wp_version` | core, plugins (`Plugin Name`, `Update URI`), themes (`style.css`) |
| **Drupal 8–11** | `composer.json` `require.drupal/core` + `core/lib/Drupal.php` + `core.services.yml` | lock pin, observed `Drupal.php`, conflict reported | core, modules (`.info.yml`, incl. `modules/contrib`), themes, profiles |
| **Drupal 7** | `includes/bootstrap.inc` with the literal 7.x `VERSION` define + `modules/system/system.module` | `VERSION` | core, legacy `.info` extensions |
| **Symfony** | `bin/console`, `src/Kernel.php` or `app/AppKernel.php`, plus `symfony/framework-bundle` in the local lock or root requirements | `composer.lock` pin | framework, framework-components, bundles, libraries; Symfony Flex recipes (`symfony.lock`) |
| **Laravel** | `artisan` + `bootstrap/app.php` + the framework requirement | `composer.lock` pin | framework, bundles, libraries |
| **PrestaShop** | `config/config.inc.php`, plus root package `prestashop/prestashop` or the pair `config/settings.inc.php` + `classes/Tools.php` | `define('_PS_VERSION_', …)` | core, modules, themes |
| **TYPO3** | core requirement plus an entry point/site directory, or classic core manifest plus entry point/root package | observed core marker | core, extensions |
| **SPIP** | `spip.php` + `ecrire/inc_version.php` (the version constant must be readable) | `$spip_version_branche` | core, dist plugins (`paquet.xml`), user plugins (`paquet.xml` or legacy `plugin.xml`) |
| **Joomla / Magento (Adobe Commerce)** | their own marker sets | product-internal | core, extensions/modules, themes |

Versions are read from **bounded prefixes** of the marker files — no file is ever executed.

## Direct vs indirect, private vs public

A CVE on a core, framework, official component, bundle, plugin or theme is **direct**; a
CVE on one of its *libraries* is **indirect** under the component that introduces it — never
direct by mere lock presence. Attribution comes from proven component ownership
(`lib/applications/inventory.js`), not path guessing, and a finding shared by several
instances keeps its own origins in each.

**Private/custom components** (a plugin with a third-party `Update URI`, a module under
`modules/custom/`, anything you declare with `--private-component`) are inventoried
separately, their dependency CVEs stay in their own report group, and their private identities are not sent
to publisher feeds. Public dependencies can still be queried through dependency sources. They are listed with the
private packages of the other ecosystems and do not mark the report incomplete.

**WordPress plugins and themes are assessed by default**, under the slug of their official header URL or of their
directory. An extension the public catalogue does not know is classified private automatically.
`--public-component <relative-path>=<slug>` is only needed for an extension installed under a renamed directory.
A single-file plugin placed directly in `plugins/` (`hello.php`) is not named after its catalogue slug: it is
assessed under the slug of its official `Plugin URI`, and otherwise listed as a private component.

## Advisory lanes, per product

| Product | Advisory lane | Notes |
| --- | --- | --- |
| **WordPress** | **[WPVulnerability](https://docs.wpvulnerability.com/)** (automatic, public, no key) | core version and every plugin and theme, under the slug of its official header URL or of its directory; cached responses travel with the air-gapped cache; a component the catalogue does not know is listed as private; an invalid response or exhausted source retries mark the report incomplete |
| **WordPress** | **Wordfence v3 production feed** (`--wordfence-feed <file>` snapshot, or live with `WORDFENCE_API_KEY` / `--wordfence-api-key`) | matches plugins and themes under the same slug rule; `--wordfence-live --proxy-cache <url>` uses the server key; without a key on either side the request fails |
| **WordPress** (integrity) | **core checksums** (`--wp-checksums-live` / `--wp-checksums <file>`, `--wp-checksums-locale`) | modified / missing / extra core files are **diagnostics**, never CVE findings; `wp-content/` is user land |
| **Drupal** | **packages.drupal.org** per-package security advisories (`--drupal-advisories[-live]`) | queried for exactly the inventoried **public** `drupal/*` identities; `--max-advisory-age` bounds snapshot age |
| **PrestaShop** | the publisher's **GitHub security-advisories** feed (`--prestashop-advisories[-live]`) | whole-repository feed, range grammar normalized in the lane |
| **TYPO3** | the publisher's **GitHub security-advisories** feed (`--typo3-advisories[-live]`) | same mechanism |
| **SPIP** | **NVD product CVEs** for the core (`cpe:2.3:a:spip:spip`, `--spip-advisories[-live]`) | The NVD lane covers the core; SPIP plugins have no dedicated advisory lane and stay `not-run / CMS_ADVISORY_NOT_QUALIFIED`. The NVD API key is optional |
| **Symfony / Laravel** | **the dependency lanes** (OSV.dev, Packagist security-advisories, NVD) | this implementation uses Composer dependency sources; the `dependency-lanes` coverage row currently has the execution-proof limitation described below |
| **Joomla / Magento** | **per component** | this implementation has no dedicated publisher lane; Composer components use dependency sources (subject to the coverage limitation below), while source-only extensions retain `not-run / CMS_ADVISORY_NOT_QUALIFIED` |

A publisher advisory and a Composer finding for the same issue are merged with their source evidence.

## Coverage and its current limits

Every capability row names the component it is about; identical gaps group into one
actionable block per cause. Publisher lanes that did not run are `not-run` with their diagnostic
(`CMS_PROVIDER_UNCONFIGURED`, `CMS_IDENTITY_UNVERIFIED`, …), never a clean verdict. The
instance synthesis (`CMS & Frameworks` chapter) aggregates per capability **and** provider:
publisher lanes aggregate their recorded execution status. **Known limitation:** the `dependency-lanes` rows used by Symfony/Laravel and some
Joomla/Magento components currently infer `completed` from inventory membership.
They do not prove that OSV/Packagist actually evaluated the package and version.
Disabling those sources can still satisfy `--fail-on-incomplete advisories`.
Do not use that gate alone as evidence of complete framework advisory coverage;
source-disabled or cold-cache runs need an independent check of the dependency
source results until execution is recorded per package/version.

## The report

- **« CMS & Frameworks » chapter** — first CVE section whenever an instance was
  inventoried: an instance synthesis (observed version, direct/indirect counts, worst
  priority, aggregated coverage), then direct and transitive findings for the root project and its
  development dependencies. The modules and themes section groups direct advisories and
  indirect findings by owner. Each explicitly private extension has its own direct,
  transitive and development subsections. Component inventories open on demand. A **zero-finding instance keeps
  its chapter** with inventory and coverage. No findings do not prove a clean installation;
  review incomplete checks and activation evidence.
- **Application inventory & coverage chapter** — every inventoried component with its
  version and evidence path, and the per-source coverage table.
- **Overview chart** — `Most vulnerable instances` ranks exposed instances by
  critical/high application findings; a shared occurrence counts in each.

## The air-gapped workflow

An anonymized dependency descriptor includes the public application identities needed
to prepare supported publisher snapshots:

1. **Phase 1 (offline)** — `--export-anonymized` writes the public coordinates *and* the
   application identities: type, core version, and the inventoried **public** component
   identities (private components never leave the enclave; a module inventoried from its
   `.info.yml` without a lock entry is included, because the Drupal feed is keyed by
   package identity).
2. **Phase 2 (online)** — `cache prepare deps.json --output cache.tar.gz` warms the advisory snapshots the
   descriptor justifies, in one run: the Drupal feed (union of lock coordinates and
   inventoried identities — exactly the set the live source would query), the
   PrestaShop/TYPO3 repository feeds, the SPIP NVD product snapshot, one WordPress checksums reference per declared core
   version, and public WPVulnerability component responses by default. An explicitly selected Wordfence catalogue still works **with a client API key, or `--wordfence-live` and a key on the proxy** (the
   key itself never travels). Each snapshot is validated with its provider's schema before
   being written. The same command writes the project archive.
3. **Phase 3 (offline)** — `--import-cache` + the plain `--offline` scan. Cached snapshots
   are consumed **automatically, with no advisory flag** — in every mode, so the air-gapped
   scan can reuse the same publisher data as its online reference. This does not
   establish completeness of dependency caches or byte-identical reports.
   An explicit flag always wins; a corrupt snapshot, or one exceeding a configured age limit, fails the scan instead of
   silently under-reporting; `--max-advisory-age` applies to auto-consumed files exactly as
   to operator-supplied ones. Provenance follows the data: an auto-consumed snapshot
   reports `completeness: "tool-fetched"` with its stamp's `collectedAt` and source URL.

For the implementation and evidence model, see [Architecture](ARCHITECTURE.md).
