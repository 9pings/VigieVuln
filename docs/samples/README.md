# HTML report samples

Generated with **VigieVuln 1.1.3** on **2026-10-29**, using the official hosted proxy and local caches. These are complete, standalone HTML exports, copied unchanged from actual scans. No findings or scores were added for the demo. Data-source dates, exclusions and limitations are included in each report. Counts describe this snapshot, not current upstream releases; one advisory affecting several dependencies can produce several findings.

| Sample | Source and scope | What to explore |
| --- | --- | --- |
| [Dubbo](dubbo.html) | Apache Dubbo **2.7.8**, commit `0be2a1bbbf9168490acecaf1eed1bd16cb8db402`; **105 Maven descriptors**, **400 dependencies** | 739 production findings, 140 dev findings, 8 KEV matches, 4 EOL frameworks; per-POM ownership, evidence, priority and remediation |
| [Multi-instance CMS/frameworks](multi-cms-frameworks.html) | **4 applications**, **270 application components**, **251 Composer dependencies** | Per-instance CVEs and ownership; application inventory and coverage; 5 EOL results; vendored JavaScript, certificate inventory, licenses and fix recommendations |

## Source corpus

- [Apache Dubbo 2.7.8](https://github.com/apache/dubbo/tree/0be2a1bbbf9168490acecaf1eed1bd16cb8db402): the README report screenshot is captured directly from this HTML sample.
- [WordPress 6.4.2](https://wordpress.org/wordpress-6.4.2.zip), under `wp/`.
- [Drupal 8.5.0](https://ftp.drupal.org/files/projects/drupal-8.5.0.tar.gz), under `drupal/`.
- [Symfony Demo v2.6.0](https://github.com/symfony/demo/tree/v2.6.0), under `symfony-demo/`; the supplied lockfile resolves `symfony/framework-bundle` **7.1.1**.
- [BookStack v24.10](https://github.com/BookStackApp/BookStack/tree/v24.10), under `bookstack/`; the supplied lockfile resolves `laravel/framework` **10.48.22**.

The CMS corpus contains source trees and their existing lockfiles, without installing packages or running application code. It is a demonstration of several independent applications in one directory, not a deployed service.

## Coverage to keep in mind

- The CMS scan selects **Composer** for dependency analysis. Vendored JavaScript and certificate discovery remain enabled. npm/yarn lockfiles are outside this sample's selected scope.
- Test directories are explicitly excluded. Default exclusions are also recorded in the report.
- WordPress inventory and checksum comparison ran against the official distribution, but **Wordfence advisory matching did not run** because a complete feed was unavailable in the cache. The report marks that coverage as indeterminate.
- The 146 certificates belong to WordPress's bundled CA trust store. They are public certificates, not 146 leaked private keys.
- Drupal uses a cached publisher advisory snapshot. Symfony and Laravel findings come from the dependency advisory lanes and are attributed to their application components.
- Cache gaps, missing lockfiles and unknown licenses are retained in the output. These samples do not claim complete runtime reachability or current security status.
- Both scans report an NVD stale-data warning: some retained NVD records could not be refreshed during these runs. The Dubbo scan also reports unresolved parent POMs; absence of findings does not establish that a dependency is safe.

## Reproduce

Arrange the CMS directories above under `multi-cms-frameworks/`. Use the existing upstream lockfiles. Create and verify a Vigie Vuln account, then run `vigievuln login` to configure the official proxy. Results may change as source data is updated.

```sh
vigievuln -s ./dubbo --proxy-cache vigievuln -a licenses -r html,json -o ./sample-dubbo

vigievuln -s ./multi-cms-frameworks --proxy-cache vigievuln --ecosystem composer \
  -a licenses --exclude-path '**/tests/**' '**/test/**' '**/Tests/**' '**/Test/**' \
  -r html,json -o ./sample-cms
```

Copy each `cve-report.html` to its corresponding filename here. HTML opens locally without a server or network connection. Updated source trees, cache contents or tool versions can change the findings; this directory preserves the demonstration snapshot, not a reproducible archive of every upstream feed.

`SHA256SUMS` covers the two published HTML files.
