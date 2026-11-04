# HTML report samples

Generated with **VigieVuln 1.2.1** on **2026-11-04** from real source scans. The Dubbo scan uses the official hosted proxy; the CMS scan runs offline against the local cache scoped to that same proxy. These are complete, standalone HTML exports, copied unchanged from actual scans. No findings or scores were added for the demo. Data-source dates, exclusions and limitations are included in each report. Counts describe this snapshot, not current upstream releases; one advisory affecting several dependencies can produce several findings.

| Sample | Source and scope | What to explore |
| --- | --- | --- |
| [Dubbo](dubbo.html) | Apache Dubbo **2.7.8**, commit `0be2a1bbbf9168490acecaf1eed1bd16cb8db402`; **105 Maven descriptors**, **400 dependencies** | 668 production findings, 127 dev findings, 7 KEV matches, 4 EOL frameworks; per-POM ownership, evidence, priority and remediation |
| [Multi-instance CMS/frameworks](multi-cms-frameworks.html) | **4 applications**, **281 application components**, **251 Composer dependencies** | 192 production findings and 8 dev findings; per-instance ownership, application coverage, vendored JavaScript and certificate inventory |

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
- WordPress inventory ran against the official distribution. **Wordfence advisory matching, WordPress checksum comparison and the Drupal publisher-advisory check did not run** in the CMS snapshot because their required inputs were absent from the scoped cache. The report marks those three checks as indeterminate.
- The 146 certificates belong to WordPress's bundled CA trust store. They are public certificates, not 146 leaked private keys.
- Drupal, Symfony and Laravel package findings come from the available dependency advisory lanes; the CMS inventory attributes them to their application components. No synthetic advisory feed was used.
- Cache gaps, missing lockfiles and unknown licenses are retained in the output. These samples do not claim complete runtime reachability or current security status.
- The CMS snapshot retains stale-source notices and advisory ranges that could not be evaluated. Its Packagist registry/advisory cache is missing, and the available lifecycle cache does not establish the lifecycle status of these PHP applications: zero EOL results is not a claim that they remain supported. The Dubbo online scan retains dated Maven/OSV/NVD/EPSS cache notices and partial CVEProject/GCVE coverage, and also reports unresolved parent POMs. Its enriched results include 7 KEV matches and 4 EOL frameworks; absence of findings does not establish that a dependency is safe.

## Reproduce

Arrange the CMS directories above under `multi-cms-frameworks/`. Use the existing upstream lockfiles. Create and verify a Vigie Vuln account, then run `vigievuln login` to configure access to the official proxy. The CMS offline command requires a previously warmed cache for this proxy origin; it does not contact the service. Results may change as source data is updated.

```sh
vigievuln scan ./dubbo --proxy-cache https://api.vigievuln.fr --source-profile proxy \
  --retries 0 --licenses --report html,json --report-output ./sample-dubbo

vigievuln scan ./multi-cms-frameworks --offline \
  --proxy-cache https://api.vigievuln.fr --source-profile proxy --ecosystem composer \
  --licenses --exclude-path '**/tests/**' '**/test/**' '**/Tests/**' '**/Test/**' \
  -r html,json -o ./sample-cms
```

The source trees used for this regeneration were `/tmp/vigie-benchmark-20261102/dubbo` and `/tmp/vigievuln-samples-20261104/multi-cms-frameworks`. Only the four upstream source directories were copied into the CMS corpus; neighboring test feeds were not included. The CMS cached OSV catalogue was collected on 2026-11-03 and its NVD cache reports 2026-10-29; the report records the other source timestamps individually.

Copy each `cve-report.html` to its corresponding filename here. HTML opens locally without a server or network connection. Updated source trees, cache contents or tool versions can change the findings; this directory preserves the demonstration snapshot, not a reproducible archive of every upstream feed.

`SHA256SUMS` covers the two published HTML files.
