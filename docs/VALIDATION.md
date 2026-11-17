# Release validation — 1.3.0 · 17 November 2026

| Check | Result |
| --- | --- |
| Local Linux suite, Node 24 | 2,415 passed, 13 skipped, zero failures |
| Isolated Docker suite, no network or sibling server | 2,410 passed, 18 skipped, zero failures |
| GitHub CI | Linux Node 22/24 and Windows Node 22 passed |
| External applications | Four fixed releases compared with native Maven, Gradle and Python inventories; see [benchmark](BENCHMARK.md) |
| Reports | HTML rendered without JavaScript errors or horizontal overflow; checked CycloneDX exports had no duplicate/orphan references or missing finding links |
| Packaging | Installed npm archive and offline CLI smoke checks passed; release build and Pages deployment passed |

Skip counts depend on platform and available integration targets. A successful
cold-cache smoke scan checks execution, not vulnerability coverage.

For measured inventory limits and advisory comparisons, see the
[benchmark](BENCHMARK.md) and [evidence](benchmark-evidence/2026-11-17/README.md).
Reproduction: [release checks](RELEASING.md).
