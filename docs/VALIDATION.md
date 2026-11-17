# Release validation — 2026-11-17

VigieVuln 1.3.0 was checked locally on Linux with Node.js 24.22.2. The
containerised application checks used Node.js 24.22.3, Java 21 and Python 3.11.

| Check | Observed result |
| --- | --- |
| Complete CLI suite | 2,428 tests: 2,415 passed, 13 intentionally skipped, zero failures |
| Four external applications | OpenRefine 3.9.0, Traccar 6.6, Paperless-ngx 2.14.7 and NetBox 4.2.3 cloned and scanned in Docker at fixed commits |
| Native inventories | Compared against Maven dependency trees, Gradle classpaths, Python lockfile entries and a pip dry-run report |
| Same-inventory Python comparison | On 99 frozen packages, all pip-audit 2.10.1 observations were present in VigieVuln: 102 explicit-alias groups with OSV, 101 with PyPI |
| CycloneDX | Corrected multi-version Maven/npm/PyPI exports; no orphan/duplicate component refs or missing finding-to-component links in the four checked final exports |
| HTML | Headless Chrome rendering and expand controls checked; no JavaScript exception or horizontal document overflow observed |
| Report integrity | SHA-256 manifests verified for the four final reports |
| npm package | `vigievuln-1.3.0.tgz`, 282 files; installed outside the checkout and ran `--version` plus a cold-cache offline scan successfully |

These checks exposed limitations that remain: Python manifests without a
complete lock do not resolve transitives, unlocked Gradle POM expansion can
select versions different from Gradle, combined lock configurations do not
prove runtime scope, and an OpenRefine local-reactor path was not fully followed.
Some runs also had EUVD failures or incomplete advisory coverage. Passing tests
does not establish universal recall, precision or exploitability.

See [the dated benchmark](BENCHMARK.md) and
[structured verification evidence](benchmark-evidence/2026-11-17/verification-summary.json).
The installed-package smoke scan correctly reported absent cold-cache data;
its success is a packaging/execution check, not a clean vulnerability verdict.
GitHub workflow results are separate from these local checks. The historical
server checks below do not validate the current server or a production deployment.

The first 1.3.0 CI attempt exposed two hosted-server tests that assumed a sibling
`server-main` checkout. They now follow the existing integration-test convention:
run against the real server when present, otherwise report an explicit skip.
Standalone CLI and full local-workspace test counts can therefore differ.
The Windows run also exposed SQLite connections left open by test cleanup and
a POSIX-only path comparison in the WAL-injection fixture. These test harnesses
now close databases before removal and use platform-aware path components.
Hosted CLI fixtures write their reports inside their temporary directory.

## Historical preparation — 2026-10-25

The following is the original 1.0.0 preparation record, not the current release
status. It was validated locally on Linux/WSL with Node.js 24.14.0, with separate
repositories in `cli/` and `server/`. Each had its own lockfile, with the server depending on
`vigievuln` via npm (`file:../cli`, installed without a symlink).

| Check | Result |
| --- | --- |
| CLI suite | 1,354 tests: 1,347 passed, 7 intentionally skipped, 0 failed |
| Server suite | 82 passed, including signed-dump interoperability; SQLite and PostgreSQL exercised |
| Fresh server installation | `npm ci` succeeded with its own lockfile and installed VigieVuln dependency |
| CLI npm archive | `dist/vigievuln-1.0.0.tgz` prepared with SHA256SUMS |
| Installation outside checkout | CLI archive installed, sibling server installed/tested, datasets and HTTP health/public page checked |
| Docker | Image rebuilt with both sibling directories; HTTP health/version and public page verified |
| Compose | SQLite and PostgreSQL configurations validated |
| GitHub workflows | YAML parsed; separate CLI/server jobs, integration, manual draft CLI release and Pages configured |

Earlier preparation also validated the retained fad-checker transition suite
(1,435 tests: 1,428 passed, 7 skipped), packed fad-checker 2.7.5 and compiled CLI
binaries for Linux x64, Windows x64 and macOS x64. The Linux binary was executed;
Windows/macOS binaries were cross-compiled without native execution.

The CLI retains the full predecessor history and original remote. The server
has a separate Git repository containing its extracted fad-service history.
The server's former coupled npm archive has been removed from the prepared release.
The server is prepared for source/Docker deployment. GitHub Actions has not run
remotely. Opt-in live-data tests remain skipped. Nothing has been published,
deprecated on npm, pushed, tagged or deployed to production.

Reproduction commands are in [RELEASING.md](RELEASING.md).
