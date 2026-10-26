# Release preparation validation — 2026-10-25

Validated locally on Linux/WSL with Node.js 24.14.0. Final layout: two separate Git repositories in `cli/` and `server/`. Nothing
else exists in their parent directory. Each has its own lockfile, with the server depending on
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
