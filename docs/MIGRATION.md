# Upgrade and compatibility

Install the current CLI and verify its version:

```bash
npm install -g vigievuln
vigievuln --version
```

If `fad-checker` is installed globally, uninstall it first to avoid conflicting
command aliases. VigieVuln provides `vigievuln`, `fad` and `fad-checker`; use
`vigievuln` in new scripts. `--verbose` enables logging; `-v` prints the version.

## Configuration and caches

The CLI stores configuration and SQLite caches under `~/.vigie-vuln/`; the shared
cache server uses `~/.vigie-vuln-proxy-cache/`. Filesystem-format cache archives
are not supported. Prepare and export a fresh cache before an offline upgrade;
see [cache preparation](USAGE.md#offline--cache-control).

| Preferred setting | Accepted alias |
| --- | --- |
| `.vigievuln-env.json` | `.fad-env.json` |
| `VIGIEVULN_ENV` | `FAD_CHECKER_ENV` |
| `VIGIEVULN_PROXY_CACHE_TOKEN` | `FAD_PROXY_CACHE_TOKEN` |

Preferred environment variables take precedence over aliases; explicit CLI flags
take precedence over configuration. Repository configuration is loaded only when
selected with `--config`. Use `-o` to fix the output directory; the default is
`vigievuln-report`.

## Integrations

Reports identify the tool as `VigieVuln`. Machine schemas retain identifiers such
as `fad-findings/1`, `fad-deps/1` and `fad-diff/1`; do not rename those identifiers
in existing integrations. The `fad-checker.js` wrapper remains available.

The server is maintained and deployed separately. Refer to its operations guide
for server updates. CLI packaging and version tags are documented in
[RELEASING.md](RELEASING.md).
