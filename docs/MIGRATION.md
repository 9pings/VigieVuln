# Migration from fad-checker to VigieVuln

Current CLI version: **1.3.0**. The package rename below began with 1.0.0;
cache handling changed again in 1.2.0. Use [USAGE.md](USAGE.md) for current
commands and [RELEASING.md](RELEASING.md) for the current tag convention.

## Names and versions

- `fad-checker@2.7.4` becomes `vigievuln@1.0.0` (product: **VigieVuln**).
- `fad-service` becomes `vigievuln-server@1.0.0` (product: **VigieVuln-Server**).
- `1.0.0` starts a new package/version series; it is not a rollback of fad-checker.
- The sibling `../fad-checker` directory was retained as the legacy project, with
  transition release 2.7.5 and an explicit registry-deprecation procedure.

## CLI users

When installing from npm, uninstall the old global package before installing a
published VigieVuln version:

```bash
npm uninstall -g fad-checker
npm install -g vigievuln
vigievuln --version
```

Both packages install `fad` and `fad-checker` aliases; uninstalling the old package
first avoids competing global bin links. `vigievuln` is the primary command.
Existing scripts can keep using the aliases. A `fad-checker.js` wrapper is also
provided for integrations that invoke the JavaScript file directly.

Since 1.2.0, the active caches are SQLite under `~/.vigie-vuln/` and
`~/.vigie-vuln-proxy-cache/`. Pre-1.2 filesystem caches are not migrated as
advisory data; startup removes legacy cache data while preserving supported
configuration and account sessions. Regenerate caches and export new SQLite
archives. Older filesystem cache archives are not accepted.

New configuration names:

| Preferred | Accepted legacy name |
| --- | --- |
| `.vigievuln-env.json` | `.fad-env.json` |
| `VIGIEVULN_ENV` | `FAD_CHECKER_ENV` |
| `VIGIEVULN_PROXY_CACHE_TOKEN` | `FAD_PROXY_CACHE_TOKEN` |

The preferred environment name wins when both are set; explicit CLI flags still win.
Repository configuration files are never loaded automatically: pass `--config`
explicitly only for files you trust.
The default report directory becomes `vigievuln-report`; use `-o` for a fixed path.
Human-facing titles/tool metadata identify the running VigieVuln version. The `fad-findings/1`,
`fad-deps/1`, `fad-diff/1`, `fad-dump/1` schemas, source IDs, SARIF rule IDs and HTTP
headers keep their existing identifiers so consumers and audit baselines remain
compatible. Integrations matching the old tool-name string must accept `VigieVuln`.

## Server operators

The executable is `bin/vigievuln-server.js` in the separate server repository (or installed `vigievuln-server`).
The server lives beside `cli/` and retains its dependency on the `vigievuln`
npm package. Run `npm ci` inside `server/`. Before publication, `file:../cli`
and `install-links=true` install the sibling CLI as a normal package, including
its modules and datasets. No root npm workspace is needed. After CLI changes,
run the server's `npm ci` again to refresh the installed copy.

`VIGIEVULN_SERVER_*` variables take precedence over `VIGIEVULN_*`, then
`FAD_SERVICE_*`. The deployed templates use the new namespace. Database schemas,
tokens, client protocol, metrics names and signed dump format remain compatible.

Keep existing database paths explicit when updating a deployment: the new default
filename is `vigievuln-server.db`. The default Compose project is
`vigievuln-server`; retain an existing project name with `-p` to reuse its volumes.
No running deployment or data file is modified by preparing this source tree.
Detailed steps are in `docs/OPERATIONS.md` in the server repository.

## Repository and documentation links

The public CLI repository is `https://github.com/9pings/VigieVuln`.
Some checkouts retain the old redirected remote `git@github.com:n8tz/fad-check.git`.
The server has its own repository and release lifecycle. Current CLI releases
use a tag matching `package.json` exactly, for example `1.3.0`; the old
`vigievuln-v1.0.0` tag is historical and is not the current workflow convention.

If renaming the public repository, preserve GitHub's redirects and do not recreate
a repository at the old URL. GitHub Pages URLs require separate handling; the
included Pages workflow publishes this repository’s `docs/`. Keep the old Pages site/domain
redirecting to the new documentation location where possible.
