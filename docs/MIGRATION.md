# Migration to VigieVuln 1.0.0

## Names and versions

- `fad-checker@2.7.4` becomes `vigievuln@1.0.0` (product: **VigieVuln**).
- `fad-service` becomes `vigievuln-server@1.0.0` (product: **VigieVuln-Server**).
- `1.0.0` starts a new package/version series; it is not a rollback of fad-checker.
- The retained `../../fad-checker` directory is retained as the legacy project, with
  transition release 2.7.5 and an explicit registry-deprecation procedure.

## CLI users

After publication, uninstall the old global package before installing the new one:

```bash
npm uninstall -g fad-checker
npm install -g vigievuln@1.0.0
vigievuln --version
```

Both packages install `fad` and `fad-checker` aliases; uninstalling the old package
first avoids competing global bin links. `vigievuln` is the primary command.
Existing scripts can keep using the aliases. A `fad-checker.js` wrapper is also
provided for integrations that invoke the JavaScript file directly.

The CLI migrates `~/.fad-checker/` and `~/.fad-checker-proxy-cache/` to
`~/.vigie-vuln/` and `~/.vigie-vuln-proxy-cache/` when the destination is absent.
Existing API keys, registry settings, warmed caches,
anonymized descriptors and offline transfer archives remain usable.

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
Human-facing titles/tool metadata identify VigieVuln 1.0.0. The `fad-findings/1`,
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

The CLI retains its original Git remote (`git@github.com:n8tz/fad-check.git`).
The previously selected public branded URL is `https://github.com/9pings/VigieVuln`;
renaming the remote repository is a separate operation. The server has its own Git
repository and no configured remote until its destination is chosen.
This local checkout retains predecessor Git history, but has no new release commit
or tag yet. Old historical tags are not reused: new releases use
`vigievuln-v1.0.0`, keeping the old `v1.0.0` lineage unambiguous.

If renaming the public repository, preserve GitHub's redirects and do not recreate
a repository at the old URL. GitHub Pages URLs require separate handling; the
included Pages workflow publishes this repository’s `docs/`. Keep the old Pages site/domain
redirecting to the new documentation location where possible.
