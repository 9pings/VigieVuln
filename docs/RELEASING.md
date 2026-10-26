# Release VigieVuln 1.0.1

This is the CLI Git repository. Its source, package.json, workflows and docs are
at the repository root. The separate server repository lives locally at
`../server`; the parent directory contains only these two repositories.

## Validate and pack

Run from this CLI checkout:

```bash
npm ci
npm test
npm run pack:release
```

Packaging creates `dist/vigievuln-1.0.1.tgz` and `dist/SHA256SUMS`. Plain `npm pack`
is also available. For the installed-package and server interoperability smoke:

```bash
cd ../server
npm ci
npm test
npm run smoke:packages
```

The server keeps its npm dependency on `vigievuln`, using `file:../cli` until
publication. After publishing, its manifest/lock can be switched together using
`npm install --save-exact vigievuln@1.0.1` from the server repository.

## Publish the CLI

After reviewing the archive, using the intended publisher account:

```bash
npm whoami
npm publish ./dist/vigievuln-1.0.1.tgz --access public
npm view vigievuln@1.0.1 name version
```

The server is deployed from its own repository, using source or Docker.

## Legacy transition

The retained legacy project is locally at `../../fad-checker`. Its
`DEPRECATION.md` describes the prepared fad-checker 2.7.5 transition. Only after
the new CLI is installable from npm:

```bash
cd ../../fad-checker
npm run publish:migration             # preview
npm run publish:migration -- --publish # explicit publication and deprecation
```

The helper checks that the new CLI exists first. The local deprecated field alone
does not update registry metadata. Do not unpublish historical versions.

## Git and binaries

The full predecessor history and branches are retained. `origin` is the original
fad-checker checkout's remote: `git@github.com:n8tz/fad-check.git`. Review and
commit the rename before pushing; no force push or history rewrite is required.
The public branded URL prepared earlier remains `https://github.com/9pings/VigieVuln`;
if the upstream repository is renamed, update origin deliberately afterward.

Pushing a version tag such as `1.0.1` runs the release workflow, tests the CLI,
builds the five platform binaries and publishes a GitHub release with the binaries
and npm archive. The tag must match `package.json`. A manual run must also select
that version tag. The workflow does not publish to npm.

```bash
npm run build
```

The Pages workflow serves `docs/` from this repository. No publication,
deprecation, push or production deployment is performed by preparation.
