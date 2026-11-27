# Releasing VigieVuln 1.3.5

From the CLI repository, with Node.js 22.13+, 23.4+ or 24+:

```bash
npm ci
npm test
npm run pack:release
npm pack --dry-run
```

Review `dist/vigievuln-1.3.5.tgz`, `dist/SHA256SUMS`, release notes and the staged Git diff. Check an installed-package offline scan. Record any live official-proxy check separately; it requires a test account or proxy key. The server is maintained separately in `../server-main`.

After approval, publish the archive with the intended npm account:

```bash
npm whoami
npm publish ./dist/vigievuln-1.3.5.tgz --access public
npm view vigievuln@1.3.5 version
```

The GitHub release workflow requires the exact `1.3.5` tag (no `v` prefix),
matching both package manifests. Create an annotated tag on the reviewed commit:

```bash
git tag -a 1.3.5 -m "VigieVuln 1.3.5" HEAD
```

If a version tag already exists, inspect its local and remote targets before
moving it; use an explicit expected old object when updating a remote tag.
Do not rewrite older version tags to a different package version.
Pushing the version tag triggers tests and publication of six platform archives
and the npm archive to GitHub Releases. It does not publish to npm. A `main` push
that changes `docs/` or the Pages workflow triggers GitHub Pages deployment.
Verify the resulting workflow runs and tag target; a local tag alone does not
update the hosted site or publish release assets.

### Linux x86_64 with musl

Run `npm run build:linux:musl` with Bun, Node and Docker on the build machine.
It writes `dist/vigievuln-linux-x64-musl-v<VERSION>.tar.gz` after running
`collect /` in an unmodified Alpine 3.20 x86_64 container with networking
disabled and a read-only root. The check reads the snapshot with the native
inventory reader and verifies Alpine package and PHP/JS lockfile evidence.
Building the archive needs network access to obtain the toolchain dependencies.

Extract the complete archive at the destination. Its `vigievuln` executable
uses the Alpine musl loader and resolves the supplied GCC runtime libraries
from the adjacent `lib/` directory. Keep the included `licenses/` files with
the bundle. The collector requires no Node installation or package installation
on the audited machine. The release workflow includes the archive in `SHA256SUMS`.
