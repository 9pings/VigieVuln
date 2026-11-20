# Releasing VigieVuln 1.3.2

From the CLI repository, with Node.js 22.13+, 23.4+ or 24+:

```bash
npm ci
npm test
npm run pack:release
npm pack --dry-run
```

Review `dist/vigievuln-1.3.2.tgz`, `dist/SHA256SUMS`, release notes and the staged Git diff. Check an installed-package offline scan. Record any live official-proxy check separately; it requires a test account or proxy key. The server is maintained separately in `../server-main`.

After approval, publish the archive with the intended npm account:

```bash
npm whoami
npm publish ./dist/vigievuln-1.3.2.tgz --access public
npm view vigievuln@1.3.2 version
```

The GitHub release workflow requires the exact `1.3.2` tag (no `v` prefix),
matching both package manifests. Create an annotated tag on the reviewed commit:

```bash
git tag -a 1.3.2 -m "VigieVuln 1.3.2" HEAD
```

If a version tag already exists, inspect its local and remote targets before
moving it; use an explicit expected old object when updating a remote tag.
Do not rewrite older version tags to a different package version.
Pushing the version tag triggers tests and publication of five platform binaries
and the npm archive to GitHub Releases. It does not publish to npm. A `main` push
that changes `docs/` or the Pages workflow triggers GitHub Pages deployment.
Verify the resulting workflow runs and tag target; a local tag alone does not
update the hosted site or publish release assets.
