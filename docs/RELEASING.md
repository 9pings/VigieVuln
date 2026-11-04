# Releasing VigieVuln 1.2.0

From the CLI repository, with Node.js 22.13+, 23.4+ or 24+:

```bash
npm ci
npm test
npm run pack:release
npm pack --dry-run
```

Review `dist/vigievuln-1.2.0.tgz`, `dist/SHA256SUMS`, release notes and the clean Git diff. Check an installed-package offline scan and the official proxy with a test account or proxy key. The server is maintained separately in `../server-main`.

After approval, publish the archive with the intended npm account:

```bash
npm whoami
npm publish ./dist/vigievuln-1.2.0.tgz --access public
npm view vigievuln@1.2.0 version
```

The GitHub release workflow runs on the matching `1.2.0` tag, tests the CLI and publishes five platform binaries and the npm archive. It does not publish to npm. Pushing `main` also deploys `docs/` to GitHub Pages.
