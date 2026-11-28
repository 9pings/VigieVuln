# Contributing

Thanks for looking. This is a young single-maintainer project, so the most valuable
contribution isn't necessarily code — it's **telling me where the output is wrong**.

## The most useful thing you can do

Run it on a real project and report what it got wrong:

```bash
npx vigievuln scan ./your-project
```

A [false positive / false negative report](https://github.com/9pings/VigieVuln/issues/new?template=false_positive.yml)
with the coordinate and the manifest snippet that produced it is worth more than a feature
request. Dependency resolution has a long tail of real-world shapes — inherited BOMs, profile
matrices, `replace` directives, vendored jars — and the only way to cover them is to be shown
one that breaks.

## Development setup

Use Node.js `^22.13.0`, `^23.4.0` or `>=24.0.0`, as declared in
`package.json`; SQLite support is required. This repository contains the CLI;
the server has its own repository.

```bash
npm ci
npm test
node --test test/core.test.js # a single file
node vigievuln.js scan test/fixtures/monorepo-mixed --offline --no-report
```

Building the single-file binaries needs [bun](https://bun.sh): `npm run build`.

The ordinary suite is offline and deterministic. `test/real-instances.test.js` is
opt-in: it clones the representative GitHub repository of each supported
CMS/framework at a tag known to be vulnerable (WordPress 6.4.2, drupal/drupal
8.5.0, symfony/symfony-demo v2.6.0, BookStack v24.10), scans the real trees and
asserts the end-to-end behavior against the real published advisories. It needs
network and git, so it stays skipped unless you ask for it:

```bash
FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js
```

Hosted-server integration tests require the separate sibling `../server-main`
checkout and its installed dependencies. A standalone CLI checkout skips those
tests explicitly; when the server is present, failures are not suppressed.
The skipped-test count therefore depends on the available integration targets.

## Ground rules for changes

- **Tests must not touch the network.** Every fixture-driven test drives an in-memory
  registry/fetcher. `test/offline-guarantee.test.js` is a tripwire that fails if any code path
  reaches for the network under `--offline` — don't work around it.
- **Add a fixture, not just an assertion.** New parsing behaviour belongs in
  `test/fixtures/`, next to the shapes that already live there.
- **A parse failure must never kill the run.** One malformed manifest logs a warning and the
  scan continues; there is no `process.exit(1)` mid-pipeline.
- **New ecosystem = new codec.** Implement the interface in
  `lib/codecs/codec.interface.js`, register it, and the orchestrator needs no edits. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- **Put code where it belongs.** [`lib/README.md`](lib/README.md) describes the layout: only
  command entry points and configuration live at the root of `lib/`; a new data source gets
  its folder under `lib/providers/<name>/`, other modules go in the folder of their theme.
- Commit messages follow Conventional Commits (`fix(maven): …`, `feat(gradle): …`).
- [`CLAUDE.md`](CLAUDE.md) is the code-level orientation map — conventions, invariants and the
  reasoning behind the non-obvious ones. Read it before a non-trivial change; it will save you
  from "simplifying" something that's load-bearing.

## On AI-assisted development

This codebase is written with heavy use of Claude Code, and I'm not going to pretend
otherwise — `CLAUDE.md` in the repo root is exactly what it looks like. What I ask of my own
changes and of contributions is the same either way: a test that fails before and passes
after, a fixture derived from a real-world shape, and no claim in the docs that isn't backed
by something you can run. If you find a place where the code doesn't meet that bar, that's a
bug report I want.

## Reporting a vulnerability in vigievuln itself

See [`SECURITY.md`](SECURITY.md) — please report privately, not as a public issue.
