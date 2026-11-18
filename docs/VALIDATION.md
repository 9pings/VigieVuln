# Validate a CLI change

Run from the CLI repository with a supported Node.js version:

```bash
npm ci
npm test
npm run pack:release
npm pack --dry-run
```

The ordinary suite uses fixtures and fake providers. Optional integrations require
an explicit environment setting or the separate server checkout; skipped tests are
reported. See [contributing](../CONTRIBUTING.md) for targeted and live tests.

For report changes, render source-only, image-only and mixed inputs in HTML and
Word. Check counts, ownership, links, chart separation, narrow-screen layout and
browser errors. Compare JSON/SBOM identities and finding links with the inventories.

For matching changes, compare a pinned public application's inventory with its
native package manager before comparing findings with another scanner. Verify
selected positive and negative version boundaries against publisher evidence.
Record tool versions, source profiles, database dates and exact input revisions.

An offline test needs a prepared cache and a network-disabled environment. Verify
that absent data stays distinguishable from an unaffected verdict, and that strict
coverage gates retain actual retrieval failures. A successful cold-cache run alone
does not validate vulnerability coverage.

[Source benchmarks](BENCHMARK.md) · [Image benchmarks](BENCHMARK-IMAGES.md) ·
[Release procedure](RELEASING.md)
