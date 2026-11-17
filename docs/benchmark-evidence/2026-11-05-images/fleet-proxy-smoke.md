# Native image inventory: direct, fleet and offline replay

Date: 2026-11-05. These checks reuse the Traefik and nginx inventories and direct
reference reports in this directory's benchmark. They do not claim exhaustive
vulnerability recall; they compare the same captured inputs across transports.

A local `serve-cache` instance listened at `127.0.0.1:18657` with its own store
in `/tmp/vv-image-fleet-live/server`. The client used a distinct proxy-scoped
cache under `/tmp/vv-image-fleet-live/client`. Default image enrichment was
retained (KEV and EPSS; NVD not requested). A Node preload wrapped the client
fetch and rejected every origin except the local proxy; registry downloads were
not part of these inventory-rescan commands. The preload appended each
attempted origin to a separate log. The server itself was allowed to contact
upstream providers.

Commands (replace `<image>` with `traefik` and `nginx`):

```sh
node vigievuln.js serve-cache --port 18657 --host 127.0.0.1 \
  --cache-dir /tmp/vv-image-fleet-live/server --max-body-mb 512 --max-transfer-mb 1024
NODE_OPTIONS=--require=/tmp/vv-fleet-tripwire.js VV_NET_LOG=/tmp/vv-image-fleet-live/<image>-network.log \
  node vigievuln.js image /tmp/vv-image-benchmark-20261105/<image>/inventory.json \
  --inventory --proxy-cache http://127.0.0.1:18657 --allow-insecure-http \
  --source-profile proxy --cache-dir /tmp/vv-image-fleet-live/client \
  --report-output /tmp/vv-image-fleet-live/<image>-full
NODE_OPTIONS=--require=/tmp/vv-fleet-tripwire.js VV_NET_LOG=/tmp/vv-image-fleet-live/<image>-offline-network.log \
  node vigievuln.js image /tmp/vv-image-benchmark-20261105/<image>/inventory.json \
  --inventory --proxy-cache http://127.0.0.1:18657 --source-profile proxy \
  --cache-dir /tmp/vv-image-fleet-live/client --offline \
  --report-output /tmp/vv-image-fleet-live/<image>-full-offline
```

| Image | Components | Findings | Fleet requests | Offline requests | Direct = fleet = offline |
|---|---:|---:|---:|---:|---|
| Traefik | 327 | 214 | 87 | 0 | Yes |
| nginx | 907 | 80 | 2 | 0 | Yes |

Equality compares sorted finding tuples of advisory ID, dependency ecosystem,
name, version, severity, CVSS, EPSS, KEV and fix version, including duplicates.
All recorded online client requests went to the local proxy; the tripwire would
have rejected a direct request. Counts reflect this particular already-warm
server/client cache, and are not a cold-cache traffic benchmark. The nginx KEV
count was one in all three runs. The reports flag missing EPSS values for some
findings and advisories without CVE identifiers; each image also has one
unidentified native binary, and nginx has an incomplete JAR coordinate. Those
are coverage limits, not successful zero-finding assertions.

Tripwire content used for the run:

```js
const fs = require('node:fs'), original = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const target = new URL(String(input));
  fs.appendFileSync(process.env.VV_NET_LOG, target.origin + '\n');
  if (target.origin !== 'http://127.0.0.1:18657') throw Error('unexpected client network origin');
  return original(input, init);
};
```

A separate transfer check prepared the Traefik cache using the same local fleet
server, imported the archive into a distinct proxy-scoped `--cache-dir`, and
rescanned offline:

```sh
node vigievuln.js cache prepare /tmp/vv-image-benchmark-20261105/traefik/inventory.json \
  --output /tmp/vv-image-fleet-live/traefik-airgap.tar.gz \
  --proxy-cache http://127.0.0.1:18657 --allow-insecure-http \
  --source-profile proxy --cache-dir /tmp/vv-image-fleet-live/client
node vigievuln.js cache import /tmp/vv-image-fleet-live/traefik-airgap.tar.gz \
  --proxy-cache http://127.0.0.1:18657 --source-profile proxy \
  --cache-dir /tmp/vv-image-fleet-live/airgap
NODE_OPTIONS=--require=/tmp/vv-fleet-tripwire.js VV_NET_LOG=/tmp/vv-image-fleet-live/traefik-transfer-network.log \
  node vigievuln.js image /tmp/vv-image-benchmark-20261105/traefik/inventory.json \
  --inventory --offline --proxy-cache http://127.0.0.1:18657 --source-profile proxy \
  --cache-dir /tmp/vv-image-fleet-live/airgap --report-output /tmp/vv-image-fleet-live/traefik-transfer
```

The prepared archive was written with an explicit partial-coverage warning.
The imported-cache scan produced 327 components and 214 findings, with the
same sorted finding tuples as the online fleet scan and zero network attempts.
