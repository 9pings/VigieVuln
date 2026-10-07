# fad-service — operations

How to run fad-service in production: install, configure, brand, observe, back up, upgrade,
scale. Design and data model: `docs/SPEC-fad-service.md` at the repository root.

## Components

| Process | Command | Role |
|---|---|---|
| web | `fad-service serve` | Public site, JSON API, `/v1/resource` for fad clients. Stateless; `--workers N` per host. |
| worker | `fad-service worker` | Ingestion jobs (mirrors). Leased: several workers never run one job twice. |
| backup | `fad-service backup` | Online, consistent copy of the database (`VACUUM INTO`). |

All three share one database: a SQLite file (one host) or PostgreSQL (`--db postgres://…` /
`FAD_SERVICE_DB`, any number of hosts). The choice is made at start-up; the same code, tests and
dumps work on both.

Requirements: Node ≥ 22.13 (24 recommended; `node:sqlite` still prints an "experimental"
warning on 24 — the image sets `NODE_NO_WARNINGS=1`), `xz` (xz-utils, for the NVD mirror), ~10 GB of
disk for the database with every mirror, outbound HTTPS to the sources listed on `/sources`.

## Install — Docker

```bash
cd packages/fad-service/deploy/docker
cp .env.example .env              # domain + secrets, never committed
$EDITOR config.json               # brand, analytics, workers
docker compose up -d --build      # Caddy (TLS) → web → SQLite volume, + worker + nightly backup
docker compose up -d --scale web=4
docker compose exec web node /app/packages/fad-service/bin/fad-service.js token add --role client --label team-a
```

The image is built from the repository root (`docker build -f packages/fad-service/Dockerfile .`),
runs as a non-root user, read-only root filesystem, all capabilities dropped, `tini` as PID 1
so `docker stop` drains. Container logs are rotated by Docker (`json-file`, 10 × 50 MB).

## Install — systemd

```bash
git clone https://github.com/9pings/fad-checker /opt/fad-service
cd /opt/fad-service/packages/fad-service && npm install --omit=dev
useradd --system --home /var/lib/fad-service fad-service
install -d -m 0750 /etc/fad-service
install -m 0640 deploy/config.example.json /etc/fad-service/config.json   # then edit it
install -m 0600 /dev/null /etc/fad-service/env                             # secrets, see below
cp deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now fad-service fad-service-worker fad-service-backup.timer
```

The units are hardened (`ProtectSystem=strict`, no capabilities, private /tmp, restricted
address families); state in `/var/lib/fad-service`, logs in `/var/log/fad-service`.
Put Caddy or nginx in front (`deploy/docker/Caddyfile` works as is with `reverse_proxy
127.0.0.1:8322`) and set `"trustProxy": true`.

## Configuration

`--config /etc/fad-service/config.json` (or `FAD_SERVICE_CONFIG`); flags override the file;
`fad-service config --config …` prints the effective configuration. Full example:
`deploy/config.example.json`. Relative paths in the file are relative to the file.

**Secrets never go in the file** (the loader refuses a `key`/`token`/`password` field):

| Variable | Used for |
|---|---|
| `FAD_SERVICE_GITHUB_TOKEN` | GitHub API (cvelistV5 and fkie release lookups) — avoids the 60 req/h anonymous limit |
| `FAD_SERVICE_NVD_KEY` | NVD API for `/v1/resource` clients (the mirror job needs none) |
| `FAD_SERVICE_WORDFENCE_KEY` | Wordfence lane for `/v1/resource` clients |
| `FAD_SERVICE_METRICS_TOKEN` | Bearer token required on `/metrics` — **mandatory** when `metrics.listen` is not loopback (the service refuses to start without it; the compose file listens on the docker network, so set it in `.env`) |

## Branding

```json
"brand": {
  "name": "…", "tagline": "…", "baseUrl": "https://vuln.example.fr",
  "logo": "/etc/fad-service/logo.svg", "accent": "#1f4fd1", "footer": "…", "contact": "mailto:…",
  "publisher": { "name": "…", "address": "…", "director": "…", "contact": "…" },
  "host":      { "name": "…", "address": "…", "contact": "…" }
}
```

`publisher` and `host` fill the legal notice — in France the publisher, the publication
director and the host must be identified (LCEN art. 6). The logo is served from
`/static/logo` (an SVG is sandboxed, it cannot run script); the accent colour from
`/static/brand.css`. `baseUrl` adds canonical links.

## Logs

- `log.file: null` → stdout (systemd journal, Docker). Otherwise the file is rotated by size
  (`maxSize`, `keep` files) by the service itself; under `--workers N` only the primary
  process writes it. SIGHUP (`systemctl reload fad-service`) reopens it, for logrotate users
  (`deploy/logrotate/fad-service`).
- `log.format`: `text` or `json` (one object per line, for Loki / ELK / Datadog).
- An access line: method, route **family**, status, latency, request id (`x-request-id`,
  echoed or generated) and a salted tag of the client token. Never the requested
  coordinates, never which CVE a visitor read, never an IP. Healthy `/health` and `/ready`
  probes are logged at debug level only.

## Metrics, health, analytics

- `/health` — liveness; **503 while draining**, so the load balancer stops routing first.
- `/ready` — readiness: the database answers and CVE data is loaded (503 on a fresh install
  until the first `cvelist` run).
- `/metrics` — Prometheus, on its own listener (`metrics.listen`, default `127.0.0.1:9464`),
  never on the public port; summed over all workers of the host. Off loopback a token is
  required. The asset counters are memoised for 60 s, shared with `/` and `/ready`: a scrape
  never scans the table. Key series:
  `fad_http_requests_total{route,status}`, `fad_resource_cache_total{result}`,
  `fad_job_last_success_timestamp_seconds{job}`, `fad_job_last_failed{job}`, `fad_assets{type}`.
  Alert when `time() - fad_job_last_success_timestamp_seconds{job="cvelist"} > 7200`, or
  `fad_job_last_failed == 1` for more than one period.
- `analytics.provider`:
  - `server` (default) — daily aggregate counters in the database (views per route family,
    searches, most-read CVE/advisory pages). No IP, no cookie, no search text: nothing
    personal, no consent banner. `GET /admin/analytics?days=30` (admin token).
  - `plausible` / `matomo` — set `scriptSrc` (https, self-hosted or EU instance); the CSP opens
    to that origin only. Matomo runs cookieless. Check your consent obligations.
  - `none`.

## Jobs

| Job | Period | Source | First run |
|---|---|---|---|
| `cvelist` | 1 h | CVEProject cvelistV5 (daily baseline + hourly delta) | ~2–3 min, 620 MB streamed |
| `nvd` | 6 h | fkie-cad NVD mirror, years whose sha256 changed | ~1–2 min |
| `osv` | 1 h | OSV.dev all.zip, then modified records only | ~1 min |
| `kev`, `epss`, `euvd` | 24 h | CISA KEV, FIRST EPSS, ENISA EUVD | seconds |
| `certfr` | 1 h | CERT-FR advisories (incremental) | ~1 min |
| `maintenance` | 24 h | FTS optimize, planner stats, WAL truncate, resource-cache budget | seconds |

`fad-service worker --once --jobs kev,epss` runs a pass by hand. A failed job keeps its last
good data (an empty feed never wipes a table) and is retried at the next pass. On SIGTERM
the worker releases its leases so another one can take over. Measured on a full cold import:
~5.5 min for every source, < 500 MB of memory; the database is ~4 GB.

## Package metadata (registries)

When a fad client asks for package metadata through `/v1/resource`, the answer is kept as a
**projection**: the registry's JSON shape, only the fields fad reads plus what a package page
shows (npm: versions, dist-tags, times, licences, deprecations, dependencies — no readme, no
tarball URL). fad finds exactly the same things in it as in the raw answer (tested against
fad's own extractors). Maven keeps `maven-metadata.xml` and POMs; no binary is ever stored.

Maven Central requests go to the official EU mirror (`upstream.mavenMirrors`, Google's
`maven-central-eu` bucket listed by Maven itself) and fall back to Central.

**Publication rule.** A package gets a public page and enters the search only when
`registry.publishThreshold` distinct clients (default 5) asked for it, or when an admin seeds
it. Until then it is served to clients but invisible. Who asked is a truncated keyed hash of
the token, deleted the moment the package is published. A name the registry answers 404 for
(a private package) is never written anywhere.

```bash
fad-service seed --ecosystem npm --popular             # fad's curated list
fad-service seed --ecosystem maven --list maven.txt    # one g:a per line (POM of the latest too)
fad-service seed --ecosystem pypi --list top-pypi.txt --concurrency 4
```

`seed` authenticates to its in-process server with an admin token held in memory only:
nothing is written to the token table, so a seed killed midway leaves no live admin token
(it also revokes any `seed (temporary)` token an earlier version left behind).

Package pages (`/pkg/<npm|pypi|maven|gem|composer|nuget|golang>/<name>`) list the advisories
naming the package and, per version, whether it is affected — **only where the ordering is
exact** (Maven ComparableVersion, SemVer 2.0 for npm and Go, or the advisory's explicit version
list); elsewhere the range is shown and the verdict is "?". Each version links to its own page
(`/pkg/<eco>/<name>?version=<v>`, only for a version the registry listed): the advisories that
affect it with their CVEs, CVSS, KEV and EPSS, the fix of each affected branch (or "≤ x, no
fix" for a branch left without one), and the **closest newer version no advisory affects**.
Both pages carry a **versions panel** on the right (below the content on a narrow screen):
every version with how many advisories affect it — rendered in the page, not an iframe (the
site forbids framing, `frame-ancestors 'none'`), memoised per package. Withdrawn advisories (OSV `withdrawn`) are
listed apart and never give a verdict.

**Freshness** — every page's footer gives the time of the newest successful import, the home
page one line per source, each list page the time of its own sources (EPSS for the most
exploited, KEV for KEV…); read from the job runs, memoised a minute.

**CVE lists** — on the home page (10 each: libraries, most exploited, KEV) and at `/cves?list=critical|libraries|exploited|kev`
(100): the latest CVEs whose headline CVSS — the CNA's or NVD's (newest CVSS version, NVD
Primary first) — is 9.0 or more; the **libraries** most recently hit by one — one row per library: its affected versions,
severity, CWE (or the CVE title), fixed versions and how many critical CVEs it has; the highest EPSS probabilities; the
latest CISA KEV additions. Each CVE row names what is vulnerable: the libraries an OSV/GHSA
advisory ties to it with their affected versions, else the CNA's own products and versions
from the CVE record ("fixed in …" when the CNA lists only fixed versions).

**Links.** Every library name links to its package page — when the registry was never asked
for it, the page is built from the public advisories that name it (no registry data, no
upstream request). Every CNA product links to `/product/<vendor>/<product>` (the CVEs that
name it, newest first, with the versions each CVE gives; `cve_product` table, kept in step
with the CVE records). A fixed version links to its version page when the registry listed it. They
read the `cve_rank` table, kept in step by every CVE / NVD write (jobs and dump restores) and
filled once from the existing data when an older database is opened (402 586 CVEs: 15 s).
Computed at startup, then memoised 10 minutes.

## Dumps (seed another instance, a relay, an air-gapped site)

A dump is `<id>.manifest.json` (signed: contents, freshness of every source, sha256 of the
payload), `<id>.manifest.sig` (Ed25519), `<id>.jsonl.gz` (the data, one JSON object per
line) and, for public builds, `<id>.torrent`.

| Kind | Contains | Who gets it |
|---|---|---|
| `public` | published CVEs, advisories, signals (KEV/EPSS/EUVD/CERT-FR), NVD, links | anyone — listed on `/dumps`, HTTPS + torrent |
| `private` | public + published package pages + the `/v1/resource` cache a relay needs (never an unpublished package, never an entry fetched with a client's credentials) | client tokens — `/dumps/private/…` |
| `full` | everything | your own instances and backups — never served |

```bash
fad-service keygen --out /etc/fad-service/keys            # once; set dumps.signingKeyFile, publish the .pub.pem
fad-service dump --kind public                             # into <dumps.dir>/public, newest dumps.keep kept
fad-service dump --kind private --since 2026-10-01         # a delta
fad-service verify  fad-public-….manifest.json --trust-key dump-signing.pub.pem
fad-service restore fad-public-….manifest.json --trust-key dump-signing.pub.pem   # merge, fresher wins, replay-safe
fad-checker serve-cache --seed fad-private-….manifest.json --trust-key dump-signing.pub.pem [--seed-only]
```

`"dumps": { "daily": true }` makes the worker build and prune a public dump every day. With
`brand.baseUrl` set, each public build gets a `.torrent` and a magnet link whose web seed is
the HTTPS file (`/dumps/files/…` supports Range), so it downloads with no peer online;
`dumps.trackers` adds announce URLs. Registry projections stay out of public builds
(`dumps.publicIncludesPackages` to change it once their terms are cleared). Large files can
also be served by the reverse proxy straight from `<dumps.dir>/public`.

## Backups and restore

`fad-service backup --dir /var/lib/fad-service/backups --keep 7` (the systemd timer and the
compose `backup` service do it nightly) writes a consistent copy while the service runs.
Backups are created `0600` (they hold token hashes, the log/demand salts and the resource
cache). Copy the directory off-host. To restore: stop web and worker, replace the database file with
a backup, remove the `-wal`/`-shm` files next to it, start again. Mirrors can always be
rebuilt from the sources; tokens and analytics cannot — that is what the backup protects.

## Upgrades

Pull the new version, `npm install --omit=dev` (or rebuild the image), restart worker then
web. Schema changes are applied in place on start (new tables/columns only). Roll back by
restoring the previous code and the last backup.

## Scaling and PostgreSQL

One host: `workers` in the config (or `--workers N`), and more web containers, on SQLite.
Several hosts: PostgreSQL —

```bash
export FAD_SERVICE_DB=postgres://fad:…@db.internal:5432/fad     # environment only: it holds a password
fad-service serve --workers 4                                     # on every web host
fad-service worker                                                # anywhere, as many as you like: jobs are leased
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d   # the same with Docker
```

The schema is created on first start (idempotent); a SQLite instance moves to PostgreSQL
with a `full` dump restored into it. Search uses a `tsvector` column with a GIN index. Every
instance shares the cache, the publication rule and the leases; rate limits, the negative
cache and the upstream budgets stay per process (divide `upstream.budgets` accordingly).
A load balancer (Caddy, nginx, HAProxy, the provider's) uses `/health`; clients also spread
themselves by region through health-based instance selection. Back up with `pg_dump`
(`fad-service backup` is for SQLite).

## Protecting the upstreams (never get banned)

A public instance must not let its clients get it banned by NVD, OSV, GitHub or a registry:

- **Answers from the mirrors.** An NVD request for a CVE the fkie mirror holds is answered
  from the database, in NVD API 2.0 shape (`x-fad-proxy: mirror`); so are EPSS requests when
  every CVE is known. No upstream request.
- **Per-source budgets** (`upstream.budgets`, per process): below each source's limit — NVD
  40/30 s with a key, 4/30 s without (80 % of NVD's own limits), npm/Maven 20/s, PyPI 10/s… Past
  the budget: the stale copy if there is one, else `503` + `Retry-After`; the source is not
  called.
- **Per-client budget** (`upstream.clientPerHour`, default 1200): the upstream requests one
  token may cause per hour. Cache hits and mirror answers are free; a client sending
  thousands of unseen identifiers runs out alone.
- **Negative cache**: a definitive 404/410 is remembered 6 h — in memory only, keyed by a
  hash (the names that 404 are a client's private packages: never on disk, never in a dump).
- Maven Central traffic goes to the EU mirror first.

## Input validation

Every input is typed against a whitelist (fad-checker's `lib/resource-cache/validate.js`,
which `fad-checker serve-cache` applies too) and refused with a `400` (or
`415`) before any lookup: the `/v1/resource` and `/admin/purge` documents (one schema per
provider/type — exactly what fad-checker sends; unknown fields, headers or types refused), the
query string of every route (unknown or repeated parameters refused), path parameters
(identifier patterns). Search text: at most 200 characters, no control character, words of
letters and digits (joined only by `. _ - : / @`), 8 words of 2–64 characters, prefix
matching from 3 characters — `%`, `*`, quotes and operators never reach the database.

## Capacity and protection

- **Workers = cores** on a public instance (`"workers": true` uses every core). SQLite reads are
  synchronous: one slow request blocks its process, so concurrency comes from processes.
- `maxInFlight` (default 256 per process): past it, requests get `503` + `Retry-After` instead
  of queueing — the guard a per-IP limit cannot give against a distributed flood. `/health`
  and `/ready` are exempt. `maxConnections` (2048) caps sockets per process.
- Public rate limit per address (`rateLimit.public`, per minute), IPv6 counted per /64; the
  table evicts its oldest entries, a flood of new addresses cannot reset the others.
- Memory is bounded on the hot path: a cached body is loaded only while it is streamed, and
  bodies being served share a 256 MB budget per process (readers past it wait); spool files
  of answers being fetched share a 2 GB quota (past it the fetch is refused, retry later);
  registry projections (which parse the whole answer) run two at a time; demand bookkeeping
  skips the database for a (package, client) already recorded and for published packages;
  analytics counters flush early past 10 000 keys. The compose file sets `mem_limit`
  (`FAD_WEB_MEM`, default 1536m; `FAD_WORKER_MEM`, default 2g).
- Registry projections bound every string, list and map they keep (licence, versions,
  dependency names, URLs…): a hostile registry answer cannot inflate a row, the search index
  or a page.
- The `/v1/resource` cache: bodies above 64 MB are streamed once and not kept (the 620 MB
  cvelistV5 archive); the `maintenance` job drops entries stale for 30 days and keeps the
  cache under `jobs.resourceCacheMaxBytes` (default 20G), least recently fetched first.
- Static files are versioned by content (`?v=<hash>`) and cached for a year; their ETag is
  computed once at startup. `/static/*` and `/dumps*` are served before the public rate limit
  on purpose (a few KB from RAM; downloads that last minutes) — the reverse proxy can limit
  them if needed.

## Security checklist

- TLS terminated by the reverse proxy; `trustProxy: true` only behind it, and with exactly
  ONE proxy in front: the service reads the last `X-Forwarded-For` entry. The Docker image's
  default command does not trust the header (a bare `docker run -p` is safe); the compose
  file adds `--trust-proxy` because Caddy is in front.
- The Caddyfile logs no search text (`q=-`), no record a reader opened (detail paths logged
  as `/cve/:id`, `/pkg/:id`, `/advisory/osv/:id`…, `Referer` dropped), no credential header,
  and truncated addresses (IPv4 /16, IPv6 /32) — the same rule as the service's own log.
- Errors: anonymous callers get `{"error":"internal error","rid":…}`; the detail is in the log
  under that request id. A malformed URL is a 400.
- `/admin/*` and the metrics port not reachable from the internet (the Caddyfile blocks
  `/admin`; metrics listen on loopback, or on the private network with a token).
- One client token per client (`token add --label`), revoked when a client leaves.
- Secrets in `/etc/fad-service/env` (0600) or the compose `.env`, never in the config file.
- Back up off-host; test a restore.
