# fad-service — operations

How to run fad-service in production: install, configure, brand, observe, back up, upgrade,
scale. Design and data model: `docs/SPEC-fad-service.md` at the repository root.

## Components

| Process | Command | Role |
|---|---|---|
| web | `fad-service serve` | Public site, JSON API, `/v1/resource` for fad clients. Stateless; `--workers N` per host. |
| worker | `fad-service worker` | Ingestion jobs (mirrors). Leased: several workers never run one job twice. |
| backup | `fad-service backup` | Online, consistent copy of the database (`VACUUM INTO`). |

All three share one SQLite file in SQLite mode (one host). Several hosts need the PostgreSQL
store (spec §3, coming).

Requirements: Node ≥ 22.13 (24 recommended), `xz` (xz-utils, for the NVD mirror), ~10 GB of
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
| `FAD_SERVICE_METRICS_TOKEN` | Bearer token required on `/metrics` |

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
  never on the public port; summed over all workers of the host. Key series:
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
| `maintenance` | 24 h | FTS optimize, planner stats, WAL truncate | seconds |

`fad-service worker --once --jobs kev,epss` runs a pass by hand. A failed job keeps its last
good data (an empty feed never wipes a table) and is retried at the next pass. On SIGTERM
the worker releases its leases so another one can take over. Measured on a full cold import:
~5.5 min for every source, < 500 MB of memory; the database is ~4 GB.

## Backups and restore

`fad-service backup --dir /var/lib/fad-service/backups --keep 7` (the systemd timer and the
compose `backup` service do it nightly) writes a consistent copy while the service runs.
Copy the directory off-host. To restore: stop web and worker, replace the database file with
a backup, remove the `-wal`/`-shm` files next to it, start again. Mirrors can always be
rebuilt from the sources; tokens and analytics cannot — that is what the backup protects.

## Upgrades

Pull the new version, `npm install --omit=dev` (or rebuild the image), restart worker then
web. Schema changes are applied in place on start (new tables/columns only). Roll back by
restoring the previous code and the last backup.

## Scaling

One host: `workers` in the config (or `--workers N`), and more web containers. Several hosts:
a load balancer (Caddy, nginx, HAProxy, the provider's) with `/health` as health check, the
PostgreSQL store, and one or more workers anywhere — jobs are leased in the database. Clients
spread themselves by region through health-based instance selection.

## Security checklist

- TLS terminated by the reverse proxy; `trustProxy: true` only behind it.
- `/admin/*` and the metrics port not reachable from the internet (the Caddyfile blocks
  `/admin`; metrics listen on loopback / the private network).
- One client token per client (`token add --label`), revoked when a client leaves.
- Secrets in `/etc/fad-service/env` (0600) or the compose `.env`, never in the config file.
- Back up off-host; test a restore.
