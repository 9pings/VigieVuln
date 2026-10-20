# fad-service

The public data service for [fad-checker](../../README.md): the same pull-through
resource cache as `fad-checker serve-cache`, behind per-client tokens, hosted in Europe.
Design: `docs/SPEC-fad-service.md` (repository root). **Production: [docs/OPERATIONS.md](docs/OPERATIONS.md)**
(Docker, systemd, configuration, branding, logs, metrics, analytics, backups).
Roadmap: [provenance, update history, backups, continuity and naming](docs/TODO.md).
Status: milestone 6 — `/v1/resource`, tokens, admin routes, `--workers`, the vulnerability
mirrors (cvelistV5, NVD via fkie, OSV, CISA KEV, EPSS, ENISA EUVD, CERT-FR; GCVE ids
computed), package metadata (projections, Maven EU mirror, K-client publication rule, seed),
full-text search, the public pages, and signed dumps (public/private/full, deltas, torrent,
restore, `fad-checker serve-cache --seed`), SQLite or PostgreSQL (`--db postgres://…`), upstream
protection (mirror answers, budgets, negative cache) and strict input validation.

Requires Node ≥ 22.13 (built-in `node:sqlite`), `xz` for the NVD mirror. Dependencies: `fflate`, and
`pg` for the PostgreSQL mode.

```bash
# one token per client, shown once
node bin/fad-service.js token add --role client --label "team-a" --db /srv/fad/service.db
node bin/fad-service.js token add --role admin --db /srv/fad/service.db

# serve (4 processes on this host, one SQLite file)
FAD_SERVICE_NVD_KEY=… node bin/fad-service.js serve --db /srv/fad/service.db \
  --host 0.0.0.0 --port 8322 --region fr --workers 4 --log

# ingestion: runs every job that is due, then sleeps (jobs are leased — several workers are safe)
node bin/fad-service.js worker --db /srv/fad/service.db
node bin/fad-service.js worker --db /srv/fad/service.db --once --jobs kev,epss   # one pass

# point fad at it
fad-checker -s ./project --proxy-cache https://fad.example.fr --proxy-cache-token fad_…
```

| Route | Access | |
|---|---|---|
| `GET /health` | public | liveness, version, region, store kind |
| `POST /v1/resource` | client token | the fad `--proxy-cache` protocol |
| `GET /admin/stats` | admin token | counters, store size |
| `POST /admin/purge` | admin token | drop one resource `{ provider, type, params }` |
| `GET /` · `/search?q=` | public | search (an exact CVE / GCVE / EUVD / CERT-FR id goes straight to its page) |
| `GET /cve/:id` · `/advisory/(certfr|osv)/:id` · `/pkg/<eco>/<name>` | public | detail pages, FR/EN, with their sources and licences |
| `GET /sources` · `/legal` | public | freshness of every mirror · attributions |
| `GET /api/search?q=` · `/api/cve/:id` | public | the same data as JSON |

Public pages are server-rendered with no script at all (CSP `default-src 'none'`), carry
an ETag and `Cache-Control`, are rate-limited per IP, and never call an upstream: they
read what the worker wrote. The cvelistV5 baseline (a 620 MB nested zip) is decompressed
while it downloads; nothing is written to disk.

Scaling: `--workers N` on one host; across hosts a load balancer in front (Caddy, nginx,
HAProxy, the provider's LB) with `/health` as health check, on the PostgreSQL store
(coming). Instances never talk to each other.

Logs record method, route, status, latency and a salted tag of the token — never the
coordinates a client asks for.
