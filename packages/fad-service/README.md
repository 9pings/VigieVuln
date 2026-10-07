# fad-service

The public data service for [fad-checker](../../README.md): the same pull-through
resource cache as `fad-checker serve-cache`, behind per-client tokens, hosted in Europe.
Design: `docs/SPEC-fad-service.md`. Status: milestone 2 — `/v1/resource`, `/health`,
tokens, admin routes, `--workers`. Search, pages, ingestion, dumps and PostgreSQL follow.

Requires Node ≥ 22.13 (built-in `node:sqlite`). No dependency.

```bash
# one token per client, shown once
node bin/fad-service.js token add --role client --label "team-a" --db /srv/fad/service.db
node bin/fad-service.js token add --role admin --db /srv/fad/service.db

# serve (4 processes on this host, one SQLite file)
FAD_SERVICE_NVD_KEY=… node bin/fad-service.js serve --db /srv/fad/service.db \
  --host 0.0.0.0 --port 8322 --region fr --workers 4 --log

# point fad at it
fad-checker -s ./project --proxy-cache https://fad.example.fr --proxy-cache-token fad_…
```

| Route | Access | |
|---|---|---|
| `GET /health` | public | liveness, version, region, store kind |
| `POST /v1/resource` | client token | the fad `--proxy-cache` protocol |
| `GET /admin/stats` | admin token | counters, store size |
| `POST /admin/purge` | admin token | drop one resource `{ provider, type, params }` |

Scaling: `--workers N` on one host; across hosts a load balancer in front (Caddy, nginx,
HAProxy, the provider's LB) with `/health` as health check, on the PostgreSQL store
(coming). Instances never talk to each other.

Logs record method, route, status, latency and a salted tag of the token — never the
coordinates a client asks for.
