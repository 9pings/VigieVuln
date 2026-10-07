# fad-service — build from the REPOSITORY ROOT (the service reuses fad-checker's lib/):
#   docker build -f packages/fad-service/Dockerfile -t fad-service .
# One image, three roles: `serve` (default), `worker`, `backup`. State lives in /data.
FROM node:24-bookworm-slim

# xz-utils: the NVD mirror ships xz. tini: PID 1 that forwards SIGTERM (graceful drain).
RUN apt-get update \
 && apt-get install -y --no-install-recommends xz-utils tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY lib ./lib
COPY packages/fad-service/package.json ./packages/fad-service/package.json
RUN cd packages/fad-service && npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY packages/fad-service ./packages/fad-service

RUN useradd --system --uid 10001 --home /data fad \
 && mkdir -p /data /data/logs /data/backups && chown -R fad /data
USER fad
VOLUME ["/data"]
ENV FAD_SERVICE_DB=/data/fad-service.db NODE_ENV=production NODE_NO_WARNINGS=1
EXPOSE 8322 9464

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8322/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--", "node", "/app/packages/fad-service/bin/fad-service.js"]
# Safe defaults for a bare `docker run -p 8322:8322`: no X-Forwarded-For trust, metrics on
# loopback. Behind a reverse proxy, add --trust-proxy (docker-compose.yml does).
CMD ["serve", "--host", "0.0.0.0", "--metrics-listen", "127.0.0.1:9464", "--log"]
