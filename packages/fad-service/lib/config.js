/**
 * fad-service configuration: defaults ← JSON file (`--config`, or FAD_SERVICE_CONFIG) ←
 * command-line flags. Secrets (upstream API keys) are NOT read from the file: they come
 * from the environment only (FAD_SERVICE_NVD_KEY, …), so a config file can be versioned
 * and shared without leaking anything.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const path = require("node:path");

const DEFAULTS = {
	db: "fad-service.db",
	listen: { host: "127.0.0.1", port: 8322 },
	workers: 1,
	region: "unknown",
	// Behind a reverse proxy (Caddy, nginx, a cloud LB): take the client address from the
	// LAST X-Forwarded-For entry, the one the proxy itself appended. Never on a direct
	// listener — any client could then pick its own rate-limit bucket.
	trustProxy: false,
	rateLimit: { client: 600, public: 300 },
	cacheSeconds: 300,
	maxInFlight: 256,          // per process; above it requests get 503 + Retry-After (probes exempt)
	maxConnections: 2048,
	shutdownSeconds: 25,
	log: { file: null, format: "text", level: "info", maxSize: "50M", keep: 10, access: true },
	brand: {
		name: "fad · vulnerabilities",
		tagline: null,             // null → the built-in FR/EN tagline
		baseUrl: null,             // https://vuln.example.fr — canonical links
		logo: null,                // path to an SVG/PNG served at /static/logo
		accent: null,              // CSS colour, e.g. "#1f4fd1"
		footer: null,              // extra footer text
		contact: null,             // "mailto:…" or URL
		publisher: null,           // { name, address, contact, director } — French LCEN legal notice
		host: null,                // { name, address, contact }
	},
	// Prometheus /metrics on its own listener (never the public port); optional bearer token.
	metrics: { enabled: true, listen: "127.0.0.1:9464", token: null },
	analytics: {
		provider: "server",        // "none" | "server" (aggregate counters, no personal data) | "plausible" | "matomo"
		scriptSrc: null,           // plausible: https://plausible.example/js/script.js · matomo: https://matomo.example/
		domain: null,              // plausible data-domain
		siteId: null,              // matomo site id
	},
	// resourceCacheMaxBytes: budget of the /v1/resource pull-through cache (maintenance job).
	jobs: { enabled: null, everyMinutes: 10, osvEcosystems: null, resourceCacheMaxBytes: "20G" },
	// Publication rule (spec §6): a registry package gets a public page once this many
	// distinct clients asked for it (or when it is seeded).
	registry: { publishThreshold: 5 },
	// Upstream routing: Maven Central requests go to these official mirrors first.
	upstream: { mavenMirrors: ["https://maven-central-eu.storage-download.googleapis.com/maven2/"] },
};

const isObj = v => v && typeof v === "object" && !Array.isArray(v);
function merge(base, over) {
	if (!isObj(over)) return over === undefined ? base : over;
	const out = { ...base };
	for (const [k, v] of Object.entries(over)) out[k] = isObj(base?.[k]) && isObj(v) ? merge(base[k], v) : v;
	return out;
}

/** "50M" / "512k" / 1048576 → bytes. */
function parseSize(v) {
	if (typeof v === "number") return v;
	const m = /^(\d+(?:\.\d+)?)\s*([kmg]?)b?$/i.exec(String(v || "").trim());
	if (!m) throw new Error(`invalid size "${v}"`);
	return Math.round(Number(m[1]) * { "": 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[m[2].toLowerCase()]);
}

// Any path segment that names a credential (keys.nvd, github.token, apiKey, password…).
const SECRET_SEGMENT = /^(api[-_]?)?(keys?|tokens?|passwords?|secrets?)$/i;
function rejectSecrets(obj, where = "") {
	for (const [k, v] of Object.entries(obj || {})) {
		const at = where ? `${where}.${k}` : k;
		if (at === "metrics.token") continue;          // allowed, though the environment is preferred
		if (SECRET_SEGMENT.test(k) && v) throw new Error(`"${at}" must not be in the config file — use the environment (FAD_SERVICE_*)`);
		if (isObj(v)) rejectSecrets(v, at);
	}
}

/**
 * Build the effective config. `args` are parsed CLI flags (bin/fad-service.js).
 * → frozen config + `sources` (which file was read).
 */
function loadConfig(args = {}, env = process.env) {
	let cfg = merge(DEFAULTS, {});
	const file = args.config || env.FAD_SERVICE_CONFIG || null;
	if (file) {
		const raw = JSON.parse(fs.readFileSync(file, "utf8"));
		rejectSecrets(raw);
		cfg = merge(cfg, raw);
		// Relative paths in the file are relative to the file, not to the cwd.
		const dir = path.dirname(path.resolve(file));
		for (const p of [["db"], ["log", "file"], ["brand", "logo"]]) {
			const holder = p.length === 1 ? cfg : cfg[p[0]];
			const k = p[p.length - 1];
			if (typeof holder[k] === "string" && holder[k] !== ":memory:" && !path.isAbsolute(holder[k])) holder[k] = path.join(dir, holder[k]);
		}
	}
	// Metrics token from the environment wins over the file.
	if (env.FAD_SERVICE_METRICS_TOKEN) cfg.metrics = { ...cfg.metrics, token: env.FAD_SERVICE_METRICS_TOKEN };
	const flags = {
		db: args.db ?? env.FAD_SERVICE_DB,
		region: args.region ?? env.FAD_SERVICE_REGION,
		workers: args.workers,
		listen: { host: args.host, port: args.port !== undefined ? Number(args.port) : undefined },
		rateLimit: { client: args.rate !== undefined ? Number(args.rate) : undefined },
		log: { file: args["log-file"], format: args["log-format"], access: args.log === true ? true : undefined },
		trustProxy: args["trust-proxy"] === true ? true : undefined,
		metrics: { listen: args["metrics-listen"], enabled: args["no-metrics"] === true ? false : undefined },
	};
	const clean = o => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined).map(([k, v]) => [k, isObj(v) ? clean(v) : v]));
	cfg = merge(cfg, clean(flags));
	if (cfg.db !== ":memory:") cfg.db = path.resolve(String(cfg.db));
	cfg.log.maxBytes = parseSize(cfg.log.maxSize);
	cfg.jobs.resourceCacheBytes = parseSize(cfg.jobs.resourceCacheMaxBytes);
	if (!["text", "json"].includes(cfg.log.format)) throw new Error(`log.format must be "text" or "json"`);
	if (!["none", "server", "plausible", "matomo"].includes(cfg.analytics.provider)) throw new Error("analytics.provider must be none, server, plausible or matomo");
	if (["plausible", "matomo"].includes(cfg.analytics.provider) && !/^https:\/\//.test(cfg.analytics.scriptSrc || ""))
		throw new Error(`analytics.scriptSrc must be an https URL for ${cfg.analytics.provider}`);
	if (cfg.brand.accent && !/^(#[0-9a-f]{3,8}|[a-z]+|rgb\([\d\s,.%]+\))$/i.test(cfg.brand.accent)) throw new Error("brand.accent must be a CSS colour");
	if (cfg.brand.baseUrl && !/^https?:\/\/[^/\s]+\/?$/.test(cfg.brand.baseUrl)) throw new Error("brand.baseUrl must be an origin like https://vuln.example.fr");
	return { ...cfg, configFile: file ? path.resolve(file) : null };
}

/** Upstream API keys — from the environment only. */
function secretsFromEnv(env = process.env) {
	return {
		nvd: env.FAD_SERVICE_NVD_KEY || undefined,
		github: env.FAD_SERVICE_GITHUB_TOKEN || undefined,
		wordfence: env.FAD_SERVICE_WORDFENCE_KEY || undefined,
	};
}

module.exports = { loadConfig, secretsFromEnv, parseSize, DEFAULTS, merge };
