/**
 * Upstream admission: the service must never get itself banned by NVD, OSV, GitHub or a
 * registry because of what its clients send. Two token buckets are checked before EVERY
 * upstream request (lib/resource-cache/engine.js `admit`):
 *
 *   per source   a budget below each source's published or polite limit (NVD: 50 requests
 *                per 30 s with a key, 5 without — we stay at 80 %). Shared by every client.
 *   per client   how many upstream requests ONE token may cause per hour, so a client that
 *                sends thousands of unseen identifiers cannot drain the source budget for
 *                everyone. Cache hits are free: only misses count.
 *
 * Refused → the stale copy when there is one, else 503 + Retry-After; the upstream is not
 * touched. Buckets are per process: with N processes or instances the effective source
 * budget is ×N — set the budgets accordingly (config `upstream.budgets`).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { fad } = require("./fad");

/** "40/30s", "10/1s", "60/1m", "1200/1h" → { tokens, perMs }. */
function parseRate(v) {
	const m = /^(\d+)\s*\/\s*(\d*)\s*(s|m|h)$/.exec(String(v || "").trim());
	if (!m) throw new Error(`invalid rate "${v}" (expected like "40/30s")`);
	const unit = { s: 1000, m: 60000, h: 3600000 }[m[3]];
	return { tokens: Number(m[1]), perMs: (Number(m[2] || 1)) * unit };
}

/** Polite defaults, per process. nvd depends on whether the service holds an NVD key. */
function defaultBudgets({ nvdKey = false, githubToken = false } = {}) {
	return {
		nvd: nvdKey ? "40/30s" : "4/30s",
		osv: "20/1s", epss: "5/1s", kev: "6/1h", eol: "5/1s",
		maven: "20/1s", npm: "20/1s", pypi: "10/1s", composer: "8/1s", ruby: "8/1s", nuget: "15/1s", go: "15/1s",
		githubApi: githubToken ? "60/1m" : "1/1m", cve: "30/1h", euvd: "2/1s", certfr: "8/1s",
		binary: "5/1s", wordfence: "2/1s", wordpress: "5/1s", drupalAdvisories: "5/1s",
		default: "5/1s",
	};
}

function bucket({ tokens, perMs }) {
	let level = tokens, last = Date.now();
	return {
		take() {
			const now = Date.now();
			level = Math.min(tokens, level + ((now - last) / perMs) * tokens);
			last = now;
			if (level >= 1) { level -= 1; return 0; }
			return Math.ceil(((1 - level) / tokens) * perMs / 1000);   // seconds until a token
		},
	};
}

/**
 * opts: { budgets: { <source id>: "n/period" }, clientPerHour (default 1200), nvdKey, githubToken }
 * → admit(url, ctx) for the engine. ctx.principal (a token) is set by the server.
 */
function createUpstreamPolicy({ budgets = {}, clientPerHour = 1200, nvdKey = false, githubToken = false } = {}) {
	const { sourceForUrl } = fad("source-health");
	const merged = { ...defaultBudgets({ nvdKey, githubToken }), ...budgets };
	const sources = new Map(Object.entries(merged).map(([k, v]) => [k, bucket(parseRate(v))]));
	const clients = new Map();
	const clientRate = parseRate(`${clientPerHour}/1h`);
	const stats = { admitted: 0, deniedSource: 0, deniedClient: 0 };
	function admit(url, ctx = {}) {
		const tag = ctx.principal?.hash;
		if (tag && clientPerHour) {
			let b = clients.get(tag);
			if (!b) {
				while (clients.size >= 50000) clients.delete(clients.keys().next().value);
				b = bucket(clientRate);
				clients.set(tag, b);
			}
			const wait = b.take();
			if (wait) { stats.deniedClient++; return { retryAfterS: wait }; }
		}
		const id = sourceForUrl(url)?.id || "default";
		const wait = (sources.get(id) || sources.get("default")).take();
		if (wait) { stats.deniedSource++; return { retryAfterS: wait }; }
		stats.admitted++;
		return true;
	}
	return { admit, stats, budgets: merged };
}

module.exports = { createUpstreamPolicy, parseRate, defaultBudgets };
