/**
 * Audience analytics, chosen in the config (`analytics.provider`):
 *
 *   "none"       nothing.
 *   "server"     (default) daily aggregate counters kept by the service itself: page views
 *                per route family, searches, and which CVE / advisory pages are read. No
 *                IP, no cookie, no user agent, no search text — nothing personal, so no
 *                consent banner. Read through GET /admin/analytics.
 *   "plausible"  a self-hosted or EU Plausible: one script tag, the CSP opened to its
 *   "matomo"     origin only. Matomo's init code is served same-origin from
 *                /static/analytics.js (CSP forbids inline script).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const FLUSH_MS = 60 * 1000;

function createServerAnalytics(db) {
	db.exec(`CREATE TABLE IF NOT EXISTS analytics_daily (
		day TEXT NOT NULL, metric TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL,
		PRIMARY KEY (day, metric, key))`);
	const add = db.prepare(`INSERT INTO analytics_daily (day, metric, key, count) VALUES (?, ?, ?, ?)
		ON CONFLICT(day, metric, key) DO UPDATE SET count = count + excluded.count`);
	const pending = new Map();
	const today = () => new Date().toISOString().slice(0, 10);
	const bump = (metric, key) => {
		const k = `${today()}|${metric}|${key}`;
		pending.set(k, (pending.get(k) || 0) + 1);
	};
	const flush = () => {
		if (!pending.size) return;
		const rows = [...pending]; pending.clear();
		try {
			db.exec("BEGIN IMMEDIATE");
			for (const [k, n] of rows) { const [day, metric, key] = k.split("|"); add.run(day, metric, key, n); }
			db.exec("COMMIT");
		} catch { try { db.exec("ROLLBACK"); } catch { /* not in a transaction */ } }
	};
	const timer = setInterval(flush, FLUSH_MS);
	timer.unref?.();
	return {
		/** One public page or API answer. `asset` = "cve:CVE-…" for detail pages. */
		record({ family, status, asset = null, search = false }) {
			if (status >= 400 && status !== 404) return;
			bump("view", family);
			if (search) bump("search", "all");
			if (asset && status === 200) bump("asset", asset);
		},
		flush,
		/** → { days: { day: { view: {family: n}, search: n } }, topAssets: [[key, n]] } over the last `days`. */
		report(days = 30) {
			flush();
			const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
			const rows = db.prepare("SELECT day, metric, key, count FROM analytics_daily WHERE day >= ? ORDER BY day").all(since);
			const out = { days: {}, topAssets: [] };
			const assets = new Map();
			for (const r of rows) {
				const d = (out.days[r.day] ||= { view: {}, search: 0 });
				if (r.metric === "view") d.view[r.key] = r.count;
				else if (r.metric === "search") d.search += r.count;
				else if (r.metric === "asset") assets.set(r.key, (assets.get(r.key) || 0) + r.count);
			}
			out.topAssets = [...assets].sort((a, b) => b[1] - a[1]).slice(0, 50);
			return out;
		},
		close() { clearInterval(timer); flush(); },
	};
}

/** The CSP additions and the head markup a third-party provider needs. */
function clientAnalytics(cfg) {
	if (!cfg || !["plausible", "matomo"].includes(cfg.provider)) return { csp: {}, head: "", initScript: null };
	const src = new URL(cfg.scriptSrc);
	const origin = src.origin;
	const attr = s => String(s).replace(/[&"<>]/g, c => ({ "&": "&amp;", '"': "&quot;", "<": "&lt;", ">": "&gt;" }[c]));
	if (cfg.provider === "plausible") {
		return { csp: { "script-src": [origin], "connect-src": [origin] },
			head: `<script defer data-domain="${attr(cfg.domain || "")}" src="${attr(src.href)}"></script>`, initScript: null };
	}
	const base = src.href.endsWith("/") ? src.href : src.href + "/";
	const initScript = `var _paq=window._paq=window._paq||[];_paq.push(["disableCookies"]);_paq.push(["trackPageView"]);_paq.push(["enableLinkTracking"]);
(function(){var u=${JSON.stringify(base)};_paq.push(["setTrackerUrl",u+"matomo.php"]);_paq.push(["setSiteId",${JSON.stringify(String(cfg.siteId || "1"))}]);
var g=document.createElement("script");g.async=true;g.src=u+"matomo.js";document.head.appendChild(g);})();`;
	return { csp: { "script-src": ["'self'", origin], "connect-src": [origin], "img-src": [origin] },
		head: `<script src="/static/analytics.js" defer></script>`, initScript };
}

module.exports = { createServerAnalytics, clientAnalytics };
