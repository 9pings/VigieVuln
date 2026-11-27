/**
 * lib/source-health.js — is this report complete, and if not, which source went dark?
 *
 * An audit tool's worst output is a scan that ran to completion with a quiet hole in it.
 * `lib/maven-repo.js` already reasons this way for mirrors ("dropping Central would
 * silently turn a transient blip into a coverage hole"), but only Maven mirrors were
 * covered and nothing was ever reported. This generalises it to every remote source.
 *
 * The rule, ONLINE only:
 *   - a lookup served from the warm cache issues no request, so a source whose cache
 *     covers everything is silent even if the site is down. That is full coverage.
 *   - a request that gets no usable answer after the retry schedule is a hole. The scan reports incomplete coverage. A required discovery or structure failure returns exit 2
 *     before publishing reports.
 * Offline scans use cached evidence and apply the same required coverage checks.
 *
 * The retry schedule applies ONLY to single-endpoint sources. A request carrying an
 * AbortSignal comes from a caller with its own deadline and its own failover across
 * mirrors/registries, so it is passed straight through.
 *
 * A definitive 404/410 is an ANSWER, not an outage — it is precisely how private and
 * internal packages are detected (lib/private-deps.js). Only 403/429/5xx and transport
 * failures count against a host.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

/** Remote sources, by id. `hosts` are matched as exact host or dot-suffix. */
const SOURCES = {
	mavenGoogle: {label:'Google Maven (Android)',flag:'check Google Maven availability',hosts:['dl.google.com','maven.google.com']},
	githubApi: { label: "GitHub publisher advisories", flag: "--prestashop-advisories <file> / --typo3-advisories <file>", hosts: ["api.github.com"] },
	cve:      { label: "CVE index (CVEProject)",   flag: "--cve-offline",   hosts: ["github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com"] },
	wordfence: { label: "Wordfence", flag: "--wordfence-feed <file>", hosts: ["wordfence.com"] },
	wpvulnerability: { label: "WPVulnerability", flag: "check public advisory source availability", hosts: ["wpvulnerability.net"] },
	wordpress: { label: "WordPress checksums", flag: "--wp-checksums <file>", hosts: ["api.wordpress.org"] },
	drupalAdvisories: { label: "Drupal advisories", flag: "--drupal-advisories <file>", hosts: ["packages.drupal.org"] },
	osv:      { label: "OSV.dev",                  flag: "--no-osv",        hosts: ["api.osv.dev", "osv-vulnerabilities.storage.googleapis.com"] },
	nvd:      { label: "NVD (NIST)",               flag: "--no-nvd",        hosts: ["services.nvd.nist.gov", "nvd.nist.gov"] },
	epss:     { label: "EPSS (FIRST.org)",         flag: "--no-epss",       hosts: ["api.first.org", "epss.cyentia.com"] },
	kev:      { label: "CISA KEV",                 flag: "--no-kev",        hosts: ["cisa.gov"] },
	euvd:     { label: "ENISA EUVD",               flag: "--no-euvd",       hosts: ["euvdservices.enisa.europa.eu"] },
	certfr:   { label: "CERT-FR (ANSSI)",          flag: "--no-certfr",     hosts: ["cert.ssi.gouv.fr"] },
	eol:      { label: "endoflife.date",           flag: "--no-eol",        hosts: ["endoflife.date"] },
	maven:    { label: "Maven Central",            flag: "--no-transitive --no-all-libs", hosts: ["repo1.maven.org", "repo.maven.apache.org", "search.maven.org", "storage-download.googleapis.com"] },
	npm:      { label: "npm registry",             flag: "--no-npm",        hosts: ["registry.npmjs.org"] },
	pypi:     { label: "PyPI",                     flag: "--no-pypi",       hosts: ["pypi.org", "files.pythonhosted.org"] },
	nuget:    { label: "NuGet",                    flag: "--no-nuget",      hosts: ["api.nuget.org", "nuget.org"] },
	composer: { label: "Packagist",                flag: "--no-composer",   hosts: ["repo.packagist.org", "packagist.org"] },
	ruby:     { label: "RubyGems",                 flag: "--no-ruby",       hosts: ["rubygems.org"] },
	go:       { label: "Go module proxy",          flag: "--no-go",         hosts: ["proxy.golang.org"] },
	binary:   { label: "Binary identity (deps.dev + CIRCL)", flag: "--no-binaries", hosts: ["api.deps.dev", "deps.dev", "hashlookup.circl.lu"] },
};

/** Default retries before a source that does not answer stops the run (`--retries <n>`). */
const RETRY_ATTEMPTS = 5;
// Internal request metadata, consumed by guardedFetch and never sent as a header.
const REQUEST_KEY = Symbol('source-health-request-key');
const ATTEMPT_TIMEOUT = Symbol('per-attempt-timeout');
const REQUEST_SOURCE = Symbol('source-for-request');
let retryAttempts = RETRY_ATTEMPTS;

/**
 * Set the run-wide retry count (`--retries <n>`, default 5). 0 = no retry: the first
 * failed answer declares the source down. Anything that is not a non-negative integer is
 * refused rather than silently clamped — `--retries five` must not quietly mean 5 or 0.
 * → the value in force.
 */
function setRetryAttempts(n) {
	const v = typeof n === "string" && n.trim() !== "" ? Number(n) : n;
	if (!Number.isInteger(v) || v < 0) throw new Error(`--retries expects a non-negative integer, got "${n}"`);
	retryAttempts = v;
	return retryAttempts;
}
function getRetryAttempts() { return retryAttempts; }

/** 5 + n seconds: 6, 7, 8, 9, 10 for the default 5. ~40s before a host is declared dead, once per host. */
function retryDelaysMs(attempts = retryAttempts) {
	return Array.from({ length: attempts }, (_, i) => (5 + i + 1) * 1000);
}

/** "5 attempts, 6→10 s" — the schedule as the abort message prints it. */
function describeSchedule(attempts = retryAttempts) {
	if (!attempts) return "no retry";
	const d = retryDelaysMs(attempts).map(ms => ms / 1000);
	return `${attempts} attempt${attempts > 1 ? "s" : ""}, ${d.length > 1 ? `${d[0]}→${d[d.length - 1]}` : d[0]} s`;
}

function hostOf(url) {
	try { return new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
}

/** The source a URL belongs to, or null when the host is none of ours (leave it alone). */
function sourceForUrl(url) {
	const host = hostOf(url);
	if (!host) return null;
	for (const [id, s] of Object.entries(SOURCES)) {
		if (s.hosts.some(h => host === h || host.endsWith("." + h))) return { id, ...s };
	}
	return null;
}

/**
 * "answered"    — the host spoke, including a definitive 404/410 or a 4xx we caused.
 * "unavailable" — throttled (429), walled off (403), broken (5xx), or no transport at all.
 */
function classifyResponse(res, err) {
	if (err) return "unavailable";
	if (!res) return "unavailable";
	const status = Number(res.status) || 0;
	if (status === 403 || status === 429 || status >= 500) return "unavailable";
	return "answered";
}

function errCode(res, err) {
	if (err) {
		const m = /\b(E[A-Z]{3,}|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|UND_ERR_[A-Z_]+)\b/.exec(err.message || "");
		return m ? m[1] : (err.message || "network error").slice(0, 60);
	}
	return res?.headers?.get?.('x-fad-proxy') ? require('./request-failure').responseFailure(res).reason : `HTTP ${res?.status ?? "?"}`;
}

/** Per-run ledger of sources that went dark. */
function createSourceHealth() {
	const down = new Map();
	const outageEvents = new Map();
	const stale = new Map();
	const staleEvents = new Map();
	const summarizeStale = (id, events) => {
		let result;
		for (const e of events) {
			const oldest = !result || (Number.isFinite(e.at) && (!result.at || e.at < result.at)) ? (Number.isFinite(e.at) ? e.at : null) : result.at;
			result = { id, at: oldest, ...((e.blocking || result?.blocking) ? { blocking: true } : {}), ...((e.refreshFailure || result?.refreshFailure) ? { refreshFailure: e.refreshFailure || result.refreshFailure } : {}) };
		}
		return result;
	};
	return {
		isDown: id => down.has(id),
		markOutage(id, { url, code, requestKey }) {
			const events = outageEvents.get(id) || [];
			events.push({ url, code, requestKey });
			outageEvents.set(id, events);
			let e = down.get(id);
			if (!e) { e = { id, url, codes: [], attempts: 0, requestKeys: [], unkeyed: false }; down.set(id, e); }
			e.attempts += 1;
			if (requestKey) { if (!e.requestKeys.includes(requestKey)) e.requestKeys.push(requestKey); } else e.unkeyed = true;
			if (code && !e.codes.includes(code)) e.codes.push(code);
			return e;
		},
		degraded: () => [...down.values()],
		unreportedOutages: keys => {
			const described = new Set(keys || []), result = [];
			for (const [id, all] of outageEvents) {
				const events = all.filter(e => !e.requestKey || !described.has(e.requestKey));
				if (!events.length) continue;
				result.push({ id, url:events[0].url, codes:[...new Set(events.map(e=>e.code).filter(Boolean))], attempts:events.length,
					requestKeys:[...new Set(events.map(e=>e.requestKey).filter(Boolean))], unkeyed:events.some(e=>!e.requestKey) });
			}
			return result;
		},
		markStale(id, fetchedAt, { reason, requestKey, refreshStatus, refreshCause, retryAfter } = {}) {
			const at = Date.parse(fetchedAt || "");
			const status=Number(refreshStatus),validCause=['rate-limit','admission','upstream-http'].includes(refreshCause),retry=Number(retryAfter);
			const refreshFailure=validCause && Number.isInteger(status) && status>=400 && status<=599 ? {status,cause:refreshCause,...(retryAfter!=null && Number.isSafeInteger(retry)&&retry>=0&&retry<=604800?{retryAfterSeconds:retry}:{})} : null;
			const events = staleEvents.get(id) || [];
			events.push({requestKey, at, blocking:reason==='refresh-failed', refreshFailure});
			staleEvents.set(id, events);
			stale.set(id, summarizeStale(id, events));
		},
		stale: () => [...stale.values()],
		unreportedStale: keys => {const described=new Set(keys||[]);return [...staleEvents].map(([id,events])=>summarizeStale(id,events.filter(e=>!e.requestKey || !described.has(e.requestKey)))).filter(Boolean);},
	};
}

/**
 * The block printed instead of a report. Names the domain, codes, URL and flag.
 *
 * In English, like every other line this tool prints. It was the one French block in an
 * otherwise English terminal — so the operator who most needs to read it, the one whose run
 * just refused to write a report, got it in a language the rest of the output had not used.
 * `--lang` deliberately does not reach here: it chooses the language of the REPORT, which is
 * handed to a client, whereas this is a diagnostic for whoever launched the scan.
 */
function formatAbort(entries) {
	const lines = [];
	const many = entries.length > 1;
	lines.push(`${entries.length} source${many ? "s" : ""} unreachable — the report would be incomplete, nothing was written.`);
	lines.push("");
	for (const e of entries) {
		const s = SOURCES[e.id] || { label: e.id, flag: "", hosts: [] };
		lines.push(`  ${s.label} — ${s.hosts[0] || "?"}`);
		lines.push(`    codes    ${e.codes.join(", ") || "no response"}   (${describeSchedule()})`);
		lines.push(`    url      ${e.url}`);
		lines.push(`    skip     ${s.flag}`);
		lines.push("");
	}
	lines.push("  Re-run with the flag(s) above to audit without those sources,");
	lines.push("  or with --offline to use the cache only (zero network).");
	return lines.join("\n");
}

/**
 * Wrap a fetch so every request to a known source is retried on an outage, each retry
 * logged, and a host that never comes back is recorded once. Requests to hosts we do not
 * own pass through untouched. A host already marked down throws immediately rather than
 * burning the schedule again on each of the remaining lookups.
 */
function guardedFetch({ health, fetch: baseFetch = globalThis.fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), onRetry = null, retries = null, requestKey = null, handledRateLimit = false } = {}) {
	// Read at wrap time: `--retries` is applied before the first guard is installed.
	const attempts = retries == null ? retryAttempts : retries;
	const delays = retryDelaysMs(attempts);
	// One recovery schedule per source, shared by every concurrent caller. The first request
	// to hit an outage owns the loop; the rest await its verdict instead of each sleeping
	// 40s of their own — on a 400-dependency reactor that difference is the whole run.
	const probes = new Map();
	function send(url, init) {
		if (!init?.[ATTEMPT_TIMEOUT]) return baseFetch(url, init);
		const { [ATTEMPT_TIMEOUT]: ms, ...rest } = init;
		return baseFetch(url, { ...rest, signal: AbortSignal.timeout(ms) });
	}

	/**
	 * Run the retry schedule for `src`, starting from the failure the caller already saw
	 * (so the first retry notice carries the real code, not a placeholder).
	 * → { alive: true, res } as soon as the host answers, or { alive: false } once exhausted.
	 */
	async function recover(src, url, init, first, key) {
		let res = first.res, err = first.err;
		let remainingMs = Math.max(120000, delays.reduce((sum, delay) => sum + delay, 0));
		for (let attempt = 0; attempt < attempts; attempt++) {
			const retryAfter = res && [429, 503].includes(res.status) ? require('./request-failure').responseFailure(res).retryAfterSeconds : 0;
			const delayMs = Math.max(delays[attempt], (retryAfter || 0) * 1000);
			const event = { source: src.id, label: src.label, attempt: attempt + 1, of: attempts, code: errCode(res, err), delayMs, url: String(url) };
			if (delayMs > remainingMs) {
				onRetry?.({ ...event, exhausted: true });
				break;
			}
			onRetry?.(event);
			remainingMs -= delayMs;
			if (res?.body && !res.body.locked) void res.body.cancel().catch(() => {});
			await sleep(delayMs);
			res = null; err = null;
			try { res = await send(url, init); }
			catch (e) { err = e; }
			if (classifyResponse(res, err) === "answered") return { alive: true, res };
			if (handledRateLimit && (res?.status === 429 || res?.status === 503 && res.headers?.get?.("x-fad-proxy") === "denied")) break;
		}
		health.markOutage(src.id, { url: String(url), code: errCode(res, err), requestKey:key });
		return { alive: false, res, err };
	}

	return async function guarded(url, init) {
		const key = init?.[REQUEST_KEY] || requestKey;
		if (init && Object.hasOwn(init, REQUEST_KEY)) { init = { ...init }; delete init[REQUEST_KEY]; }
		const src = init?.[REQUEST_SOURCE] || sourceForUrl(url?.url || url);
		if (init?.[REQUEST_SOURCE]) { init = { ...init }; delete init[REQUEST_SOURCE]; }
		if (!src) return baseFetch(url, init);
		// A caller that supplied an AbortSignal owns the deadline — and in fad every such
		// caller (lib/maven-repo.js across mirrors, lib/registries.js and the npm registry
		// across bases) also owns a FAILOVER to the next host. Retrying inside that budget
		// is futile once the signal has fired, and costs 40s of backoff per dead mirror
		// where the caller would have moved on immediately. Hand the outcome straight back
		// and let the rotation do its job; exhaustion is reported by the caller, not here.
		if (init?.signal && !init[ATTEMPT_TIMEOUT]) return baseFetch(url, init);
		if (health.isDown(src.id)) {
			const original = health.degraded().find(e => e.id === src.id)?.codes?.[0];
			health.markOutage(src.id, { url: String(url), code: 'source already unreachable', requestKey:key });
			throw new Error(`${src.label} already unreachable this run${original ? ` (${original})` : ''} (${src.flag} to scan without it)`);
		}
		let res = null, err = null;
		try { res = await send(url, init); }
		catch (e) { err = e; }
		if (classifyResponse(res, err) === "answered") return res;
		if (handledRateLimit && res && (res.status === 429 || res.status === 503 && res.headers?.get?.('x-fad-proxy') === 'denied')) {
			health.markOutage(src.id, {url:String(url),code:errCode(res,err),requestKey:key});
			return res;
		}

		let probe = probes.get(src.id);
		const owner = !probe;
		if (owner) {
			probe = recover(src, url, init, { res, err }, key).finally(() => probes.delete(src.id));
			probes.set(src.id, probe);
		}
		const verdict = await probe;
		if (!verdict.alive) {
			if (owner) {
				if (verdict.err) throw verdict.err;
				return verdict.res;
			}
			health.markOutage(src.id, {url:String(url),code:errCode(res,err),requestKey:key});
			if (err) throw err;
			return res;
		}
		// The owner already holds the answer its own schedule produced.
		if (owner) return verdict.res;
		// A waiter's URL is not the one that was probed, so re-issue it. If THAT still fails,
		// the host is up but this lookup is genuinely holed — record it rather than return a
		// silent gap.
		let r2 = null, e2 = null;
		try { r2 = await send(url, init); }
		catch (e) { e2 = e; }
		if (classifyResponse(r2, e2) !== "answered") {
			health.markOutage(src.id, { url: String(url), code: errCode(r2, e2), requestKey:key });
			if (e2) throw e2;
		}
		return r2;
	};
}

/**
 * Classify one fan-out miss, as lib/maven-repo.js and lib/registries.js phrase it to their
 * `onMiss` hook: "HTTP <status>" or "network: <message>". A 404 (and an auth wall) is a
 * host that ANSWERED; only throttling, server errors and transport failures are not.
 */
function classifyMissReason(reason) {
	const m = /^HTTP (\d{3})$/.exec(String(reason || "").trim());
	if (!m) return "unavailable";                       // "network: …", or nothing at all
	return classifyResponse({ ok: false, status: Number(m[1]) }, null);
}

// Requests that carry the caller's own AbortSignal bypass the guard (the caller owns the
// deadline AND the failover), so the ledger cannot see them. The rotation reports its own
// exhaustion here instead: ONE lookup where no host could answer is the coverage hole.
let activeLedger = null;
function setActiveLedger(h) { activeLedger = h || null; }

/** Called by a fan-out loop that exhausted every host without a usable answer. */
function noteFanoutExhausted(url, reasons, { requestKey } = {}) {
	if (!activeLedger) return;
	const list = reasons || [];
	if (!list.length || list.some(r => classifyMissReason(r) === "answered")) return;
	const src = sourceForUrl(url);
	if (!src) return;
	activeLedger.markOutage(src.id, { url: String(url), code: String(list[0] || "no answer"), requestKey });
}

function displaySourceRetry(r) {
	const wait = `${Math.ceil(r.delayMs / 1000)}s`;
	const action = r.exhausted ? `retry wait of ${wait} exceeds the remaining budget`
		: `attempt ${r.attempt}/${r.of}, retrying in ${wait}`;
	require("./ui").networkNotice(`${r.label} — ${r.code}, ${action}`);
}

module.exports = {
	displaySourceRetry,
	SOURCES, sourceForUrl, classifyResponse, errCode, REQUEST_KEY, ATTEMPT_TIMEOUT, REQUEST_SOURCE,
	RETRY_ATTEMPTS, retryDelaysMs, setRetryAttempts, getRetryAttempts, describeSchedule,
	createSourceHealth, formatAbort, guardedFetch,
	classifyMissReason, noteFanoutExhausted, setActiveLedger,
};
