/** Server-only full catalogue cache. A client receives only an explicit projection. */
const { gzipSync, gunzipSync } = require("node:zlib");
const { indexProductionFeed } = require("../application-providers/wordfence-v3");
const { queriesOf, projectFeed, MAX_RESPONSE_BYTES } = require("../application-providers/wordfence-projection");
const MAX_FEED_BYTES = 128 * 1024 * 1024;

function createWordfenceProjection({ store, loadFeed, ttlMs, allowStale, stats, maxEntries,
	maxResponseBytes = MAX_RESPONSE_BYTES, now = Date.now }) {
	const flights = new Map(), failures = new Map();
	let memo = null; // One parsed catalogue at most; credential scopes never share it.
	const rememberFailure = key => {
		for (const [k, until] of failures) if (until <= now()) failures.delete(k);
		if (failures.size >= maxEntries) failures.delete(failures.keys().next().value);
		failures.set(key, now() + 30000);
	};
	async function catalogue(key, request) {
		if (flights.has(key)) { stats.coalesced++; return flights.get(key); }
		const work = (async () => {
			let previous = null;
			const entry = await store.get(key);
			if (entry && entry.bytes <= MAX_FEED_BYTES && entry.fetchedAt > 0 && entry.fetchedAt <= now()) {
				const release = store.acquire(entry);
				try {
					if (memo?.key === key && memo.fetchedAt === entry.fetchedAt && memo.bytes === entry.bytes) previous = memo;
					else {
						const feed = JSON.parse(gunzipSync(await store.readBody(entry), { maxOutputLength: MAX_FEED_BYTES }).toString("utf8"));
						const index = indexProductionFeed(feed);
						if (!index.size) throw new Error("empty Wordfence catalogue");
						previous = memo = { key, index, fetchedAt: entry.fetchedAt, bytes: entry.bytes };
					}
				} catch { /* A corrupt cache cannot prove coverage; refresh it. */ }
				finally { release(); }
			}
			if (previous && now() - previous.fetchedAt < Math.min(ttlMs, entry.ttlMs)) {
				stats.hits++;
				return { ...previous, stale: false };
			}
			if ((failures.get(key) || 0) > now()) {
				if (!previous || !allowStale) throw new Error("Wordfence refresh is temporarily unavailable");
				stats.stale++;
				return { ...previous, stale: true };
			}
			try {
				stats.misses++;
				const feed = await loadFeed(request);
				const index = indexProductionFeed(feed);
				if (!index.size) throw new Error("empty Wordfence catalogue cannot establish coverage");
				const body = gzipSync(JSON.stringify(feed));
				if (body.length > Math.min(MAX_FEED_BYTES, store.maxEntryBytes || MAX_FEED_BYTES))
					throw new Error("Wordfence catalogue exceeds the server cache limit");
				const fetchedAt = now();
				await store.put(key, body, { fetchedAt, ttlMs, contentType: "application/gzip", bytes: body.length });
				memo = { key, index, fetchedAt, bytes: body.length };
				failures.delete(key);
				return { ...memo, stale: false };
			} catch (error) {
				stats.errors++;
				rememberFailure(key);
				if (!previous || !allowStale) throw error;
				stats.stale++;
				return { ...previous, stale: true };
			}
		})();
		flights.set(key, work);
		try { return await work; } finally { flights.delete(key); }
	}
	return async (software, key, request) => {
		const queries = queriesOf(software, { min: 1, max: 100 });
		const result = await catalogue(key, request);
		const snapshot = projectFeed(result.index, queries, result.fetchedAt, result.stale);
		const body = Buffer.from(JSON.stringify(snapshot));
		if (body.length > maxResponseBytes) throw new Error("Wordfence projection exceeds the response limit");
		return { body, fetchedAt: result.fetchedAt, stale: result.stale };
	};
}

module.exports = { createWordfenceProjection, MAX_FEED_BYTES };
