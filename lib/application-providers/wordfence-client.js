const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { FORMAT, MAX_RESPONSE_BYTES, componentQueries, queriesOf, keyOf, indexProjection, projectFeed, mergeProjections } = require("./wordfence-projection");
const CACHE_FILE = "wordfence-v3-targeted.json";

async function readProjection(response) {
	if (!response?.ok) throw new Error(`Wordfence projection request failed with HTTP ${response?.status ?? "unknown"}`);
	if (Number(response.headers.get("content-length")) > MAX_RESPONSE_BYTES) {
		await response.body?.cancel();
		throw new Error("Wordfence projection response limit exceeded");
	}
	let size = 0;
	const chunks = [];
	for await (const chunk of response.body) {
		size += chunk.length;
		if (size > MAX_RESPONSE_BYTES) throw new Error("Wordfence projection response limit exceeded");
		chunks.push(chunk);
	}
	try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))); }
	catch { throw new Error("invalid Wordfence projection JSON"); }
}

async function fetchWordfenceProjection(components, { fetchImpl = globalThis.fetch, apiKey, now = Date.now(), software } = {}) {
	const { hasProxyRoute, getResource } = require("../providers");
	if (!hasProxyRoute()) throw new Error("Wordfence projection requires a proxy");
	const queries = software ? queriesOf(software) : componentQueries(components);
	let snapshot = null;
	for (let start = 0; start < queries.length; start += 100) {
		const batch = queries.slice(start, start + 100);
		const response = await getResource("wordfence", "software", { software: batch }, {
			fetcher: fetchImpl, headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
			signal: AbortSignal.timeout(120000), streaming: true, noStore: true,
		});
		const part = await readProjection(response);
		const index = indexProjection(part);
		if (index.queriedSoftware.size !== batch.length || batch.some(q => !index.queriedSoftware.has(keyOf(q))))
			throw new Error("Wordfence projection does not explicitly cover the requested software");
		const collected = Date.parse(part._fadSnapshot.collectedAt);
		if (collected > now + 60000) throw new Error("Wordfence projection collection date is in the future");
		// Never re-date old evidence; the transport may know an even older collection date.
		const transportDate = Date.parse(response.headers.get("x-fad-proxy-fetched-at"));
		if (Number.isFinite(transportDate) && transportDate < collected)
			part._fadSnapshot.collectedAt = new Date(transportDate).toISOString();
		if (response.headers.get("x-fad-proxy") === "stale") part._fadSnapshot.stale = true;
		snapshot = mergeProjections(snapshot, part);
		if (Buffer.byteLength(JSON.stringify(snapshot)) > MAX_RESPONSE_BYTES)
			throw new Error("Wordfence combined projection response limit exceeded");
	}
	snapshot ||= projectFeed(new Map(), [], now);
	return { snapshot, sourceSnapshot: { ...snapshot._fadSnapshot,
		sha256: crypto.createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") } };
}

function cacheProjection(dir, snapshot) {
	if (snapshot.format !== FORMAT) throw new Error("expected a targeted Wordfence snapshot");
	const file = path.join(dir, CACHE_FILE);
	let previous = null;
	try {
		if (fs.statSync(file).size > MAX_RESPONSE_BYTES) throw new Error("Wordfence cache limit exceeded");
		previous = JSON.parse(fs.readFileSync(file, "utf8")); indexProjection(previous);
	}
	catch { previous = null; }
	const merged = mergeProjections(previous, snapshot);
	// Keep the current scan's exact coverage if the cross-project union is too large.
	require("./live-snapshot").writeSnapshotAtomically(file,
		Buffer.byteLength(JSON.stringify(merged)) <= MAX_RESPONSE_BYTES ? merged : snapshot);
}

module.exports = { fetchWordfenceProjection, cacheProjection, CACHE_FILE };
