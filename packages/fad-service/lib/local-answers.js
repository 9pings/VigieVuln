/**
 * Answers to /v1/resource requests the service can give from its OWN mirrors, without any
 * upstream request: the cheapest way never to load NVD or FIRST.org on behalf of clients.
 *
 *   nvd/cve, nvd/cve-mirror   the NVD record rebuilt in NVD API 2.0 shape from the fkie
 *                             mirror (metrics, weaknesses, configurations, references) and
 *                             the CVE List description — what fad's extractFromNvdRecord reads
 *   epss/scores, epss/cve-score  from the daily EPSS file, when EVERY requested CVE is known
 *
 * Anything the mirrors do not hold falls through to the engine (cache, then the upstream,
 * under the admission budgets).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

const METRIC_KEY = { "4.0": "cvssMetricV40", "3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "2.0": "cvssMetricV2" };

/** Our stored NVD row (+ the CVE List record) → an NVD API 2.0 `cve` object. */
function nvdRecord(row, cveData) {
	const metrics = {};
	for (const m of row.metrics || []) {
		const k = METRIC_KEY[m.version];
		if (!k) continue;
		(metrics[k] ||= []).push({ source: m.source || "nvd@nist.gov", type: m.type || "Secondary",
			cvssData: { version: m.version, baseScore: m.score, baseSeverity: m.severity || undefined, vectorString: m.vector || undefined } });
	}
	return {
		id: row.id, published: row.published || cveData?.published || null, lastModified: row.lastModified || null,
		vulnStatus: row.vulnStatus || null,
		descriptions: cveData?.description ? [{ lang: "en", value: cveData.description }] : [],
		metrics,
		weaknesses: (row.cwes || []).length ? [{ source: "nvd@nist.gov", type: "Primary", description: row.cwes.map(c => ({ lang: "en", value: c })) }] : [],
		configurations: row.configurations || [],
		references: (row.references || []).map(r => ({ url: r.url, source: r.source || undefined, tags: r.tags || [] })),
	};
}

/** → { status, body: object, tag } or null when the mirrors cannot answer. */
async function answerLocally(payload, assets) {
	const p = payload?.params || {};
	const key = `${payload?.provider}/${payload?.type}`;
	if (key === "nvd/cve" || key === "nvd/cve-mirror") {
		const id = String(p.id || "").toUpperCase();
		const row = await assets.nvd(id);
		if (!row) return null;
		const cve = await assets.get("cve", id, { includeUnpublished: true });
		const rec = nvdRecord(row, cve?.data);
		return key === "nvd/cve-mirror" ? { status: 200, body: rec }
			: { status: 200, body: { resultsPerPage: 1, startIndex: 0, totalResults: 1, format: "NVD_CVE", version: "2.0",
				timestamp: new Date().toISOString(), vulnerabilities: [{ cve: rec }] } };
	}
	if (key === "epss/scores" || key === "epss/cve-score") {
		const ids = key === "epss/scores" ? p.ids : [p.id];
		if (!Array.isArray(ids) || !ids.length) return null;
		const data = [];
		for (const raw of ids) {
			const id = String(raw).toUpperCase();
			const s = await assets.signals(id);
			if (s?.epss_score == null) return null;               // one unknown → let the engine answer all
			data.push({ cve: id, epss: String(s.epss_score), percentile: String(s.epss_percentile), date: s.epss_date || null });
		}
		return { status: 200, body: { status: "OK", "status-code": 200, total: data.length, data } };
	}
	return null;
}

module.exports = { answerLocally, nvdRecord };
