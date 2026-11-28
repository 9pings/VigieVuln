/**
 * lib/providers/nvd/cpe.js — CPE 2.3 parsing + matching of NVD configuration trees.
 *
 * CPE 2.3 URI binding:
 *   cpe:2.3:part:vendor:product:version:update:edition:language:
 *           sw_edition:target_sw:target_hw:other
 * Each field can be a literal, "*" (ANY) or "-" (NA). Some characters
 * are percent-encoded, we only need to undo "\:" and "\\" for the
 * fields we read.
 *
 * Used in two directions:
 *   1. Given a NVD-enriched match (cve.cpes[] + cve.configurations[]),
 *      decide whether a dep is _truly_ affected (version range check)
 *      and whether we can upgrade the match confidence.
 *   2. Given a dep coord, find CVEs in the index whose CPE configurations
 *      it satisfies. (Future use — kept compatible with the data shape.)
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { compareMavenVersions } = require("../../codecs/maven/version");

let CPE_COORD_MAP_CACHE = null;
function loadCpeCoordMap() {
	if (CPE_COORD_MAP_CACHE) return CPE_COORD_MAP_CACHE;
	try {
		CPE_COORD_MAP_CACHE = require("../../../data/cpe-coord-map.json");
	} catch {
		CPE_COORD_MAP_CACHE = { byVendorProduct: {}, byProduct: {} };
	}
	return CPE_COORD_MAP_CACHE;
}

/**
 * Parse a CPE 2.3 URI. Returns null on malformed input.
 * Field order: cpe:2.3:part:vendor:product:version:update:edition:language:
 *              sw_edition:target_sw:target_hw:other
 */
function parseCpe23(uri) {
	if (typeof uri !== "string") return null;
	if (!uri.startsWith("cpe:2.3:")) return null;
	// Split on `:` but respect backslash escaping.
	const fields = [];
	let buf = "";
	for (let i = 0; i < uri.length; i++) {
		const c = uri[i];
		if (c === "\\" && i + 1 < uri.length) {
			buf += uri[i + 1]; i++;
		} else if (c === ":") {
			fields.push(buf); buf = "";
		} else {
			buf += c;
		}
	}
	fields.push(buf);
	// fields = ["cpe","2.3","a","vendor","product","version","update","edition","language","sw_edition","target_sw","target_hw","other"]
	if (fields.length < 7) return null;
	return {
		part:        fields[2] || "*",
		vendor:      fields[3] || "*",
		product:     fields[4] || "*",
		version:     fields[5] || "*",
		update:      fields[6] || "*",
		edition:     fields[7] || "*",
		language:    fields[8] || "*",
		sw_edition:  fields[9] || "*",
		target_sw:   fields[10] || "*",
		target_hw:   fields[11] || "*",
		other:       fields[12] || "*",
	};
}

// Memoize parseCpe23 on the cpeMatch object so subsequent passes (the
// confidence walk inside evaluateCveForDep) don't re-tokenize the same URI.
// `_parsedCpe` uses `null` (parse failed) vs `undefined` (not yet parsed) to
// distinguish empty result from missing cache.
function parseCpe23Cached(cpeMatch) {
	if (!cpeMatch || typeof cpeMatch !== "object") return parseCpe23(cpeMatch?.criteria || "");
	if (cpeMatch._parsedCpe !== undefined) return cpeMatch._parsedCpe;
	cpeMatch._parsedCpe = parseCpe23(cpeMatch.criteria || "");
	return cpeMatch._parsedCpe;
}

/**
 * Match a dep version against a single NVD cpeMatch entry.
 * The entry has the shape:
 *   { criteria: "cpe:2.3:a:vendor:product:version:...",
 *     vulnerable: true,
 *     versionStartIncluding, versionStartExcluding,
 *     versionEndIncluding,   versionEndExcluding }
 *
 * Returns true if `depVersion` is in range. If the CPE itself pins a
 * concrete version (criteria's version field != "*"/"-"), that pin wins.
 */
function matchVersionRange(depVersion, cpeMatch) {
	if (!cpeMatch) return false;
	if (!depVersion) return true; // unknown version → assume affected
	const parsed = parseCpe23Cached(cpeMatch);
	if (!parsed) return false;

	// Hard pin in the criteria URI itself
	if (parsed.version && parsed.version !== "*" && parsed.version !== "-") {
		// CPE 2.3 update field qualifies the version (`:1.0.0:beta1:` ≡ `1.0.0-beta1`).
		// Without folding it in, a release like 1.0.0 would incorrectly match a pin
		// of 1.0.0:rc1 — see H5 in CRITICAL-REVIEW.md.
		const pinned = (parsed.update && parsed.update !== "*" && parsed.update !== "-")
			? `${parsed.version}-${parsed.update}`
			: parsed.version;
		try { return compareMavenVersions(depVersion, pinned) === 0; }
		catch { return false; }
	}

	try {
		if (cpeMatch.versionStartIncluding && compareMavenVersions(depVersion, cpeMatch.versionStartIncluding) < 0) return false;
		if (cpeMatch.versionStartExcluding && compareMavenVersions(depVersion, cpeMatch.versionStartExcluding) <= 0) return false;
		if (cpeMatch.versionEndIncluding && compareMavenVersions(depVersion, cpeMatch.versionEndIncluding) > 0) return false;
		if (cpeMatch.versionEndExcluding && compareMavenVersions(depVersion, cpeMatch.versionEndExcluding) >= 0) return false;
	} catch { return false; }
	return true;
}

/**
 * Evaluate a node (OR/AND of cpeMatch entries). For our use we only care
 * about the `vulnerable` matches — "AND runs on Windows" runtime context
 * is ignored on purpose: we assume the library is being _used_, so any
 * vulnerable-marked CPE that matches the dep version is a real hit.
 *
 * Returns true if any vulnerable cpeMatch in the node matches the dep.
 */
function nodeAffectsDep(node, dep, cpeCoordMap, opts = {}) {
 return evaluateProductConfiguration(node,
  leaf=>cpeMatchesDep(parseCpe23Cached(leaf),dep,cpeCoordMap,opts),
  leaf=>matchVersionRange(dep.version,leaf)) === true;
}

/**
 * Does ANY vulnerable cpeMatch in this CVE name the dep's product/vendor — IGNORING the
 * version range? This distinguishes "NVD has a CPE for this product but the dep version is
 * out of range" (a genuine false positive worth filtering) from "NVD's CPE never names this
 * product at all" (a coverage gap — NOT a false positive: the dep's own matcher, OSV or the
 * CVE index, found it on a real coordinate, and CPE simply can't speak to it).
 */
function cveCpeNamesDep(cveRecord, dep, cpeCoordMap) {
	const map = cpeCoordMap || loadCpeCoordMap();
	const scan = nodes => {
		for (const n of (nodes || [])) {
			for (const m of (n.cpeMatch || n.cpe_match || [])) {
				if (m.vulnerable === false) continue;
				const parsed = parseCpe23Cached(m);
				if (parsed && cpeMatchesDep(parsed, dep, map)) return true;
			}
			if (scan([...(n.children || []),...(n.nodes || [])])) return true;
		}
		return false;
	};
	for (const cfg of (cveRecord?.configurations || [])) if (scan(cfg.nodes)) return true;
	for (const uri of (cveRecord?.cpes || [])) { const p = parseCpe23(uri); if (p && cpeMatchesDep(p, dep, map)) return true; }
	return false;
}

// Evaluate only vulnerable entries identifying the audited product. Other CPEs
// describe environmental prerequisites, assumed satisfied by scanner policy.
// A context-only OR branch cannot establish a vulnerability for the product.
function evaluateProductConfiguration(node, isProduct, versionVerdict) {
 function visit(current) {
  if (!current || !['OR','AND',undefined].includes(current.operator)) return null;
  const values=(current.cpeMatch || current.cpe_match || [])
   .filter(leaf=>leaf.vulnerable===true && isProduct(leaf))
   .map(versionVerdict);
  for (const child of [...(current.nodes || []),...(current.children || [])]) {
   const value=visit(child);
   if(value!==undefined)values.push(value);
  }
  if(!values.length)return undefined;
  if(current.negate)return null;
  return current.operator==='AND'
   ? values.includes(false)?false:values.includes(null)?null:true
   : values.includes(true)?true:values.includes(null)?null:false;
 }
 const result=visit(node);
 return result===undefined?false:result;
}


/**
 * Decide whether a CPE (parsed) refers to the same artifact as a dep.
 * Lookup order:
 *   1. Curated map `byVendorProduct["vendor:product"]` — array of dep keys
 *      (maven "g:a" or "npm:name"). Exact, high confidence.
 *   2. Curated map `byProduct[product]` — same shape, used when vendor is
 *      ambiguous (Apache wraps several groupIds).
 *   3. Heuristic: vendor token appears in groupId, or groupId/artifactId
 *      equals/contains product. Same logic as cve-match.vendorMatchesGroup
 *      but kept local here so cpe.js is standalone.
 */
function cpeMatchesDep(cpe, dep, cpeCoordMap, opts = {}) {
	if (!cpe || !dep) return false;
	if (cpe.part !== "a" && cpe.part !== "*") return false; // we only care about apps
	const map = cpeCoordMap || loadCpeCoordMap();
	const vp = `${cpe.vendor}:${cpe.product}`.toLowerCase();
	const depKey = depToKey(dep).toLowerCase();
	const altKey = altDepKey(dep).toLowerCase();

	const inList = arr => Array.isArray(arr) && arr.some(k => {
		const lk = String(k).toLowerCase();
		return lk === depKey || lk === altKey;
	});

	if (inList(map.byVendorProduct?.[vp])) return true;
	if (inList(map.byProduct?.[cpe.product?.toLowerCase()])) return true;

	// `curatedOnly` stops here. The heuristic below is safe when REFINING a match another
	// source already made (worst case it declines to upgrade confidence), but it is not safe
	// as a way to CREATE matches: name-similarity between a Maven coordinate and a CPE
	// product is exactly what makes CPE-driven scanners noisy. matchDepsAgainstNvdCpe sets it.
	if (opts.curatedOnly) return false;

	// Heuristic fallback
	if (dep.ecosystem === "npm") {
		const name = (dep.artifactId || "").toLowerCase();
		if (cpe.product?.toLowerCase() === name) return true;
		// scoped packages: @scope/name → CPE vendor="scope", product="name"
		const m = name.match(/^@([^/]+)\/(.+)$/);
		if (m && cpe.vendor?.toLowerCase() === m[1] && cpe.product?.toLowerCase() === m[2]) return true;
	} else {
		const g = (dep.groupId || "").toLowerCase();
		const a = (dep.artifactId || "").toLowerCase();
		const v = (cpe.vendor || "").toLowerCase();
		const p = (cpe.product || "").toLowerCase();
		if (p !== a) return false;
		if (g === v) return true;
		// Mirrors vendorMatchesGroup: dot-segment membership only, no substring
		// fallback. Unbounded substring matching leaked FPs (M4 in CRITICAL-REVIEW.md).
		if (g.split(".").includes(v)) return true;
	}
	return false;
}

function depToKey(dep) {
	if (dep.ecosystem === "npm") return `npm:${dep.artifactId}`;
	return `${dep.groupId}:${dep.artifactId}`;
}
function altDepKey(dep) {
	// For artifactId-only matching against curated lists keyed by artifact-only.
	return dep.ecosystem === "npm" ? `npm:${dep.artifactId}` : dep.artifactId || "";
}

/**
 * Run the CPE configurations of `cveRecord` against `dep`.
 * `cveRecord.configurations` follows NVD's shape. Returns:
 *   { affected: boolean, confidence: "exact" | "probable" | null }
 *
 * - "exact" when a curated mapping confirms vendor:product → dep
 * - "probable" when only heuristic matched
 */
function evaluateCveForDep(cveRecord, dep, cpeCoordMap, opts = {}) {
	const map = cpeCoordMap || loadCpeCoordMap();
	const configs = cveRecord?.configurations || [];
	let bestConfidence = null;
	const note = c => {
		if (c === "exact" || bestConfidence === "exact") bestConfidence = "exact";
		else if (c === "probable") bestConfidence = bestConfidence || "probable";
	};

	for (const cfg of configs) {
		const nodes = cfg.nodes || [];
		const op = (cfg.operator || "OR").toUpperCase();
		const passes=nodeAffectsDep({...cfg,operator:op},dep,map,opts);
		if (passes) {
			// Determine confidence: scan vulnerable cpeMatches that hit
			const pending=nodes.slice();
			while(pending.length) {
				const n=pending.pop();
				pending.push(...(n.nodes || []),...(n.children || []));
				for (const m of n.cpeMatch || n.cpe_match || []) {
					if (m.vulnerable === false) continue;
					const parsed = parseCpe23Cached(m);
					if (!parsed) continue;
					if (!cpeMatchesDep(parsed, dep, map, opts)) continue;
					if (!matchVersionRange(dep.version, m)) continue;
					const vp = `${parsed.vendor}:${parsed.product}`.toLowerCase();
					const depKey = depToKey(dep).toLowerCase();
					const curated = (map.byVendorProduct?.[vp] || []).some(k => String(k).toLowerCase() === depKey);
					note(curated ? "exact" : "probable");
				}
			}
		}
	}

	// Fallback: no configurations[] (some NVD records only have cpes[]).
	// We accept a hit if any CPE string matches the dep coord — but with no
	// version range info, we can only say "possible" (caller's existing
	// confidence stays unless we can prove version match).
	if (!configs.length && Array.isArray(cveRecord?.cpes)) {
		for (const uri of cveRecord.cpes) {
			const parsed = parseCpe23(uri);
			if (!parsed) continue;
			if (cpeMatchesDep(parsed, dep, map, opts)) {
				note("probable");
				break;
			}
		}
	}

	return { affected: bestConfidence !== null, confidence: bestConfidence };
}

/**
 * Walk an enriched matches list and refine each entry using NVD CPE data.
 * Mutates each match in place:
 *   - sets m.cpeConfidence = "exact" | "probable" | null
 *   - if NVD configurations include version ranges that the dep version does NOT
 *     satisfy AND no other configuration places it in scope, sets
 *     m.cpeFiltered = true so the report can mark it as "likely false positive".
 *   - upgrades m.confidence from "possible" → "probable", "probable" → "exact"
 *     when the CPE side confirms with curated mapping.
 *
 * Note: m.cve.configurations is only present on NVD-enriched records. If
 * absent, we still try m.cve.cpes[] (URI list) for vendor:product matching.
 */
function refineMatchesWithCpe(matches, opts = {}) {
	const map = opts.cpeCoordMap || loadCpeCoordMap();
	for (const m of matches) {
		const cve = m.cve || {};
		// Build a tiny record shape that evaluateCveForDep accepts
		const rec = { configurations: cve.configurations || [], cpes: cve.cpes || [] };
		if (!rec.configurations.length && !rec.cpes.length) continue;
		const { affected, confidence } = evaluateCveForDep(rec, m.dep, map);
		m.cpeConfidence = confidence;
		// Mark a match as a CPE false-positive ONLY for a genuine VERSION contradiction:
		// NVD's CPE names this product but the dep version is outside the vulnerable range.
		// NEVER filter when:
		//   - the match is OSV-confirmed — OSV did a precise, ecosystem-native version match
		//     (its data is authoritative for the package ecosystems; don't let NVD override it);
		//   - NVD's CPE never names this product (`!productNamed`) — that's a coverage gap, not
		//     a false positive (covers every pypi/composer/nuget/go/ruby coord, and any maven/
		//     npm artifact whose CPE product name simply differs from its coordinate).
		// Without these guards the filter silently hid REAL CVEs (e.g. cryptography 46.0.5,
		// fixed in 46.0.6) by dumping them into the false-positives appendix.
		const isExactProvider = String(m.source || "").includes("osv") || String(m.source || "").includes("wordfence-v3");
		const productNamed = cveCpeNamesDep(rec, m.dep, map);
		if (!affected && productNamed && !isExactProvider) {
			m.cpeFiltered = true;
		}
		if (affected && confidence === "exact" && m.confidence !== "exact") m.confidence = "exact";
		else if (affected && confidence === "probable" && m.confidence === "possible") m.confidence = "probable";
	}
	return matches;
}

/**
 * ADDITIVE matching tier: NVD's CPE version ranges, for CURATED coordinates only.
 *
 * OSV/GHSA declare affected ranges per release *branch* — for CVE-2020-9546 only
 * 2.9.0–2.9.10.4, the branch that got a fix. NVD declares three ranges for the same CVE
 * (`2.0.0 ≤ v < 2.7.9.7`, `2.8.0 ≤ v < 2.8.11.6`, `2.9.0 ≤ v < 2.9.10.4`), so
 * jackson-databind 2.5.2 is affected and simply never received a fix. fad already had that
 * data — every enriched CVE's `configurations` sits in the NVD cache — but only ever used it
 * SUBTRACTIVELY, to filter false positives. This uses it additively.
 *
 * MEASURED PRECISION IS POOR, which is why the orchestrator keeps this behind an opt-in flag
 * (`--nvd-cpe-match`). On Dubbo 2.7.8 it adds 76 findings of which only 9 (12%) are
 * corroborated by Snyk. The cause is structural and not fixable by better curation: CPE
 * products are FRAMEWORK-level (`spring_framework`, `netty`, `log4j`) while Maven coordinates
 * are ARTIFACT-level, so a framework CVE lands on every artifact of that framework —
 * CVE-2016-1000027 is a spring-web flaw and CPE puts it on spring-core. This is the same
 * limitation that makes CPE-driven scanners noisy. Useful as a triage aid ("what might I be
 * missing?"), not as a default.
 *
 * Strictly bounded, because the cost of getting this wrong is a false-positive engine:
 *   - `curatedOnly`: a coordinate must appear in `data/cpe-coord-map.json`. No name heuristics.
 *   - Only CVEs already in the NVD cache are considered — no new fetch, no new network path.
 *   - Every distinct concrete version is evaluated; unresolved or `${…}` versions never match,
 *     mirroring the rule in cve-match.js that an unversioned dep is not assumed vulnerable.
 *
 * @param resolvedDeps Map<coordKey, depRecord>
 * @param nvdRecordsById {[cveId]: nvdRecord}  records with `configurations`
 * @returns match[] in the shape mergeBySource expects, tagged `source: "nvd"`
 */
function matchDepsAgainstNvdCpe(resolvedDeps, nvdRecordsById, opts = {}) {
	const map = opts.cpeCoordMap || loadCpeCoordMap();
	const out = [];
	if (!resolvedDeps || !nvdRecordsById) return out;

	// UNAMBIGUOUS entries only: a CPE product that maps to a SINGLE Maven coordinate.
	// The curated map deliberately maps one CPE to several artifacts — its own comment says
	// so ("one CPE may legitimately map to several Maven artifacts"). That is right for
	// FILTERING, where any member matching means "don't call this a false positive", and
	// catastrophic for MATCHING, where it would assert the CVE affects all of them.
	// Measured on Dubbo: allowing 1:N entries produced 262 new findings of which only 8%
	// were corroborated by any other scanner — CVE-2016-1000027 (a spring-web flaw) landed
	// on spring-core/-beans/-context, CVE-2019-20444 (netty-codec-http) on
	// netty-common/-codec/-handler. That is precisely the CPE noise this tier must not add.
	const curated = new Set();
	for (const list of [...Object.values(map.byVendorProduct || {}), ...Object.values(map.byProduct || {})]) {
		if (!Array.isArray(list) || list.length !== 1) continue;
		curated.add(String(list[0]).toLowerCase());
	}
	const candidates = [];
	for (const dep of resolvedDeps.values()) {
		if (!dep || dep.ecosystem !== "maven") continue;
		if (dep.provenance === "binary") continue;          // no coordinate, identified by hash
		const key = `${dep.groupId}:${dep.artifactId}`.toLowerCase();
		if (!curated.has(key)) continue;
		const versions = (Array.isArray(dep.versions) && dep.versions.length ? dep.versions : [dep.version])
			.filter(v => v && !/\$\{/.test(String(v)));
		if (versions.length) candidates.push([dep, versions]);
	}
	if (!candidates.length) return out;

	for (const [cveId, record] of Object.entries(nvdRecordsById)) {
		if (!record?.configurations?.length) continue;
		for (const [dep, versions] of candidates) {
			for (const version of versions) {
				const probe = { ...dep, version };
				if (!evaluateCveForDep(record, probe, map, { curatedOnly: true }).affected) continue;
				out.push({
					dep: probe,
					cve: {
						id: cveId,
						severity: record.severity || "UNKNOWN",
						score: record.score ?? null,
						description: record.description || "",
						cvssVector: record.cvssVector || null,
						published: record.published || null,
					},
					source: "nvd",
					confidence: "exact",   // curated coordinate + explicit NVD version range
				});
			}
		}
	}
	return out;
}

module.exports = {
	evaluateProductConfiguration,
	parseCpe23,
	matchVersionRange,
	cpeMatchesDep,
	matchDepsAgainstNvdCpe,
	nodeAffectsDep,
	evaluateCveForDep,
	cveCpeNamesDep,
	refineMatchesWithCpe,
	loadCpeCoordMap,
};
