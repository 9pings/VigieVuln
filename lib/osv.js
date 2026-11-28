/**
 * lib/osv.js — query OSV.dev for Maven-ecosystem vulnerabilities.
 *
 * OSV.dev (Google + GitHub Security Lab) aggregates CVE + GHSA data and
 * maintains a curated Maven-coordinate mapping. For Maven recall this is
 * vastly better than the raw CVEProject feed (which lacks packageName
 * fields on pre-2024 CVEs).
 *
 * API: https://google.github.io/osv.dev/post-v1-querybatch/
 *   POST /v1/querybatch  with up to 1000 queries
 *   POST /v1/query       for a single dep
 *   GET  /v1/vulns/{id}  to fetch full details
 *
 * Cached responses live in ~/.fad-checker/osv-cache/ for 4h.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const OSV_CACHE_DIR = path.join(require("./cache-directory").getCacheDir(), "osv-cache");
const OSV_BASE = "https://api.osv.dev";
const BATCH_SIZE = 800;          // OSV limit is 1000; stay under for safety

/**
 * A cache FILENAME, never a path. The version was interpolated raw until a package-lock v1
 * entry for a URL-installed dep ("version": "https://registry.npmjs.org/x/-/x-0.12.5.tgz")
 * turned it into a nested path and killed the scan on ENOENT mid-step. Anything that is not
 * safe in a single segment is collapsed — which also means a version can never walk out of
 * the cache directory. `_` is not used as the replacement for `v` because a version legally
 * contains `_`; `%` keeps distinct versions distinct.
 */
function cacheKey(g, a, v, ecosystem = "maven") {
	const tuple = JSON.stringify([ecosystem, g || "", a || "", String(v == null ? "" : v)]);
	return `query-${require('node:crypto').createHash('sha256').update(tuple).digest('hex')}.json`;
}

const SEVERITY_ALIASES = { MODERATE: "MEDIUM", IMPORTANT: "HIGH", SEVERE: "HIGH", INFO: "LOW" };

function normalizeSeverity(s) {
	const up = String(s || "").toUpperCase();
	return SEVERITY_ALIASES[up] || up;
}

const severityFromScore = score => require("./severity").severityFromScore(score, "UNKNOWN");

// Compute a CVSS v3.0/3.1 base score from its vector string. Returns null for
// non-v3 vectors (v2/v4) or anything unparseable. OSV stores the *vector* in
// `severity[].score` for CVSS_V3 — there is NO bare base number to read, so the
// old "first number in the string" approach extracted the VERSION ("3.1") as the
// score, mislabelling HIGH findings as ~low everywhere downstream (SARIF
// security-severity, priority banding, SBOM/CSAF ratings).
function cvss3BaseScore(vector) {
	const v = String(vector || "");
	if (!/^CVSS:3\.[01]\//.test(v)) return null;
	const p = {};
	for (const kv of v.split("/").slice(1)) {
		const [k, val] = kv.split(":");
		if (k && val) p[k] = val;
	}
	const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[p.AV];
	const AC = { L: 0.77, H: 0.44 }[p.AC];
	const UI = { N: 0.85, R: 0.62 }[p.UI];
	const scopeChanged = p.S === "C";
	const PR = scopeChanged
		? { N: 0.85, L: 0.68, H: 0.5 }[p.PR]
		: { N: 0.85, L: 0.62, H: 0.27 }[p.PR];
	const imp = { H: 0.56, L: 0.22, N: 0 };
	const C = imp[p.C], I = imp[p.I], A = imp[p.A];
	if ([AV, AC, UI, PR, C, I, A].some(x => x == null)) return null;
	const iss = 1 - (1 - C) * (1 - I) * (1 - A);
	const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
	if (impact <= 0) return 0;
	const exploit = 8.22 * AV * AC * PR * UI;
	const base = Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10);
	return Math.ceil(base * 10) / 10; // CVSS roundup to one decimal
}

/**
 * Best CVSS info from an OSV vuln: { score, vector, version } (version like "3.1").
 * Every entry is read: the first SCORABLE one wins (v3.x vector or bare number). Ubuntu
 * lists CVSS_V4 first, then CVSS_V3 — stopping at the unscorable v4 lost the v3 score
 * (UBUNTU-CVE-2025-6965 came out UNKNOWN). With nothing scorable, the first CVSS vector
 * is still returned as evidence, with a null score (no v4 score is invented).
 */
function cvssInfoFromVuln(vuln) {
	let unscored = null;
	for (const s of vuln.severity || []) {
		const str = String(s.score || "");
		const mver = str.match(/^CVSS:(\d\.\d)\//);
		if (mver) {
			const version = mver[1];
			const score = (version === "3.0" || version === "3.1") ? cvss3BaseScore(str) : null;
			if (score != null) return { score, vector: str, version };
			if (!unscored) unscored = { score: null, vector: str, version };
			continue;
		}
		const mnum = str.match(/^\s*(\d+(\.\d+)?)\s*$/); // a bare numeric score ("9.8")
		if (mnum) return { score: parseFloat(mnum[1]), vector: null, version: null };
	}
	return unscored || { score: null, vector: null, version: null };
}

// A distribution's own qualitative rating in severity[] (e.g. { type: "Ubuntu", score: "medium" }).
// Only the four standard bands are taken; "negligible"/"untriaged" stay UNKNOWN.
function qualitativeSeverityFromVuln(vuln) {
	for (const s of vuln.severity || []) {
		if (/^CVSS/i.test(String(s.type || ""))) continue;
		const label = normalizeSeverity(String(s.score || "").trim());
		if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(label)) return label;
	}
	return null;
}

/** Map an OSV vuln to { severity, score }. */
function severityFromOsv(vuln) {
	const direct = vuln.database_specific?.severity;
	const { score } = cvssInfoFromVuln(vuln);
	if (direct) return { severity: normalizeSeverity(direct), score };
	if (score != null) return { severity: severityFromScore(score), score };
	const qualitative = qualitativeSeverityFromVuln(vuln);
	if (qualitative) return { severity: qualitative, score: null };
	return { severity: "UNKNOWN", score: null };
}

function scoreFromVuln(vuln) { return cvssInfoFromVuln(vuln).score; }

/**
 * Pick the fix version to recommend from OSV's affected ranges. A multi-branch advisory
 * (e.g. Tomcat fixed in 9.0.118, 10.1.55 AND 11.0.22) lists one `fixed` per branch — the
 * old code returned the FIRST, which for an 11.0.21 dep meant "upgrade to 9.0.118", i.e. a
 * DOWNGRADE. Instead pick the smallest fix strictly ABOVE the current version: that's the
 * next patched release on the dep's own branch. If none is greater (the branch has no
 * published fix, or the dep is already patched), return null rather than suggest a downgrade.
 */
function fixVersionFromOsv(vuln, depKey, depVersion) {
	const { compareMavenVersions } = require("./maven-version");
	const fixes = [];
	for (const a of vuln.affected || []) {
		const name = a.package?.name?.toLowerCase();
		if (name && name !== depKey.toLowerCase()) continue;
		for (const r of a.ranges || []) {
			for (const ev of r.events || []) {
				if (ev.fixed) fixes.push(String(ev.fixed));
			}
		}
	}
	if (!fixes.length) return null;
	const cmp = (x, y) => { try { return compareMavenVersions(x, y); } catch { return String(x).localeCompare(String(y)); } };
	const sorted = [...fixes].sort(cmp);
	if (!depVersion) return sorted[0]; // no current version to compare against → lowest published fix
	const upgrades = sorted.filter(f => cmp(f, depVersion) > 0);
	return upgrades.length ? upgrades[0] : null;
}

/** The fix on the dep's OWN branch (see maven-version#branchFixFromOsvEvents). → { branchFix } | {} */
function branchFixFromOsv(vuln, depKey, depVersion) {
	if (!depVersion) return {};
	const { branchFixFromOsvEvents } = require("./maven-version");
	for (const a of vuln.affected || []) {
		const name = a.package?.name?.toLowerCase();
		if (name && name !== String(depKey).toLowerCase()) continue;
		for (const r of a.ranges || []) {
			if (r.type && r.type !== "ECOSYSTEM" && r.type !== "SEMVER") continue;
			const f = branchFixFromOsvEvents(String(depVersion), r.events);
			if (f) return { branchFix: f };
		}
	}
	return {};
}

function fixForDependency(dep, vuln, { source } = {}) {
	const maven=dep.ecosystem === 'maven' || dep.ecosystem === 'gradle';
	const ecosystem=osvEcosystemFor(dep);
	if (!maven && !['npm','Go','RubyGems','PyPI','Packagist'].includes(ecosystem)) return {fixVersion:null};
	const {compareSemver,vulnVerdict,rangeVerdict,packageKey}=require('./osv-db');
	const name=osvPkgName(dep);
	const affected=(vuln.affected || []).filter(a=>a?.package?.ecosystem===ecosystem &&
		(maven ? a.package.name===name : packageKey(a.package.name,ecosystem)===packageKey(name,ecosystem)));
	// Use these additional orderings only to verify a proposed remediation.
	const compareVersion = ecosystem === 'PyPI' ? (a,b)=>{
		const pep = require('@renovatebot/pep440');
		if ([a,b].some(v=>typeof v !== 'string' || v.length>255 || /\d{16}/.test(v) || !pep.valid(v))) return null;
		return pep.compare(a,b);
	} : ecosystem === 'Packagist' ? (a,b)=>{
		// Stable Composer tags normalize to four numeric components.
		const numeric = /^[vV]?\d+(?:\.\d+){0,3}$/;
		if ([a,b].some(v=>typeof v !== 'string' || v.length>255 || !numeric.test(v))) return null;
		const parts = v=>v.replace(/^[vV]/,'').split('.').map(BigInt);
		const x=parts(a), y=parts(b);
		for (let i=0;i<4;i++) {
			const left=x[i] ?? 0n, right=y[i] ?? 0n;
			if (left!==right) return left<right ? -1 : 1;
		}
		return 0;
	} : null;
	const compare=maven ? (a,b)=>{
		// Maven's comparator uses Numbers for numeric components. Never replace
		// an indeterminate comparison with lexical ordering or a rounded number.
		if (!a || !b || /\$\{|\d{16}/.test(a) || /\$\{|\d{16}/.test(b)) return null;
		try { return require('./maven-version').compareMavenVersions(a,b); } catch { return null; }
	} : compareVersion || (ecosystem === 'RubyGems' ? require('./ruby-version').compareRubyVersions : compareSemver);
	if (!affected.length || !dep.version || compare(String(dep.version),String(dep.version)) !== 0) return {fixVersion:null};
	const candidates=[];
	for(const a of affected) for(const r of (Array.isArray(a.ranges) ? a.ranges : [])) for(const event of (Array.isArray(r?.events) ? r.events : []))
		if(['ECOSYSTEM','SEMVER'].includes(r.type) && typeof event?.fixed==='string' && compare(event.fixed,String(dep.version)) > 0) candidates.push(event.fixed);
	// Reviewed VV records may prove individual safe versions without proving a
	// continuous range. Never apply this extension to third-party OSV records.
	const exact = new Set();
	if (source === 'vigievuln') for (const a of affected) {
		if (a.database_specific?.vigievuln_partial_versions !== true) continue;
		for (const v of Array.isArray(a.database_specific.unaffected_versions) ? a.database_specific.unaffected_versions : []) {
			if (typeof v === 'string' && compare(v, String(dep.version)) > 0) { candidates.push(v); exact.add(v); }
		}
	}
	candidates.sort((a,b)=>compare(a,b));
	// A negative must cover every applicable entry, not only the entry that
	// supplied the candidate. In particular unknown/conflicting evidence fails.
	const fixed=candidates.find(v=>vulnVerdict(v,{affected},ecosystem,{source,compareVersion})===false) || null;
	const evidence = fixed && exact.has(fixed) ? {fixEvidence:'explicit-unaffected-version'} : {};
	if (!maven || !fixed) return {fixVersion:fixed,...evidence};
	for(const a of affected) for(const r of (Array.isArray(a.ranges) ? a.ranges : [])) {
		if (rangeVerdict(String(dep.version),r,ecosystem)!==true) continue;
		const branch=branchFixFromOsv({affected:[{...a,ranges:[r]}]},name,dep.version).branchFix;
		if (branch?.fixed && compare(branch.fixed,fixed)===0)
			return {fixVersion:fixed,branchFix:{fixed},...evidence};
	}
	// last_affected only names an affected boundary. It does not identify a
	// concrete release whose safety can be checked against all other ranges.
	return {fixVersion:fixed,...evidence};
}

/** Pick the best CVE id from an OSV vuln (prefer CVE-* aliases over GHSA-*). */
function pickPrimaryId(vuln) {
	if (vuln.id?.startsWith("CVE-")) return vuln.id;
	const cveAlias = (vuln.aliases || []).find(a => a.startsWith("CVE-"));
	return cveAlias || vuln.id;
}

// OSV ecosystem name per codec id. OSV.dev natively supports all of these.
const OSV_ECO = { maven: "Maven", npm: "npm", yarn: "npm", nuget: "NuGet", composer: "Packagist", pypi: "PyPI", go: "Go", ruby: "RubyGems" };

/** OSV ecosystem string for a dep, derived from its codec id. */
function osvEcosystemFor(dep) { return OSV_ECO[dep.ecosystem] || "Maven"; }

/** Build the OSV package-name key for a dep — delegated to the dep's codec. */
function osvPkgName(dep) {
	const { getCodec } = require("./codecs");
	const c = getCodec(dep.ecosystem);
	if (c) return c.osvPackageName(dep);
	// Fallback historique si le codec est introuvable.
	return dep.ecosystem === "npm" ? dep.artifactId : `${dep.groupId}:${dep.artifactId}`;
}

/** Convert one OSV vuln to vigievuln match shape. */
function vulnToMatch(dep, vuln, opts = {}) {
	const id = pickPrimaryId(vuln);
	const { severity, score } = severityFromOsv(vuln);
	const cvss = cvssInfoFromVuln(vuln);
	const fix = fixForDependency(dep, vuln, opts);
	// `details` (long markdown) is the substantive description; `summary` is just the title.
	// We keep them both: summary as headline, details as body.
	const summary = (vuln.summary || "").trim();
	const details = (vuln.details || "").trim();
	let description = "";
	if (summary && details && !details.toLowerCase().startsWith(summary.toLowerCase())) {
		description = `${summary}\n\n${details}`;
	} else if (details) {
		description = details;
	} else {
		description = summary;
	}
	// Keep up to 2000 chars — enough for full advisory text without bloating the report.
	if (description.length > 2000) description = description.slice(0, 2000) + "…";
	// Categorise OSV references: ADVISORY / FIX / REPORT / WEB / PACKAGE / ARTICLE / EVIDENCE
	const refs = (vuln.references || []).map(r => ({ type: String(r.type || "WEB").toUpperCase(), url: r.url }));
	const weaknessIds = vuln.database_specific?.cwe_ids;
	const cwes = Array.isArray(weaknessIds) ? [...new Set(weaknessIds
		.filter(id => typeof id === "string" && /^CWE-[1-9]\d*$/i.test(id)).map(id => id.toUpperCase()))] : [];
	return {
		dep,
		cve: {
			id,
			severity,
			score,
			...(cvss.vector ? { cvssVector: cvss.vector } : {}),
			...(cvss.version ? { cvssVersion: `CVSS:${cvss.version}` } : {}),
			description,
			summary,
			...fix,
			fixEvaluation: fix.fixVersion ? 'verified' : 'unknown',
			ghsa: (vuln.aliases || []).find(a => a.startsWith("GHSA-")) || (vuln.id?.startsWith("GHSA-") ? vuln.id : null),
			published: vuln.published || null,
			modified: vuln.modified || null,
			osvRefs: refs,
			...(cwes.length ? {cwes} : {}),
			aliases: id !== vuln.id ? [...new Set([...(vuln.aliases || []), vuln.id])] : vuln.aliases || [],
			sourceAdvisoryId: vuln.id,
		},
		source: "osv",
		confidence: "exact",
	};
}

const validVulnId = id => typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,255}$/.test(id);
function incompleteOsv(message) {
	const error = new Error(`OSV coverage incomplete: ${message}`);
	error.code = "OSV_INCOMPLETE";
	return error;
}

// Preserve the collection time supplied by a proxy instead of presenting a
// stale snapshot as freshly observed. A proxy without a date is unknown-age.
function observation(response) {
	const headers = response?.headers;
	const status = headers?.get?.('x-fad-proxy');
	const stamp = Date.parse(headers?.get?.('x-fad-proxy-fetched-at') || '');
	const isProxy = require('./providers').hasProxyRoute();
	const valid = Number.isFinite(stamp) && stamp > 0 && stamp <= Date.now() + 300000;
	const reason=headers?.get?.('x-fad-proxy-reason'), rawStatus=headers?.get?.('x-fad-proxy-refresh-status'), refreshStatus=/^[45]\d\d$/.test(rawStatus||'') ? Number(rawStatus) : null;
	const refreshFailure=reason==='refresh-failed' || refreshStatus ? {reason:reason==='refresh-failed'?'refresh-failed':'http-error',...(refreshStatus?{status:refreshStatus}:{})} : null;
	return { fetchedAt: valid ? stamp : isProxy ? 1 : Date.now(), stale: status === 'stale' || (isProxy && (!valid || Date.now()-stamp >= require('./cache-policy').DEFAULT_TTL_MS)), ...(refreshFailure?{refreshFailure}:{}) };
}

// querybatch can paginate EACH query independently. An empty object is a valid
// no-findings result; a missing result, an error or an unfinished page is not.
async function fetchBatchPages(batch, fetcher, onFailure) {
	const results = batch.map(() => ({ vulns: [], fetchedAt: Date.now(), stale: false, complete: false }));
	let pending = batch.map((query, index) => ({ query, index, seen: new Set() }));
	while (pending.length) {
		let items, observed;
		try {
			const res = await require("./providers").getResource("osv", "packages", {
				queries: pending.map(({ query }) => ({
					ecosystem: query.package.ecosystem, name: query.package.name, version: query.version,
					...(query.page_token ? { page_token: query.page_token } : {}),
				})),
			}, { fetcher, forceRefresh:true, headers: { "User-Agent": "vigievuln-osv" } });
			if (!res.ok) throw incompleteOsv(`querybatch HTTP ${res.status}`);
			observed = observation(res);
			items = (await res.json())?.results;
			if (!Array.isArray(items) || items.length !== pending.length)
				throw incompleteOsv("querybatch returned a missing or truncated result list");
		} catch (error) {
			onFailure(error.message);
			break;
		}
		const next = [];
		for (let i = 0; i < pending.length; i++) {
			const item = items[i], slot = pending[i], result = results[slot.index];
			if (!item || typeof item !== "object" || Array.isArray(item) || item.error
				|| (item.vulns !== undefined && (!Array.isArray(item.vulns) || !item.vulns.every(v => validVulnId(v?.id))))) {
				onFailure("querybatch returned an invalid result");
				continue;
			}
			result.fetchedAt = Math.min(result.fetchedAt, observed.fetchedAt);
			result.stale ||= observed.stale;
			if (observed.refreshFailure) result.refreshFailure = observed.refreshFailure;
			result.vulns.push(...(item.vulns || []));
			const token = item.next_page_token;
			if (!token) {
				result.complete = true;
			} else if (typeof token !== "string" || slot.seen.has(token) || slot.seen.size >= 1000) {
				onFailure("invalid or repeated pagination token");
			} else {
				slot.seen.add(token);
				next.push({ ...slot, query: { ...slot.query, page_token: token } });
			}
		}
		pending = next;
	}
	return results;
}

function staleSeverity(observation, offline, maxAgeMs) {
	const p=observation?.provenance||observation||{};
	const failure=p.refreshFailure || p.refreshError || p.error || Number(p.status)>=400 || p.reason==='refresh-failed';
	const date=Number(observation?.fetchedAt), policyExceeded=Number.isFinite(maxAgeMs) && maxAgeMs>=0 && (!Number.isFinite(date) || date<=1 || date>Date.now() || Date.now()-date>maxAgeMs);
	return !failure && !policyExceeded ? 'info' : undefined;
}
async function queryBatch(deps, opts = {}) {
	if (!deps.length) return [];
	const { offline, fetcher = globalThis.fetch, onProgress, onWarning, queryTtlMs = 4 * 3600 * 1000 } = opts;
	const root = opts.cacheDir || require('./cache-directory').getCacheDir();
	const store = opts.store || require('./advisory-store').openAdvisoryStore({cacheDir:root});
	try {
	const tuple = d => ({source:'osv', ecosystem:osvEcosystemFor(d), name:osvPkgName(d), version:String(d.version).trim()});
	const views = [], pending = [], output = new Array(deps.length), warnings = [], reviewedFreshnessNotices = new Set();
	const partial = new Map();
	const warn = (type, message, severity) => warnings.push({type,message,...(severity ? {severity} : {})});
	for (let i=0; i<deps.length; i++) {
		const q=tuple(deps[i]);
		const view=store.getPackageView(q,{ttlMs:queryTtlMs});
		views[i]=view;
		if (!offline && (opts.forceUpdate || require('./cache-policy').shouldForceUpdate() || !view.query || !view.query.fresh || view.querySuperseded)) pending.push({index:i, tuple:q});
	}
	if (pending.length) {
	  try {
		const fetched=[];
		const reportFailure = message => {
			if (!opts.allowStaleFallback) throw incompleteOsv(message);
			warn('source-unavailable', `OSV: refresh failed; coverage is incomplete (${message}).`);
		};
		for (let i=0;i<pending.length;i+=BATCH_SIZE) {
			if (onProgress) onProgress(Math.floor(i/BATCH_SIZE)+1,Math.ceil(pending.length/BATCH_SIZE));
			const part=pending.slice(i,i+BATCH_SIZE);
			const results=await fetchBatchPages(part.map(({tuple:q})=>({package:{ecosystem:q.ecosystem,name:q.name},version:q.version})),fetcher,reportFailure);
			fetched.push(...results);
		}
		const ids=[...new Set(fetched.flatMap(x=>x.vulns.map(v=>v.id)))], details=new Map(), failures=[];
		let cursor=0,done=0;
		await Promise.all(Array.from({length:Math.min(10,ids.length)},async()=>{
			while(cursor<ids.length) {
				const id=ids[cursor++];
				try {
					const existing=store.getRecord('osv',id);
					if (existing?.provenance?.origin === require('./providers').resourceOrigin() && !existing.provenance.stale && !existing.document?.withdrawn && existing.fetchedAt > 0 && existing.fetchedAt <= Date.now() && require('./record-freshness').stableRecord('osv',existing.document,opts)) { details.set(id,{body:existing.document,fetchedAt:existing.fetchedAt,stale:false,reusedStable:true}); if(onProgress)onProgress(++done,ids.length); continue; }
					const r=await require('./providers').getResource('osv','vuln',{id},{fetcher,forceRefresh:true,headers:{'User-Agent':'vigievuln-osv'}});
					if (!r.ok) throw Error(`HTTP ${r.status}`);
					const body=await r.json(); if (body?.id!==id) throw Error('invalid advisory detail');
					details.set(id,{body,...observation(r)});
				} catch(error) { failures.push(`${id}: ${error.message}`); }
				if(onProgress)onProgress(++done,ids.length);
			}
		}));
		if (failures.length) reportFailure(`${failures.length} advisory detail(s) unavailable (${failures.sort()[0]})`);
		const transport=require('./providers').hasProxyRoute()?'proxy':'direct';
		const records=[...details.values()].filter(d=>!d.reusedStable).map(d=>({source:'osv',document:d.body,fetchedAt:d.fetchedAt,provenance:{transport,origin:require('./providers').resourceOrigin(),stale:d.stale,...(d.refreshFailure?{refreshFailure:d.refreshFailure}:{})}}));
		// Keep revision evidence independently of the write transaction: a full
		// disk must not allow an older API payload to resurrect a known withdrawal.
		const existingRecords=new Map(ids.map(id=>[id,store.getRecord('osv',id)]));
		const incomingRecords=new Map(records.map(record=>[record.document.id,record]));
		const queries=[];
		for(let i=0;i<pending.length;i++) {
			const entry=pending[i], result=fetched[i], ids=[...new Set(result.vulns.map(v=>v.id))];
			const verifiedIds = ids.filter(id => details.has(id));
			const relevant=verifiedIds.map(id=>details.get(id));
			const fetchedAt=Math.min(result.fetchedAt,...relevant.filter(d=>!d.reusedStable).map(d=>d.fetchedAt));
			const stale=result.stale || relevant.some(d=>d.stale);
			const refreshFailure=result.refreshFailure || relevant.find(d=>d.refreshFailure)?.refreshFailure;
			const documentHashes=Object.fromEntries(verifiedIds.map(id=>[id,require('node:crypto').createHash('sha256').update(JSON.stringify(details.get(id).body)).digest('hex')]));
			queries.push({...entry.tuple,ids:verifiedIds,fetchedAt,complete:result.complete && verifiedIds.length === ids.length,provenance:{transport,stale,...(refreshFailure?{refreshFailure}:{}),documentHashes}});
		}
		try {
			// A query is committed only after all its details are durable. Partial
			// failure leaves no new evidence of a clean package.
			if(records.length)await store.importEnvelopes(records);
			const completeQueries = queries.filter(q => q.complete);
			for(let i=0;i<completeQueries.length;i+=200)store.commit({queries:completeQueries.slice(i,i+200)});
		} catch(error) {warn('source-unavailable',`OSV: live results could not be saved for offline use (${error.message}).`);}
		const {vulnVerdict,packageKey}=require('./osv-db');
		for(let i=0;i<pending.length;i++) {
			const entry=pending[i],query=queries[i],found=[];
			let savedView=views[entry.index];
			try { savedView=store.getPackageView(entry.tuple,{ttlMs:queryTtlMs}); }
			catch(error) { warn('source-unavailable',`OSV: saved consultation could not be reread (${error.message}); previously read evidence is retained.`); }
			if(savedView.query && savedView.query.fetchedAt>query.fetchedAt) {
				views[entry.index]=savedView;
				if (!savedView.query.fresh) warn('source-stale',`OSV: the response for ${entry.tuple.name}@${entry.tuple.version} predates its saved consultation; newer local evidence is used.`);
				continue;
			}
			if(query.provenance.stale)warn('source-stale',`OSV: the source response was stale or its collection date is unknown for ${entry.tuple.name}@${entry.tuple.version}.`,staleSeverity(query,offline,opts.maxAdvisoryAgeMs));
			for(const id of query.ids) {
				const fetched=details.get(id).body;
				let existing=existingRecords.get(id);
				try { existing=store.getRecord('osv',id) || existing; }
				catch(error) { warn('source-unavailable',`OSV: saved revision of ${id} could not be reread (${error.message}); previously read revision evidence is retained.`); }
				const winner=require('./advisory-store').selectAdvisoryRecord(incomingRecords.get(id) || existing,existing).document;
				if(winner.withdrawn)continue;
				if(JSON.stringify(winner)!==JSON.stringify(fetched)) {
					const relevant=(winner.affected || []).filter(a=>a?.package?.ecosystem===entry.tuple.ecosystem && (entry.tuple.ecosystem === 'Maven' ? a.package.name === entry.tuple.name : packageKey(a.package.name,entry.tuple.ecosystem)===packageKey(entry.tuple.name,entry.tuple.ecosystem)));
					const verdict=relevant.length ? vulnVerdict(entry.tuple.version,{...winner,affected:relevant},entry.tuple.ecosystem) : null;
					if(verdict===null) {warn('osv-coverage',`OSV: a newer revision of ${id} cannot be evaluated for ${entry.tuple.name}@${entry.tuple.version}.`);continue;}
					if(!verdict)continue;
				}
				found.push(vulnToMatch(deps[entry.index],winner));
			}
			if (query.complete) {
				output[entry.index] = found;
				if (!query.provenance.stale) opts.onConsulted?.(deps[entry.index], 'osv');
			}
			else {
				// Retain verified live matches. Consult previous evidence only for
				// details or pages the source could not supply during this refresh.
				partial.set(entry.index, { found, verified: new Set(query.ids),
					listed: fetched[i].complete ? new Set(fetched[i].vulns.map(v => v.id)) : null });
			}
		}
	  } catch(error) {
		if (!opts.allowStaleFallback) throw error;
		warn('source-unavailable',`OSV: refresh failed; cached advisories are used with incomplete coverage (${error.message}).`);
	  }
	}
	const {vulnVerdict,packageKey}=require('./osv-db');
	const unverified = new Map();
	const undecidable = [];
	for(let i=0;i<deps.length;i++) {
		if(output[i])continue;
		const d=deps[i],q=tuple(d),view=views[i], query=view.query;
		if (query && !query.fresh)
			warn('source-stale',`OSV: package/version consultation for ${q.name}@${q.version} is ${query.fetchedAt>1 ? `from ${new Date(query.fetchedAt).toISOString()}` : 'of unknown age'}.`,staleSeverity(query,offline,opts.maxAdvisoryAgeMs));
		if (!query && (!view.coverage?.complete || opts.useStoredRanges === false)) {
			if (!unverified.has(q.ecosystem)) unverified.set(q.ecosystem, new Set());
			unverified.get(q.ecosystem).add(`${q.name}@${q.version}`);
		}
		// An exact consultation already covers the package/version. When a
		// newer advisory supersedes it, evaluate that advisory below; the age
		// of an unrelated older catalogue does not make the query stale.
		if (view.coverage && !view.coverage.fresh && !query) warn('source-stale',`OSV: ${q.ecosystem} seed is ${view.coverage.fetchedAt>1 ? `from ${new Date(view.coverage.fetchedAt).toISOString()}` : 'of unknown age'}.`,staleSeverity(view.coverage,offline,opts.maxAdvisoryAgeMs));
		const unknownBefore = undecidable.length;
		const live = partial.get(i);
		const ids=new Set(query?.ids || []), found=live?.found || []; let unknown=false;
		for(const item of view.records) {
			const v=item.document;if(v.withdrawn)continue;
			if (live && (live.verified.has(v.id) || (live.listed && !live.listed.has(v.id)))) continue;
			if(item.source==='osv-legacy-maven')warn('osv-coverage',`OSV: legacy Maven advisory ${v.id} is partial; its withdrawal status is unknown.`);
			let affected;
			if(query && require('./advisory-store').queryCoversRecord(query,item)) affected=ids.has(v.id);
			else if(opts.useStoredRanges === false) { unknown=true; continue; }
			else {
				const relevant=(v.affected || []).filter(a=>a?.package?.ecosystem===q.ecosystem && (q.ecosystem === 'Maven' ? a.package.name === q.name : packageKey(a.package.name,q.ecosystem)===packageKey(q.name,q.ecosystem)));
				affected=relevant.length ? vulnVerdict(q.version,{...v,affected:relevant},q.ecosystem) : ids.has(v.id) ? true : false;
			}
			if (affected === null) undecidable.push({id:v.id, package:q.name, version:q.version, reason:'OSV version range cannot be evaluated.'});
			else if (affected) found.push(vulnToMatch(d,v));
		}
		if(unknown)warn('osv-coverage',`OSV: at least one advisory for ${q.name}@${q.version} requires a verified package/version consultation with stored range matching disabled.`);
		const proof = query || (opts.useStoredRanges !== false && view.coverage);
		if (!live && !unknown && undecidable.length === unknownBefore && proof?.complete && !proof.provenance?.stale &&
			!proof.provenance?.refreshFailure && (offline || proof.fresh)) opts.onConsulted?.(d,'osv');
		output[i]=found;
	}
	if (undecidable.length) onWarning?.(require('./diagnostics').advisoryEvidenceDiagnostic(undecidable));
	for(const [ecosystem,packages] of unverified) {
		const examples=[...packages].slice(0,3).join(', ');
		warn('osv-coverage',`OSV: ${offline ? 'offline ' : ''}coverage is incomplete for ${packages.size} ${ecosystem} package/version(s) without a verified consultation (${examples}${packages.size>3?', …':''}). Available advisory ranges were still matched; no finding does not prove those versions clean.`);
	}
	// VigieVuln's reviewed advisories are an independent source in the local
	// advisory journal. They remain available offline and never inherit OSV's
	// coverage claims or source identity.
	for(let i=0;i<deps.length;i++) {
		const d=deps[i],q=tuple(d);
		const ownQuery=store.getQuery({source:'vigievuln',ecosystem:q.ecosystem,name:q.name,version:'*'},{ttlMs:queryTtlMs});
		const ownKey=`${q.ecosystem}\0${q.name}`;
		if(ownQuery&&!ownQuery.fresh&&!reviewedFreshnessNotices.has(ownKey)){reviewedFreshnessNotices.add(ownKey);const severity=staleSeverity(ownQuery,offline,opts.maxAdvisoryAgeMs);onWarning?.({type:'source-stale',...(severity?{severity}:{}),message:`VigieVuln: reviewed advisory consultation for ${q.name} is from ${new Date(ownQuery.fetchedAt).toISOString()}.`});}
		for(const item of store.getPackageRecords(q.ecosystem,q.name,{source:'vigievuln'})) {
			const v=item.document;
			if(v.withdrawn)continue;
			if(!require('./vigievuln-advisories').isCurrentForPackage(store,q,item))continue;
			const relevant=(v.affected||[]).filter(a=>a?.package?.ecosystem===q.ecosystem && typeof a.package.name==='string' && (q.ecosystem==='Maven' ? a.package.name===q.name : packageKey(a.package.name,q.ecosystem)===packageKey(q.name,q.ecosystem)));
			const verdict=relevant.length ? vulnVerdict(q.version,{...v,affected:relevant},q.ecosystem,{source:'vigievuln'}) : null;
			if(verdict===null && relevant.length) warn('source-unavailable',`VigieVuln: ${v.id} has only partial version evidence for ${q.name}@${q.version}.`);
			if(verdict===true){
				const match=vulnToMatch(d,v,{source:'vigievuln'});match.source='vigievuln';if(/^VV:CVE-\d{4}-\d{4,}$/.test(v.id||''))match.cve.aliases=[...new Set([...match.cve.aliases,v.id])];match.cve.curation=relevant[0]?.database_specific?.vigievuln_curation || v.curation;
				output[i].push(match);
			}
		}
	}
	for(const warning of warnings)if(warning.type!=='source-stale')onWarning?.(warning);
	for(const severity of [undefined,'info']) {
	const staleWarnings=warnings.filter(w=>w.type==='source-stale' && w.severity===severity);
	if(severity==='info' && staleWarnings.length) {
		const dates=staleWarnings.flatMap(w=>w.message.match(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/g)||[]).sort();
		const oldestFetchedAt=dates[0]||null, unknownAgeCount=staleWarnings.filter(w=>w.message.includes('unknown age')).length;
		onWarning?.({type:'cache-freshness',severity:'info',source:'osv',count:staleWarnings.length,oldestFetchedAt,unknownAgeCount,queryTtlMs,
			message:`OSV: saved consultations were used${offline ? ' offline' : ''}${oldestFetchedAt ? `; oldest known collection ${oldestFetchedAt}` : ''}${unknownAgeCount ? '; some collection dates are unknown' : ''}.`});
	} else if(staleWarnings.length===1)onWarning?.(staleWarnings[0]);
	else if(staleWarnings.length>1) {
		const dates=staleWarnings.flatMap(w=>w.message.match(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/g)||[]).sort();
		const age=dates.length ? ` Oldest saved data: ${dates[0]}.` : '';
		const older=staleWarnings.some(w=>w.message.includes('predates')) ? ' A response predates a newer saved consultation.' : '';
		onWarning?.({type:'source-stale',message:`OSV: ${staleWarnings.length} freshness notices; cached advisory data is used${offline ? ' offline' : ''}.${age}${older}`});
	}
	}
	return output.flat();
	} finally { if (!opts.store) store.close(); }
}

/** Reviewed-source matching also works when OSV is explicitly disabled. */
function queryReviewedForDeps(resolvedDeps,opts={}) {
	const store=opts.store||require('./advisory-store').openAdvisoryStore({cacheDir:opts.cacheDir||require('./cache-directory').getCacheDir()});
	try {
	const {vulnVerdict,packageKey}=require('./osv-db');const matches=[],warned=new Set();
	for(const d of resolvedDeps.values()) {
		if(!d || d.scope==='parent' || d.provenance==='binary')continue;
		const ecosystem=osvEcosystemFor(d),name=osvPkgName(d);if(!name)continue;
		const ownQuery=store.getQuery({source:'vigievuln',ecosystem,name,version:'*'},{ttlMs:opts.queryTtlMs ?? 4 * 3600000});
		if(ownQuery&&!ownQuery.fresh&&!warned.has(`${ecosystem}\0${name}`)){warned.add(`${ecosystem}\0${name}`);const severity=staleSeverity(ownQuery,opts.offline,opts.maxAdvisoryAgeMs);opts.onWarning?.({type:'source-stale',...(severity?{severity}:{}),message:`VigieVuln: reviewed advisory consultation for ${name} is from ${new Date(ownQuery.fetchedAt).toISOString()}.`});}
		for(const version of d.versions?.length?d.versions:[d.version]) {
			if(!version||/\$\{|SNAPSHOT/i.test(version))continue;
			for(const item of store.getPackageRecords(ecosystem,name,{source:'vigievuln'})) {
				if(item.document.withdrawn || !require('./vigievuln-advisories').isCurrentForPackage(store,{ecosystem,name},item))continue;
				const relevant=(item.document.affected||[]).filter(a=>a?.package?.ecosystem===ecosystem && typeof a.package.name==='string' && (ecosystem==='Maven'?a.package.name===name:packageKey(a.package.name,ecosystem)===packageKey(name,ecosystem)));
				if(!relevant.length)continue;
				const verdict=vulnVerdict(String(version),{...item.document,affected:relevant},ecosystem,{source:'vigievuln'});
				if(verdict===null)opts.onWarning?.({type:'source-unavailable',message:`VigieVuln: ${item.document.id} has only partial version evidence for ${name}@${version}.`});
				if(verdict===true){const dep=version===d.version?d:{...d,version};const match=vulnToMatch(dep,item.document,{source:'vigievuln'});match.source='vigievuln';if(/^VV:CVE-\d{4}-\d{4,}$/.test(item.document.id||''))match.cve.aliases=[...new Set([...match.cve.aliases,item.document.id])];match.cve.curation=relevant[0]?.database_specific?.vigievuln_curation || item.document.curation;matches.push(match);}
			}
		}
	}
	return matches;
	} finally { if (!opts.store) store.close(); }
}

/**
 * Public: query OSV for every dep in `resolvedDeps` Map, return vigievuln-shape matches.
 */
async function queryOsvForDeps(resolvedDeps, opts = {}) {
	const deps = [];
	for (const d of resolvedDeps.values()) {
		if (d.scope === "parent" || d.provenance === 'binary') continue; // native metadata is not an authenticated package identity
		// Query every distinct concrete version (e.g. two profiles pinning the
		// same g:a), not just the representative highest — otherwise a vuln that
		// only affects a lower-versioned variant would be missed.
		const versions = (d.versions && d.versions.length) ? d.versions : [d.version];
		for (const ver of versions) {
			if (!ver || /\$\{|SNAPSHOT/i.test(ver)) continue;
			// npm version specifiers like "^1.0.0" can't be queried against OSV —
			// need a concrete version. Lockfiles always provide one; package.json-
			// only deps are skipped here.
			if (d.ecosystem === "npm" && /^[\^~>=<*]|^(latest|next|workspace:|git\+|file:|link:)/.test(ver)) continue;
			// Spread the whole depRecord (carries namespace/name/coordKey, which the
			// codec's osvPackageName + the report's dedup rely on) and override only
			// the version for this per-version query. Cherry-picking fields here used
			// to drop name/namespace → OSV queried `undefined` for composer/pypi/nuget.
			deps.push({ ...d, version: ver });
		}
	}
	return queryBatch(deps, opts);
}

module.exports = {
	queryReviewedForDeps,
	cacheKey,
	queryOsvForDeps,
	queryBatch,
	vulnToMatch,
	severityFromOsv,
	fixVersionFromOsv,
	osvEcosystemFor,
	osvPkgName,
	OSV_CACHE_DIR,
};
