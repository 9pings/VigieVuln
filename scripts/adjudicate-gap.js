#!/usr/bin/env node
/**
 * scripts/adjudicate-gap.js — measure how much of a claimed recall gap is actually real.
 *
 *   node scripts/adjudicate-gap.js pairs.json
 *   node scripts/adjudicate-gap.js --snyk snyk-test.json
 *
 * Input is a list of (Maven coordinate, version, vulnerability id) another scanner
 * reported and vigievuln did not. Each id is resolved against the live OSV API — its
 * aliases too, since a `SNYK-*` or `GHSA-*` id may be the only handle you have — and the
 * pair is adjudicated by `lib/gap-adjudicate` using the scanner's own range evaluation.
 *
 * Why this exists. A benchmark's "misses" list is not a recall backlog. Treating it as
 * one, and widening the matcher until it empties, is precisely how a scanner acquires
 * mass false positives: most of what another tool reports and this one doesn't is either
 * unreachable from public data or the other tool disagreeing with the public record.
 * Only CONFIRMED_MISS is worth engineering against. Run this first, fix those, re-run.
 *
 * Nothing static ships: no vulnerability fixture, no curated answer key. The authority is
 * whatever OSV says on the day you ask, which is also what a re-run has to reproduce.
 *
 * Input formats
 *   generic: [{ "coord": "g:a", "version": "1.2.3", "ids": ["CVE-…", "GHSA-…"] }, …]
 *   --snyk : `snyk test --json` output; reads vulnerabilities[].{packageName,version,identifiers}
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const pLimit = require("p-limit");
const { classifyPair, summarize, mergeRecords, reconcileFound, foundKey, VERDICT } = require("../lib/gap-adjudicate");

const OSV_API = "https://api.osv.dev/v1/vulns/";

function usage(msg) {
	if (msg) console.error(`error: ${msg}\n`);
	console.error(`usage: node scripts/adjudicate-gap.js [--snyk] <pairs.json> [--json out.json]

  <pairs.json>   [{ coord, version, ids: [...] }, ...]
  --snyk         read \`snyk test --json\` output instead
  --found <f>    fad's findings.json — drops pairs it already reports under an alias
  --json <file>  also write the per-pair verdicts

Verdicts: CONFIRMED_MISS (the real gap) · OUT_OF_RANGE / WRONG_ARTIFACT (the other tool
disagrees with the public record) · NO_MAVEN_BINDING / NOT_IN_OSV (unreachable from OSV).`);
	process.exit(msg ? 2 : 0);
}

/** Snyk's JSON → our generic shape. Defensive: skip anything without a usable coordinate. */
function fromSnyk(doc) {
	const projects = Array.isArray(doc) ? doc : [doc];
	const out = [];
	for (const p of projects) {
		for (const v of p.vulnerabilities || []) {
			const coord = v.packageName || v.moduleName || v.name;
			const version = v.version;
			if (!coord || !version || !String(coord).includes(":")) continue;   // Maven only
			const ids = [v.id, ...(v.identifiers?.CVE || []), ...(v.identifiers?.GHSA || [])].filter(Boolean);
			out.push({ coord, version, ids: [...new Set(ids)] });
		}
	}
	return out;
}

/**
 * OSV answers an unknown id with 404 — but when it knows the vulnerability under another
 * id it says so in the body: {"code":5,"message":"Vulnerability not found, but the
 * following aliases were: GHSA-…"}. Treating every non-OK response as "no record" throws
 * that away and mislabels a perfectly public advisory as proprietary.
 */
function aliasHint(body) {
	const m = /aliases were:\s*(.+)$/.exec(String(body && body.message || ""));
	return m ? m[1].split(/[,\s]+/).map(x => x.trim()).filter(Boolean) : [];
}

async function fetchVuln(id, fetcher) {
	try {
		const res = await fetcher(OSV_API + encodeURIComponent(id));
		if (res && res.ok) return await res.json();
		if (res && res.status === 404) {
			const hinted = aliasHint(await res.json().catch(() => null));
			for (const alt of hinted) {
				const r2 = await fetcher(OSV_API + encodeURIComponent(alt));
				if (r2 && r2.ok) return await r2.json();
			}
		}
		return null;
	} catch { return null; }   // one id failing must not decide the verdict for the pair
}

/**
 * Collect the WHOLE public record for a vulnerability, not the first record that answers.
 * OSV keeps the CVE-converted entry (frequently a GIT commit range and nothing else) and
 * the GHSA entry that binds it to Maven as separate documents linked by `aliases`; take
 * one hop through them and merge, or a bound advisory reads as "no ecosystem binding".
 * A proprietary id simply 404s everywhere — null is a verdict, not an error.
 */
async function resolve(ids, fetcher = fetch) {
	const seen = new Map();
	for (const id of ids) if (!seen.has(id)) seen.set(id, await fetchVuln(id, fetcher));
	const aliases = [...seen.values()].filter(Boolean).flatMap(r => r.aliases || []);
	for (const id of aliases) if (!seen.has(id)) seen.set(id, await fetchVuln(id, fetcher));
	return mergeRecords([...seen.values()]);
}

async function main() {
	const argv = process.argv.slice(2);
	if (!argv.length || argv.includes("-h") || argv.includes("--help")) usage();
	const snyk = argv.includes("--snyk");
	const foundAt = argv.indexOf("--found");
	const jsonAt = argv.indexOf("--json");
	const jsonOut = jsonAt >= 0 ? argv[jsonAt + 1] : null;
	const consumed = new Set([jsonAt + 1, foundAt + 1].filter(i => i > 0));
	const file = argv.find((a, i) => !a.startsWith("--") && !consumed.has(i));
	if (!file) usage("no input file");

	let doc;
	try { doc = JSON.parse(fs.readFileSync(file, "utf8")); }
	catch (e) { usage(`cannot read ${file}: ${e.message}`); }

	const pairs = snyk ? fromSnyk(doc) : doc;
	if (!Array.isArray(pairs) || !pairs.length) usage("no pairs to adjudicate");

	const limit = pLimit(8);   // OSV is generous but this is not a load test
	let done = 0;
	const rows = await Promise.all(pairs.map(p => limit(async () => {
		const rec = await resolve(p.ids || [p.id].filter(Boolean));
		const row = classifyPair(p, rec);
		if (++done % 25 === 0) process.stderr.write(`  ${done}/${pairs.length}\r`);
		return row;
	})));

	// A vulnerability carries a CVE and several aliased GHSA ids; if the two sides picked
	// different ones, a pair the scanner DID report looks missing. Reconcile before counting.
	let finalRows = rows;
	if (foundAt >= 0 && argv[foundAt + 1]) {
		const doc = JSON.parse(fs.readFileSync(argv[foundAt + 1], "utf8"));
		const set = new Set();
		for (const f of doc.cve || []) {
			const dep = f.dep || {};
			if (!dep.coord || !dep.version) continue;
			for (const id of [f.id, ...(f.aliases || [])].filter(Boolean)) set.add(foundKey(dep.coord, dep.version, id));
		}
		finalRows = reconcileFound(rows, set);
	}
	const rowsOut = finalRows;
	const s = summarize(rowsOut);
	const pct = n => `${((n / s.total) * 100).toFixed(1)}%`;
	console.log(`\nadjudicated ${s.total} claimed miss(es) against OSV\n`);
	for (const v of Object.values(VERDICT)) {
		const n = s.counts[v] || 0;
		if (n) console.log(`  ${String(n).padStart(5)}  ${pct(n).padStart(6)}  ${v}`);
	}
	console.log(`\n  REAL GAP: ${s.realGap} of ${s.total} (${pct(s.realGap)}) — these are worth engineering against.`);
	console.log(`  The rest is unreachable from public data, or the other tool disagreeing with it.\n`);

	for (const r of rowsOut.filter(r => r.verdict === VERDICT.CONFIRMED_MISS)) {
		console.log(`  CONFIRMED  ${r.id}  ${r.coord}@${r.version}`);
	}
	if (jsonOut) {
		fs.writeFileSync(jsonOut, JSON.stringify({ summary: s, rows: rowsOut }, null, 2));
		console.log(`\n  → ${jsonOut}`);
	}
	process.exitCode = 0;
}

if (require.main === module) main().catch(e => { console.error(e); process.exit(1); });
module.exports = { fromSnyk, resolve, aliasHint };
