/**
 * lib/snyk.js — optional Snyk integration.
 *
 * Runs `snyk test --all-projects --json` on the cleaned POM directory and
 * normalises the output to vigievuln's CVE match shape so the report can
 * merge findings from both engines.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

/**
 * Run `snyk test --all-projects --json` in outputDir.
 * Snyk exits with code 1 when vulnerabilities are found — that's not an
 * error for us, so we accept exit codes 0 and 1.
 */
async function runSnykTest(outputDir, opts = {}) {
	const { verbose, timeoutMs = 10 * 60 * 1000 } = opts;
	if (!outputDir) throw new Error("runSnykTest: outputDir required");
	try {
		const { stdout } = await execFileP("snyk", ["test", "--all-projects", "--json"], {
			cwd: outputDir,
			maxBuffer: 256 * 1024 * 1024,
			timeout: timeoutMs,
		});
		return parseSnykStdout(stdout);
	} catch (err) {
		if (err.code === "ENOENT") throw new Error("snyk CLI not found on PATH — install snyk separately");
		if (err.killed) throw new Error(`snyk timed out after ${Math.round(timeoutMs / 1000)}s (raise opts.timeoutMs)`);
		// snyk exits 1 when vulnerabilities are found — stdout holds the real findings
		// JSON, so that's NOT a failure. BUT exit 2 (command error, e.g. auth) and
		// exit 3 (no supported projects) ALSO write JSON to stdout, shaped
		// { ok:false, error:"…" }. Returning that as-is makes parseSnykResults read it
		// as "0 vulnerabilities" → a silent success that hides a real snyk failure.
		if (err.stdout) {
			const parsed = parseSnykStdout(err.stdout);
			const snykErr = snykOutputError(parsed);
			if (snykErr) throw new Error(`snyk failed (exit ${err.code}): ${snykErr}`);
			return parsed;
		}
		// No JSON on stdout at all → surface stderr (the human-readable reason) rather
		// than execFile's generic "Command failed: snyk test…".
		const detail = (err.stderr && String(err.stderr).trim()) || err.message;
		throw new Error(`snyk failed (exit ${err.code}): ${detail}`);
	}
}

/**
 * Inspect parsed `snyk --json` output and return a human-readable error string when
 * snyk actually FAILED — i.e. every project is an error stub ({ ok:false, error }) and
 * none carries usable results — or `null` when the output holds real findings.
 *
 * Snyk emits this error-shaped JSON on stdout for exit 2 (command error, e.g. auth) and
 * exit 3 (no supported projects). Without this check those are read as "0 vulnerabilities",
 * silently hiding the failure behind a green "Snyk: 0 findings merged".
 */
function snykOutputError(parsed) {
	const projects = Array.isArray(parsed) ? parsed : (parsed != null ? [parsed] : []);
	if (!projects.length) return null;
	// A usable project either lists vulnerabilities (exit 1) or reports ok:true (clean).
	const usable = projects.some(p => p && (Array.isArray(p.vulnerabilities) || p.ok === true));
	if (usable) return null;
	const errored = projects.filter(p => p && p.ok === false && p.error);
	if (!errored.length) return null;
	return [...new Set(errored.map(p => String(p.error).trim()).filter(Boolean))].join("; ");
}

function parseSnykStdout(stdout) {
	if (!stdout) return [];
	const str = String(stdout).trim();
	if (!str) return [];
	// --all-projects can produce either a JSON array of project results
	// or a single object. Normalise to array.
	try {
		const parsed = JSON.parse(str);
		return Array.isArray(parsed) ? parsed : [parsed];
	} catch (_) {
		// Some snyk versions emit one JSON object per line.
		const lines = str.split(/\n+/).filter(Boolean);
		const out = [];
		for (const l of lines) {
			try { out.push(JSON.parse(l)); } catch { /* skip */ }
		}
		return out;
	}
}

/**
 * Normalise snyk JSON to vigievuln match objects:
 *   [{ dep: {groupId, artifactId, version}, cve: {id, severity, score, ...}, source: 'snyk' }]
 */
function parseSnykResults(snykProjectsJson) {
	const out = [];
	const projects = Array.isArray(snykProjectsJson) ? snykProjectsJson : [snykProjectsJson];
	for (const proj of projects) {
		const vulns = proj?.vulnerabilities || [];
		for (const v of vulns) {
			const pkg = v.packageName || v.moduleName || "";
			const [groupId, artifactId] = pkg.includes(":") ? pkg.split(":") : [null, pkg];
			const cveIds = v.identifiers?.CVE || [];
			const cveId = cveIds[0] || v.id;
			const fixVersions = Array.isArray(v.fixedIn) ? v.fixedIn : [];
			out.push({
				dep: {
					groupId: groupId || "",
					artifactId: artifactId || "",
					version: v.version || "",
					scope: "compile",
					pomPaths: [],
				},
				cve: {
					id: cveId,
					severity: (v.severity || "UNKNOWN").toUpperCase(),
					score: typeof v.cvssScore === "number" ? v.cvssScore : null,
					description: v.title || v.description || "",
					fixVersion: fixVersions[0] || null,
				},
				source: "snyk",
				confidence: "exact",
			});
		}
	}
	return out;
}

/**
 * Merge vigievuln and Snyk matches, deduping by (groupId:artifactId, cve.id).
 * When a finding exists in both, vigievuln's row is kept but tagged source='both'.
 */
function mergeWithFadResults(fadMatches, snykMatches) {
	const byKey = new Map();
	const k = m => `${m.dep.groupId}:${m.dep.artifactId}|${m.cve.id}`;
	for (const m of fadMatches || []) byKey.set(k(m), { ...m, source: "fad" });
	for (const s of snykMatches || []) {
		const key = k(s);
		if (byKey.has(key)) {
			const existing = byKey.get(key);
			byKey.set(key, { ...existing, source: "both" });
		} else {
			byKey.set(key, s);
		}
	}
	const merged = [...byKey.values()];
	// Re-sort by severity (Snyk additions throw off ordering)
	const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, UNKNOWN: 0 };
	merged.sort((a, b) => {
		const sa = rank[(a.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		const sb = rank[(b.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		if (sb !== sa) return sb - sa;
		return (a.cve.id || "").localeCompare(b.cve.id || "");
	});
	return merged;
}

module.exports = {
	runSnykTest,
	parseSnykResults,
	parseSnykStdout,
	snykOutputError,
	mergeWithFadResults,
};
