/**
 * Coverage is a record of checks performed, independent of their findings.
 * A missing source or unknown version can never become a reassuring no-match.
 */
const EXECUTIONS = new Set(["completed", "partial", "not-run", "failed", "not-applicable"]);
const RESULTS = new Set(["affected", "no-match", "indeterminate", "not-applicable"]);

// A private component, or one the public catalogue does not know, is treated like a
// private package of any other ecosystem: it is listed as private, not as a failed check.
const PRIVATE_DIAGNOSTICS = new Set(["CMS_PRIVATE_COMPONENT", "CMS_PROVIDER_COMPONENT_UNKNOWN"]);
const isPrivateCheck = check => PRIVATE_DIAGNOSTICS.has(check?.diagnostic);

function createCoverage() {
	const records = [];
	const keys = new Set();
	return {
		records,
		record(input) {
			if (!input || !input.applicationId || !input.capability) throw new Error("coverage requires applicationId and capability");
			const { execution, result } = input;
			if (!EXECUTIONS.has(execution)) throw new Error(`invalid coverage execution: ${execution}`);
			if (!RESULTS.has(result)) throw new Error(`invalid coverage result: ${result}`);
			if (result === "no-match" && execution !== "completed") throw new Error("no-match requires a completed check");
			if (execution === "not-applicable" && result !== "not-applicable") throw new Error("not-applicable execution requires not-applicable result");
			if ((execution === "failed" || execution === "not-run") && result === "affected") throw new Error("an unexecuted check cannot establish affected");
			const expected = input.expected ?? 0;
			const executed = input.executed ?? 0;
			if (![expected, executed].every(n => Number.isSafeInteger(n) && n >= 0)) throw new Error("coverage counts must be nonnegative integers");
			if (execution === "completed" && executed < expected) throw new Error("completed check has fewer executions than expected");
			const key = [input.applicationId, input.occurrenceId || "", input.capability, input.sourceId || ""].join("\0");
			if (keys.has(key)) throw new Error("duplicate coverage check");
			keys.add(key);
			const entry = { ...input, expected, executed, ...(isPrivateCheck(input) ? { affectsCompleteness: false } : {}) };
			records.push(entry);
			return entry;
		},
	};
}

/** Private application components, in the shape of the private-package list of the other ecosystems. */
function privateComponents(appState, relativise = p => p) {
	const types = new Map((appState.applications || []).map(app => [app.id, app.type]));
	const items = new Map();
	for (const c of appState.inventory || []) {
		const declared = c.visibility === "private";
		const unknown = (appState.coverage || []).some(r => r.occurrenceId === c.id && r.diagnostic === "CMS_PROVIDER_COMPONENT_UNKNOWN");
		if (!declared && !unknown) continue;
		const label = /^[a-z0-9][a-z0-9._-]*$/i.test(c.slug || "") ? c.slug : c.name || c.coord || c.id;
		items.set(c.id, { id: `${c.kind || "component"} · ${label}${c.version ? "@" + c.version : ""}`,
			ecosystem: types.get(c.applicationId) || "application", manifestPaths: c.path ? [relativise(c.path)] : [] });
	}
	return [...items.values()];
}

function summarizeCoverage(records = []) {
	const out = { checks: records.length, completed: 0, partial: 0, failed: 0, notRun: 0, expected: 0, executed: 0 };
	for (const r of records) {
		if (r.execution === "completed") out.completed++;
		else if (r.execution === "partial") out.partial++;
		else if (r.execution === "failed") out.failed++;
		else if (r.execution === "not-run") out.notRun++;
		out.expected += r.expected || 0;
		out.executed += r.executed || 0;
	}
	return out;
}

function requiredCoverageComplete(records = [], capabilities = []) {
	if (!capabilities.length) return true;
	const applications = new Set(records.map(r => r.applicationId));
	if (!applications.size) return false;
	for (const applicationId of applications) {
		for (const capability of capabilities) {
			const checks = records.filter(r => r.applicationId === applicationId && r.capability === capability);
			if (!checks.length || checks.some(r => !isPrivateCheck(r) && r.execution !== "completed" && r.execution !== "not-applicable")) return false;
		}
	}
	return true;
}

// Group incomplete module checks by cause, retaining every affected component.
function applicationWarnings(appState, srcRoot = '') {
	const diagnostics = appState.diagnostics.filter(d => !PRIVATE_DIAGNOSTICS.has(d.code)).map(d => ({ type: d.sourceIds?.length ? "source-unavailable" : "cms-coverage", code: d.code,
			applicationId: d.applicationId || null, ...(d.path ? { path: d.path } : {}),
			message: `${d.applicationId || d.pluginId || "application"}: ${d.message}` }));
	const componentById = new Map(appState.inventory.map(c => [c.id, c]));
	const groups = new Map();
	for (const c of appState.coverage) {
		if (c.execution !== "partial" && c.execution !== "not-run" && c.execution !== "failed") continue;
		if (isPrivateCheck(c)) continue;   // listed once with the private packages of every ecosystem
		if (appState.diagnostics.some(d => d.applicationId === c.applicationId && d.code === c.diagnostic)) continue;
		const diagnostic = c.diagnostic || "CMS_INCOMPLETE";
		const key = `${c.applicationId}\0${c.capability}\0${c.sourceId || ""}\0${diagnostic}`;
		if (!groups.has(key)) groups.set(key, { applicationId: c.applicationId, capability: c.capability,
			sourceId: c.sourceId || null, execution: c.execution, diagnostic, checks: [] });
		groups.get(key).checks.push(c);
	}
	const gaps = [...groups.values()].map(g => {
		const items = g.checks.map(c => {
			const component = componentById.get(c.occurrenceId);
			return { id: component ? `${component.kind || "component"} · ${component.name || component.coord || component.id}`
					: c.occurrenceId || g.applicationId,
				manifestPaths: component?.path ? [require('node:path').join(srcRoot, component.path)] : [] };
		});
		return { type: "cms-coverage", code: g.diagnostic, count: g.checks.length,
			applicationId: g.applicationId, capability: g.capability, sourceId: g.sourceId,
			execution: g.execution, diagnostic: g.diagnostic, items,
			message: `${g.applicationId}: ${g.capability}${g.sourceId ? ` (${g.sourceId})` : ""} — ` +
				`${g.checks.length} component(s) not evaluated (${g.diagnostic})` };
	});
	return diagnostics.concat(gaps);
}

module.exports = { applicationWarnings, createCoverage, summarizeCoverage, requiredCoverageComplete, privateComponents, isPrivateCheck, EXECUTIONS, RESULTS };
