/**
 * Ingestion jobs: the full vulnerability mirrors (docs/SPEC-fad-service.md §8).
 *
 * A job runs under a LEASE taken in the database (`job_runs`), so with several worker
 * processes — or several hosts on one database — a job never runs twice at once. A job
 * keeps its own small state (e.g. the last cvelistV5 release imported) in the same row.
 *
 * Each job: async run(ctx) → a one-line detail. ctx = { assets, fetcher, log, state, setState }.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const os = require("node:os");

const HOUR = 3600 * 1000;
const JOBS = {
	cvelist: { every: HOUR, run: (...a) => require("./cvelist").run(...a), label: "CVE List (cvelistV5)" },
	kev: { every: 24 * HOUR, run: (...a) => require("./signals").kev(...a), label: "CISA KEV" },
	epss: { every: 24 * HOUR, run: (...a) => require("./signals").epss(...a), label: "EPSS (FIRST.org)" },
	euvd: { every: 24 * HOUR, run: (...a) => require("./signals").euvd(...a), label: "ENISA EUVD" },
	certfr: { every: HOUR, run: (...a) => require("./certfr").run(...a), label: "CERT-FR (ANSSI)" },
	nvd: { every: 6 * HOUR, run: (...a) => require("./nvd").run(...a), label: "NVD (fkie-cad mirror)" },
	osv: { every: HOUR, run: (ctx) => require("./osv").run({ ...ctx, ...(ctx.options.osvEcosystems ? { ecosystems: ctx.options.osvEcosystems } : {}) }), label: "OSV.dev" },
	maintenance: { every: 24 * HOUR, run: (...a) => require("./maintenance").run(...a), label: "Database maintenance" },
	// Opt-in (dumps.daily): a signed public build every day, older ones pruned.
	dump: { every: 24 * HOUR, optIn: true, run: (...a) => require("./dump").run(...a), label: "Public dump build" },
};
const LEASE_MS = 6 * HOUR;

function createJobRunner({ assets, fetcher = globalThis.fetch, log = () => {}, owner = `${os.hostname()}:${process.pid}`, jobOptions = {} } = {}) {
	const db = assets.db;
	const q = {
		ensure: db.prepare("INSERT OR IGNORE INTO job_runs (job) VALUES (?)"),
		take: db.prepare("UPDATE job_runs SET lease_until = ?, owner = ?, last_started = ? WHERE job = ? AND lease_until < ?"),
		finish: db.prepare("UPDATE job_runs SET lease_until = 0, last_finished = ?, last_status = ?, last_detail = ? WHERE job = ? AND owner = ?"),
		state: db.prepare("SELECT state FROM job_runs WHERE job = ?"),
		setState: db.prepare("UPDATE job_runs SET state = ? WHERE job = ?"),
		all: db.prepare("SELECT job, last_started, last_finished, last_status, last_detail FROM job_runs ORDER BY job"),
	};

	/** Run one job now if nobody holds its lease. → { ran, status, detail } */
	async function runJob(name) {
		const job = JOBS[name];
		if (!job) throw new Error(`unknown job ${name} (known: ${Object.keys(JOBS).join(", ")})`);
		q.ensure.run(name);
		const now = Date.now();
		if (!q.take.run(now + LEASE_MS, owner, now, name, now).changes) return { ran: false, status: "leased" };
		const state = JSON.parse(q.state.get(name)?.state || "{}");
		const setState = next => q.setState.run(JSON.stringify(next), name);
		let status = "ok", detail = "";
		const t0 = Date.now();
		try { detail = String(await job.run({ assets, fetcher, log, state, setState, options: jobOptions }) || ""); }
		catch (error) { status = "error"; detail = String(error.message || error); }
		q.finish.run(Date.now(), status, detail.slice(0, 500), name, owner);
		log(`job ${name}: ${status} ${detail} (${((Date.now() - t0) / 1000).toFixed(1)} s)`);
		return { ran: true, status, detail };
	}

	/** Run every job whose last finish is older than its period. */
	async function runDue(names = Object.keys(JOBS).filter(n => !JOBS[n].optIn)) {
		const last = Object.fromEntries(q.all.all().map(r => [r.job, r]));
		const out = {};
		for (const name of names) {
			const r = last[name];
			if (r?.last_status === "ok" && r.last_finished && Date.now() - r.last_finished < JOBS[name].every) continue;
			out[name] = await runJob(name);
		}
		return out;
	}

	/** Freshness of every source, for /sources and the provenance of a page. */
	function status() {
		const rows = Object.fromEntries(q.all.all().map(r => [r.job, r]));
		return Object.entries(JOBS).filter(([name, job]) => !job.optIn || rows[name]).map(([name, job]) => ({ job: name, label: job.label,
			lastFinished: rows[name]?.last_finished || null, status: rows[name]?.last_status || "never", detail: rows[name]?.last_detail || "" }));
	}

	return { runJob, runDue, status };
}

module.exports = { createJobRunner, JOBS };
