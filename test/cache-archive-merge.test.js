/**
 * test/cache-archive-merge.test.js — `--import-cache` MERGES, it doesn't replace.
 *
 * The air-gapped workflow ships a warmed cache into an enclave that already has a warm
 * cache of its own (and a config.json holding the NVD key + private repo credentials,
 * which --export-cache deliberately never bundles). A wholesale replace silently threw
 * both away: the next `--offline` run then reports 0 CVE / 0 EOL on a cold cache, which
 * reads exactly like a clean project. It also left a full copy of the cache behind as
 * .vigie-vuln.bak-<ts> on every import.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const CLI = path.join(__dirname, "..", "vigievuln.js");

function run(args, home) {
	return execFileSync("node", [CLI, ...args], {
		env: { ...process.env, HOME: home, USERPROFILE: home, FORCE_COLOR: "0" },
		encoding: "utf8",
	});
}

function home(tag) {
	const h = fs.mkdtempSync(path.join(os.tmpdir(), `fad-${tag}-`));
	fs.mkdirSync(path.join(h, ".vigie-vuln"), { recursive: true });
	return h;
}
const fad = (h, ...p) => path.join(h, ".vigie-vuln", ...p);
function w(p, body) {
	fs.mkdirSync(path.dirname(p), { recursive: true });
	fs.writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body));
}
const read = p => JSON.parse(fs.readFileSync(p, "utf8"));
const baks = h => fs.readdirSync(h).filter(n => n.startsWith(".vigie-vuln.bak-"));
const clean = (...dirs) => dirs.forEach(d => { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } });

const DAY = 24 * 3600 * 1000;

test("Maven merge ignores legacy negatives even when their cache is newer", () => {
	const online = home("maven-online"), offline = home("maven-offline");
	const archive = path.join(offline, "maven.tar.gz"), now = Date.now();
	try {
		w(fad(online, "maven-exists-cache.json"), { meta: { fetchedAt: now - DAY }, entries: { "g:archive-positive": true, "g:local-positive": false, "g:legacy": false } });
		w(fad(offline, "maven-exists-cache.json"), { meta: { fetchedAt: now }, entries: { "g:archive-positive": false, "g:local-positive": true } });
		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);
		assert.deepEqual(read(fad(offline, "maven-exists-cache.json")).entries, { "g:archive-positive": true, "g:local-positive": true });
	} finally { clean(online, offline); }
});

test("import MERGES: the enclave's own warm cache and config survive the imported one", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "fad-cache.tar.gz");
	try {
		// Online host: warmed on other projects.
		w(fad(online, "osv-cache", "dep-ONLINE.json"), { id: "ONLINE" });
		w(fad(online, "poms-cache", "parent-ONLINE.json"), { pom: "online" });
		w(fad(online, "epss-cache.json"), { meta: { fetchedAt: Date.now() }, entries: { "CVE-ONLINE": { score: 0.5 } } });
		w(fad(online, "config.json"), { nvd_api_key: "CLE-ONLINE" });

		// Enclave: already warm from earlier air-gapped runs, with its own credentials.
		w(fad(offline, "osv-cache", "dep-ENCLAVE.json"), { id: "ENCLAVE" });
		w(fad(offline, "poms-cache", "parent-ENCLAVE.json"), { pom: "enclave" });
		w(fad(offline, "epss-cache.json"), { meta: { fetchedAt: Date.now() }, entries: { "CVE-ENCLAVE": { score: 0.9 } } });
		w(fad(offline, "config.json"), { nvd_api_key: "CLE-ENCLAVE", registries: { maven: [{ name: "nexus" }] } });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);

		// Per-key file caches: union, nothing dropped.
		assert.ok(fs.existsSync(fad(offline, "osv-cache", "dep-ONLINE.json")), "imported OSV entry must land");
		assert.ok(fs.existsSync(fad(offline, "osv-cache", "dep-ENCLAVE.json")), "the enclave's own OSV entry must survive the import");
		assert.ok(fs.existsSync(fad(offline, "poms-cache", "parent-ENCLAVE.json")), "the enclave's own POM cache must survive the import");

		// entries{} maps: union of both sides.
		const epss = read(fad(offline, "epss-cache.json"));
		assert.deepEqual(Object.keys(epss.entries).sort(), ["CVE-ENCLAVE", "CVE-ONLINE"], "entries{} maps must be merged, not overwritten");

		// config.json is machine-local: --export-cache never ships it, so an import must never touch it.
		assert.equal(read(fad(offline, "config.json")).nvd_api_key, "CLE-ENCLAVE", "the enclave's NVD key must not be lost");
		assert.ok(read(fad(offline, "config.json")).registries, "the enclave's private registries must not be lost");

		// No 123 MB copy left behind in $HOME on every sneakernet refresh.
		assert.deepEqual(baks(offline), [], "a merging import must not leave a .vigie-vuln.bak-* copy");
	} finally { clean(online, offline); }
});

test("colliding entries: the fresher side wins the value, the merged stamp stays the older one", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "c.tar.gz");
	try {
		const older = Date.now() - 3 * DAY, newer = Date.now() - 1 * DAY;
		w(fad(online, "version-cache.json"), { meta: { fetchedAt: newer }, entries: { "g:a": { latest: "2.0.0" }, "g:only-online": { latest: "9" } } });
		w(fad(offline, "version-cache.json"), { meta: { fetchedAt: older }, entries: { "g:a": { latest: "1.0.0" }, "g:only-enclave": { latest: "7" } } });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);

		const v = read(fad(offline, "version-cache.json"));
		assert.equal(v.entries["g:a"].latest, "2.0.0", "on a key collision the fresher side's value wins");
		assert.equal(v.entries["g:only-enclave"].latest, "7", "keys only the enclave had must survive");
		assert.equal(v.entries["g:only-online"].latest, "9", "keys only the archive had must land");
		assert.equal(v.meta.fetchedAt, older, "the merged map is only as fresh as its oldest half — never antedate it");
	} finally { clean(online, offline); }
});

test("whole-corpus snapshots (kev) are not key-merged: the newest snapshot wins as a block", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "k.tar.gz");
	try {
		w(fad(online, "kev-cache.json"), { _fetchedAt: Date.now(), body: { byId: { "CVE-NEW": { dateAdded: "2026-09-11" } } } });
		w(fad(offline, "kev-cache.json"), { _fetchedAt: Date.now() - 30 * DAY, body: { byId: { "CVE-OLD": { dateAdded: "2020-01-01" } } } });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);

		const kev = read(fad(offline, "kev-cache.json"));
		assert.deepEqual(Object.keys(kev.body.byId), ["CVE-NEW"], "the fresher full KEV catalog replaces the stale one wholesale");
	} finally { clean(online, offline); }
});

test("a stale archive never downgrades a fresher local snapshot", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "k.tar.gz");
	try {
		w(fad(online, "kev-cache.json"), { _fetchedAt: Date.now() - 30 * DAY, body: { byId: { "CVE-OLD": {} } } });
		w(fad(offline, "kev-cache.json"), { _fetchedAt: Date.now(), body: { byId: { "CVE-NEW": {} } } });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);

		assert.deepEqual(Object.keys(read(fad(offline, "kev-cache.json")).body.byId), ["CVE-NEW"], "importing an older archive must not roll the enclave back");
	} finally { clean(online, offline); }
});

test("cve-data/ is atomic: the index and its meta.json always come from the same build", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "d.tar.gz");
	try {
		w(fad(online, "cve-data", "maven-cve-index.json"), { built: "online" });
		w(fad(online, "cve-data", "meta.json"), { releaseTag: "cve_2026-09-14_1000Z", cveCount: 19240 });
		w(fad(offline, "cve-data", "maven-cve-index.json"), { built: "enclave" });
		w(fad(offline, "cve-data", "meta.json"), { releaseTag: "cve_2026-01-01_1000Z", cveCount: 100 });
		// Make the enclave's meta.json look freshly touched while its index is old: a
		// per-file newest-wins rule would pair the online index with the enclave meta.
		const soon = new Date(Date.now() + 60_000);
		fs.utimesSync(fad(offline, "cve-data", "meta.json"), soon, soon);

		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);

		const idx = read(fad(offline, "cve-data", "maven-cve-index.json"));
		const meta = read(fad(offline, "cve-data", "meta.json"));
		const pairedOnline = idx.built === "online" && meta.releaseTag === "cve_2026-09-14_1000Z";
		const pairedEnclave = idx.built === "enclave" && meta.releaseTag === "cve_2026-01-01_1000Z";
		assert.ok(pairedOnline || pairedEnclave, `cve-data must not be mixed across builds (got index=${idx.built}, meta=${meta.releaseTag})`);
	} finally { clean(online, offline); }
});

test("--replace keeps the old wholesale behaviour, backup and all", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "r.tar.gz");
	try {
		w(fad(online, "osv-cache", "dep-ONLINE.json"), { id: "ONLINE" });
		w(fad(offline, "osv-cache", "dep-ENCLAVE.json"), { id: "ENCLAVE" });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive, "--replace"], offline);

		assert.ok(fs.existsSync(fad(offline, "osv-cache", "dep-ONLINE.json")), "the archive must land");
		assert.ok(!fs.existsSync(fad(offline, "osv-cache", "dep-ENCLAVE.json")), "--replace is wholesale: the local cache is gone from the active dir");
		assert.equal(baks(offline).length, 1, "--replace moves the previous cache aside as .vigie-vuln.bak-*");
		assert.ok(fs.existsSync(path.join(offline, baks(offline)[0], "osv-cache", "dep-ENCLAVE.json")), "and the backup holds it");
	} finally { clean(online, offline); }
});

test("--replace --force replaces without leaving a backup", () => {
	const online = home("online"), offline = home("offline");
	const archive = path.join(offline, "f.tar.gz");
	try {
		w(fad(online, "osv-cache", "dep-ONLINE.json"), { id: "ONLINE" });
		w(fad(offline, "osv-cache", "dep-ENCLAVE.json"), { id: "ENCLAVE" });

		run(["--export-cache", archive], online);
		run(["--import-cache", archive, "--replace", "--force"], offline);

		assert.ok(!fs.existsSync(fad(offline, "osv-cache", "dep-ENCLAVE.json")));
		assert.deepEqual(baks(offline), [], "--force keeps no backup");
	} finally { clean(online, offline); }
});

test("import into a machine with no cache at all still works", () => {
	const online = home("online");
	const cold = fs.mkdtempSync(path.join(os.tmpdir(), "fad-cold-"));
	const archive = path.join(cold, "n.tar.gz");
	try {
		w(fad(online, "osv-cache", "dep-ONLINE.json"), { id: "ONLINE" });
		run(["--export-cache", archive], online);
		run(["--import-cache", archive], cold);
		assert.ok(fs.existsSync(fad(cold, "osv-cache", "dep-ONLINE.json")));
		assert.deepEqual(baks(cold), []);
	} finally { clean(online, cold); }
});

test("import works when the enclave unpacks the archive as root", () => {
	// tar restores the archived uid/gid when it runs as root. REAL root can chown to
	// anything, so a plain Docker enclave is unaffected; MAPPED root cannot — a rootless
	// container, a userns-remapped daemon, anything under `unshare -r`. There the chown
	// fails, tar aborts having written NOTHING, and the air-gapped run that follows finds
	// no cache and reports a clean project. --no-same-owner is already the default for a
	// non-root user, so the paths that worked are untouched.
	//
	// A user namespace is what reproduces it: the caller is mapped to root and the archived
	// uid is unmappable, which is exactly the failing chown. Skipped where unprivileged user
	// namespaces are unavailable (some hardened kernels, some CI).
	let userns = true;
	try { execFileSync("unshare", ["-r", "true"], { stdio: "ignore" }); } catch { userns = false; }
	if (!userns) return;   // nothing to assert here on a kernel without unprivileged userns

	const online = home("root-src"), enclave = home("root-dst");
	const archive = path.join(online, "fad-cache.tar.gz");
	try {
		w(fad(online, "osv-cache", "dep-A.json"), { id: "A" });
		w(fad(online, "nvd-cache", "CVE-2021-44228.json"), { id: "CVE-2021-44228" });
		run(["--export-cache", archive], online);

		// The enclave starts with NO cache, and imports as (mapped) root.
		fs.rmSync(path.join(enclave, ".vigie-vuln"), { recursive: true, force: true });
		execFileSync("unshare", ["-r", "node", CLI, "--import-cache", archive], {
			env: { ...process.env, HOME: enclave, USERPROFILE: enclave, FORCE_COLOR: "0" },
			encoding: "utf8",
		});

		assert.equal(read(fad(enclave, "osv-cache", "dep-A.json")).id, "A");
		assert.equal(read(fad(enclave, "nvd-cache", "CVE-2021-44228.json")).id, "CVE-2021-44228");
	} finally { clean(online, enclave); }
});

test("CMS snapshot imports compare collection dates even when mtimes are reversed", () => {
	const online = home("cms-online"), offline = home("cms-offline");
	const archive = path.join(offline, "cms.tar.gz");
	try {
		for (const [name, incomingDate, currentDate, expected] of [
			["older.json", "2020-01-01", "2026-01-01", "current"],
			["newer.json", "2026-01-01", "2020-01-01", "incoming"],
			["invalid.json", "invalid", "2026-01-01", "current"],
		]) {
			const incoming = fad(online, "advisory-snapshots", name), current = fad(offline, "advisory-snapshots", name);
			w(incoming, { _fadSnapshot: { collectedAt: incomingDate }, value: "incoming" });
			w(current, { _fadSnapshot: { collectedAt: currentDate }, value: "current" });
			fs.utimesSync(incoming, new Date("2030-01-01"), new Date("2030-01-01"));
			fs.utimesSync(current, new Date("2010-01-01"), new Date("2010-01-01"));
		}
		run(["--export-cache", archive], online);
		run(["--import-cache", archive], offline);
		assert.equal(read(fad(offline, "advisory-snapshots", "older.json")).value, "current");
		assert.equal(read(fad(offline, "advisory-snapshots", "newer.json")).value, "incoming");
		assert.equal(read(fad(offline, "advisory-snapshots", "invalid.json")).value, "current");
	} finally { clean(online, offline); }
});

test("semantic cache merge publishes body and metadata together and preserves old data on failure", () => {
	const { createCacheStore } = require("../lib/proxy-cache");
	const { mergeResourceStore } = require("../lib/cache-archive");
	const incomingDir = home("resource-in"), currentDir = home("resource-out");
	const incoming = createCacheStore(incomingDir), current = createCacheStore(currentDir);
	const put = (store, key, body, stamp) => {
		const tmp = path.join(store.dir, "seed"); fs.writeFileSync(tmp, body);
		store.commit(key, tmp, { bytes: Buffer.byteLength(body), fetchedAt: stamp, ttlMs: 1 });
	};
	const stats = () => ({ added: 0, updated: 0, kept: 0 });
	try {
		put(incoming, "a", "new", 2); put(current, "a", "old", 1);
		const rename = fs.renameSync;
		try {
			fs.renameSync = (from, to) => {
				if (to === current.metaPath(current.hash("a"))) throw new Error("simulated interrupted publication");
				return rename(from, to);
			};
			assert.throws(() => mergeResourceStore(incomingDir, currentDir, stats()), /interrupted/);
		} finally { fs.renameSync = rename; }
		assert.equal(fs.readFileSync(current.get("a").bodyPath, "utf8"), "old");
		mergeResourceStore(incomingDir, currentDir, stats());
		assert.equal(fs.readFileSync(current.get("a").bodyPath, "utf8"), "new");
		fs.unlinkSync(incoming.get("a").bodyPath);
		mergeResourceStore(incomingDir, currentDir, stats());
		assert.equal(fs.readFileSync(current.get("a").bodyPath, "utf8"), "new");
	} finally { clean(incomingDir, currentDir); }
});
