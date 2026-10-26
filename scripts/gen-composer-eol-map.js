#!/usr/bin/env node
/**
 * scripts/gen-composer-eol-map.js — regenerate data/eol-composer-frameworks.json.
 *
 * DEV-TIME ONLY. Needs network (Packagist p2 metadata). It never runs during a scan,
 * so the `--offline` zero-network guarantee is untouched; the output is committed and
 * reviewed as a git diff.
 *
 * Rule (see docs/superpowers/specs/2026-09-02-eol-php-reliability-design.md §5.3):
 * a package is a framework component iff the framework's monorepo package lists it in
 * `replace` with the value `self.version` — i.e. it is versioned in lockstep. We take the
 * LAST version of each still-relevant major whose `replace` is non-empty (the map is
 * absent on some patch releases), union them (a component removed in a newer major, e.g.
 * symfony/security-guard, is still in the wild), and add the monorepo package itself.
 * Union over ALL published versions would be wrong: it drags in packages that left the
 * monorepo for an independent version line (symfony/monolog-bundle) — false positives.
 *
 * Usage:  node scripts/gen-composer-eol-map.js
 */
const fs = require("fs");
const path = require("path");

const FRAMEWORKS = {
	symfony: {
		product: "symfony", label: "Symfony", monorepo: "symfony/symfony",
		majors: ["4.4", "5.4", "6.4", "7.2"],
		anchors: ["symfony/framework-bundle", "symfony/symfony", "symfony/http-kernel", "symfony/console"],
	},
	laravel: {
		product: "laravel", label: "Laravel", monorepo: "laravel/framework",
		majors: ["9", "10", "11", "12"],
		anchors: ["laravel/framework", "illuminate/support"],
	},
};

/** Pure. `versions` = Packagist p2 array (newest first), each { version, replace? }. */
function computeCoreComponents(versions, majors, monorepo) {
	const out = new Set([monorepo.toLowerCase()]);
	for (const m of majors) {
		const hit = (versions || []).find(v =>
			String(v.version || "").replace(/^v/, "").startsWith(m + ".") && Object.keys(v.replace || {}).length > 0);
		if (!hit) continue;
		for (const [name, val] of Object.entries(hit.replace)) {
			if (val === "self.version") out.add(String(name).toLowerCase());
		}
	}
	return [...out].sort();
}

async function fetchVersions(pkg) {
	const res = await fetch(`https://repo.packagist.org/p2/${pkg}.json`, { headers: { "User-Agent": "vigievuln-gen-composer-eol-map" } });
	if (!res.ok) throw new Error(`packagist ${pkg}: HTTP ${res.status}`);
	const j = await res.json();
	return j.packages?.[pkg] || [];
}

async function main() {
	const file = path.join(__dirname, "..", "data", "eol-composer-frameworks.json");
	const out = {};
	for (const [id, fw] of Object.entries(FRAMEWORKS)) {
		const versions = await fetchVersions(fw.monorepo);
		const components = computeCoreComponents(versions, fw.majors, fw.monorepo);
		const missing = fw.anchors.filter(a => !components.includes(a));
		if (missing.length) throw new Error(`${id}: anchors missing from components: ${missing.join(", ")}`);
		out[id] = { product: fw.product, label: fw.label, anchors: fw.anchors, components };
		console.log(`${id}: ${components.length} components (${fw.monorepo}, majors ${fw.majors.join("/")})`);
	}
	fs.writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
	console.log(`wrote ${path.relative(process.cwd(), file)}`);
}

module.exports = { computeCoreComponents, FRAMEWORKS };
if (require.main === module) main().catch(e => { console.error(e.message); process.exit(1); });
