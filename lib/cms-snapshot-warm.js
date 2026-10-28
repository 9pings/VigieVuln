/**
 * lib/cms-snapshot-warm.js — phase-2 (online) warming of the per-publisher CMS advisory
 * snapshots an air-gapped phase 3 consumes automatically (runner.js offline fallback).
 *
 * `--import-anonymized` scans the descriptor's public coordinates with no source tree,
 * so the application plugins never run there and the CMS advisory lanes would reach
 * phase 3 with nothing cached. But the Drupal feed is keyed by package identity and
 * the PrestaShop/TYPO3 feeds are whole-repository: the descriptor's own coordinates are
 * enough to fetch them, so the documented 3-phase workflow needs no extra flags — warm
 * here, `--export-cache` carries the file, phase 3 reuses it offline. A fetched snapshot
 * is validated with its provider's schema before being written, so a shape change fails
 * online (where it can be fixed) instead of aborting the air-gapped phase 3.
 *
 * Application identities in the descriptor also justify SPIP's NVD snapshot and
 * WordPress checksums pinned to core version and the requested locale. Wordfence
 * warming uses a client API key or explicit live activation with a proxy server key. Network requests use the configured provider route.
 */
const path = require("node:path");
const {
	fetchDrupalAdvisories, fetchGithubAdvisories, fetchWordpressChecksums, fetchWordfenceFeed, writeSnapshotAtomically,
} = require("./application-providers/live-snapshot");
const { fetchSpipAdvisories, validateSnapshot: validateSpip } = require("./application-providers/spip-advisories");
const { validateSnapshot: validateDrupal } = require("./application-providers/drupal-advisories");
const { validateSnapshot: validateGithub } = require("./application-providers/github-advisories");
const { validateChecksums } = require("./application-providers/wp-checksums");

/** Public composer coordinates of a resolved-deps Map (or array) — "vendor/name", lowercased. */
function composerCoords(deps) {
	const records = deps && typeof deps.values === "function" ? [...deps.values()]
		: Array.isArray(deps) ? deps : [];
	const coords = new Set();
	for (const dep of records) {
		if (dep && dep.ecosystem === "composer" && dep.namespace && dep.name)
			coords.add(`${dep.namespace}/${dep.name}`.toLowerCase());
	}
	return coords;
}

/**
 * Fetch and cache the CMS advisory snapshots the descriptor justifies: from its public
 * composer coordinates (the Drupal feed is keyed by package identity) and from its
 * application identities (publisher feeds of installs whose lock holds none of the
 * publisher's own packages; the WordPress checksums reference, pinned by core version
 * and locale; the Wordfence catalogue when the warming machine holds an API key).
 * Returns what was warmed: { drupal, prestashop, typo3, wpChecksums: [versions],
 * wordfence }.
 */
async function warmCmsAdvisorySnapshots(deps, { fetchImpl, advisoryCacheDir,
	drupalUrl, prestashopUrl, typo3Url, spipUrl, applications = [], wordfenceApiKey,
	wordfenceUrl, wordfenceLive = false, wpChecksumsLocale = "en_US", nvdApiKey, now } = {}) {
	const warmed = { drupal: 0, prestashop: false, typo3: false, spip: false, wpChecksums: [], wordfence: false };
	if (!advisoryCacheDir) return warmed;
	const coords = composerCoords(deps);
	const appTypes = new Set(applications.map(app => String(app?.type || "").toLowerCase()));
	// The Drupal feed is keyed by package identity; the live source queries the union
	// of every instance's PUBLIC inventoried identities — a module/theme inventoried
	// from its .info.yml never appears in the lock, so the descriptor carries the
	// inventoried components alongside the lock coordinates. Private components are
	// already absent from the descriptor; the drupal/ prefix is the public catalogue.
	const drupalPackages = [...new Set([...coords,
		...applications.flatMap(app => Array.isArray(app?.components) ? app.components : [])]
		.filter(coord => typeof coord === "string" && coord.toLowerCase().startsWith("drupal/"))
		.map(coord => String(coord).toLowerCase()))];
	if (drupalPackages.length) {
		const fetched = await fetchDrupalAdvisories(drupalPackages,
			{ fetchImpl, ...(drupalUrl ? { apiUrl: drupalUrl } : {}), now });
		validateDrupal(fetched.snapshot);
		writeSnapshotAtomically(path.join(advisoryCacheDir, "drupal-security-advisories.json"), fetched.snapshot);
		warmed.drupal = drupalPackages.length;
	}

	for (const [publisher, repo, file, url, validateOpts] of [
		["prestashop", "PrestaShop/PrestaShop", "github-prestashop-advisories.json", prestashopUrl,
			{ fallbackCoord: "prestashop/prestashop" }],
		["typo3", "TYPO3/typo3", "github-typo3-advisories.json", typo3Url, {}],
	]) {
		// Whole-repository feed: warmed when the lock carries the publisher's own
		// packages OR the descriptor declares an instance of that CMS — an install's
		// lock may hold none of the publisher's packages (the core is not a dep).
		if (![...coords].some(coord => coord.startsWith(`${publisher}/`)) && !appTypes.has(publisher)) continue;
		const fetched = await fetchGithubAdvisories(repo,
			{ fetchImpl, ...(url ? { endpoint: url } : {}), now });
		validateGithub(fetched.snapshot, validateOpts);
		writeSnapshotAtomically(path.join(advisoryCacheDir, file), fetched.snapshot);
		warmed[publisher] = true;
	}

	// SPIP: the only machine-readable source is NVD's product CVE set — a single
	// snapshot for the whole instance, warmed when a spip application is declared
	// (the NVD API key is optional; it only lifts the rate limit).
	if (appTypes.has("spip")) {
		const fetched = await fetchSpipAdvisories({ fetchImpl,
			...(spipUrl ? { apiUrl: spipUrl } : {}), ...(nvdApiKey ? { apiKey: nvdApiKey } : {}), now });
		validateSpip(fetched.snapshot);
		writeSnapshotAtomically(path.join(advisoryCacheDir, "spip-security-advisories.json"), fetched.snapshot);
		warmed.spip = true;
	}

	// WordPress checksums: one reference per declared core version, pinned by the
	// warming run's locale (the phase-3 scan reads it back with its own --wp-checksums-
	// locale — the two must agree, like the report's own checksums note says).
	if (appTypes.has("wordpress")) {
		for (const version of [...new Set(applications
			.filter(app => String(app?.type || "").toLowerCase() === "wordpress" && app.version)
			.map(app => String(app.version)))]) {
			const fetched = await fetchWordpressChecksums(version, wpChecksumsLocale, { fetchImpl, now });
			validateChecksums(fetched.snapshot);
			writeSnapshotAtomically(path.join(advisoryCacheDir,
				`wordpress-checksums-${fetched.snapshot.version || version}-${fetched.snapshot.locale || wpChecksumsLocale}.json`), fetched.snapshot);
			warmed.wpChecksums.push(fetched.snapshot.version || version);
		}
		// In proxy mode only declared public identities are queried and cached.
		if (wordfenceApiKey || wordfenceLive) {
			const { WORDFENCE_PRODUCTION_URL } = require("./application-providers/live-snapshot");
			const software = [{ type: "core", slug: "wordpress" }, ...applications
				.filter(app => String(app?.type || "").toLowerCase() === "wordpress")
				.flatMap(app => (app.components || []).flatMap(coord => {
					const match = /^wordpress:(plugin|theme):([a-z0-9][a-z0-9._-]*)$/.exec(coord);
					return match ? [{ type: match[1], slug: match[2] }] : [];
				}))];
			const fetched = await fetchWordfenceFeed(wordfenceUrl || WORDFENCE_PRODUCTION_URL,
				{ fetchImpl, apiKey: wordfenceApiKey, now, software });
			if (fetched.snapshot.format === "wordfence-targeted-v1")
				require("./application-providers/wordfence-client").cacheProjection(advisoryCacheDir, fetched.snapshot);
			else writeSnapshotAtomically(path.join(advisoryCacheDir, "wordfence-v3.json"), fetched.snapshot);
			warmed.wordfence = true;
		}
	}
	return warmed;
}

module.exports = { warmCmsAdvisorySnapshots, composerCoords };
