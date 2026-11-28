/**
 * lib/inventory/dep-record.js — contrat de données unifié partagé par tous les codecs.
 *
 * `coordKey` est la clé de la Map résolue ; elle ne collisionne jamais entre
 * écosystèmes grâce au préfixe `ecosystem:`. `groupId`/`artifactId`/`pomPaths`
 * sont conservés comme alias rétro-compat le temps de migrer tous les
 * consommateurs vers `namespace`/`name`/`manifestPaths`.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// NuGet, Composer et PyPI sont case-insensitive : on normalise la clé en lower
// (l'affichage garde la casse d'origine via dep.name).
function normalizeForKey(ecosystem, s) {
	if (ecosystem === "nuget" || ecosystem === "composer" || ecosystem === "pypi") return String(s).toLowerCase();
	return s;
}

// La clé de la Map résolue.
// - Maven : clé BRUTE "g:a" (pas de préfixe "maven:"). Collision-free face aux
//   préfixes des autres écosystèmes (un groupId reverse-DNS ne commence jamais
//   par "npm:"/"nuget:"/…), et ça garde transitive.js + les tests inchangés.
// - npm : "npm:<name>" où name peut inclure le scope (@org/pkg) — namespace reste "".
// - composer : "composer:vendor/pkg". pypi/nuget : "<eco>:<name>".
function coordKeyFor(ecosystem, namespace, name) {
	if (ecosystem === "maven") {
		const g = namespace || "";
		return g ? `${g}:${name}` : name;
	}
	const ns = normalizeForKey(ecosystem, namespace || "");
	const nm = normalizeForKey(ecosystem, name || "");
	const joined = ns ? `${ns}/${nm}` : nm;
	return `${ecosystem}:${joined}`;
}

function makeDepRecord(input) {
	const { ecosystem, namespace = "", name, version = null, manifestPath, scope = "compile", isDev = false, ecosystemType, provenance = "manifest", hashes = null, declaredName = null } = input;
	const concrete = version && !/\$\{/.test(version) ? version : null;
	const manifestPaths = manifestPath ? [manifestPath] : [];
	// Embedded binaries (a dep discovered INSIDE a .jar/.war/.ear) and standalone
	// committed native binaries (.dll/.so/…) must not share the Map key of a declared
	// dep with the same coordinate — they'd merge and the unmanaged report chapter
	// would lose them. Key them by their unique physical location instead. provenance
	// stays on the record so the report/exports can label & group them; "both" is set
	// later if a merge across provenances ever happens.
	const byLocation = (provenance === "embedded" || provenance === "binary") && manifestPath;
	const coordKey = byLocation
		? `${provenance}:${manifestPath}`
		: coordKeyFor(ecosystem, namespace, name);
	return {
		ecosystem,
		ecosystemType: ecosystemType || ecosystem,
		namespace: namespace || "",
		name,
		version: version || null,
		versions: concrete ? [concrete] : [],
		// Per-version → the manifest(s) DECLARING that version. `versions[]` and
		// `manifestPaths[]` are both coord-wide sets with no link between them, so
		// neither says which manifest declared which version. A match carries ONE
		// version, so without this link it renders against EVERY manifest holding the
		// coord: on a scan root spanning several independent projects (A pins
		// jackson-databind 2.15.3, B pins 2.17.0) both projects are reported as holding
		// BOTH versions and each version's CVEs land on both. Maintained on merge by the
		// collectors; consumed by lib/findings/attribution.js.
		versionPaths: concrete && manifestPath ? { [concrete]: [manifestPath] } : {},
		coordKey,
		provenance,
		hashes,
		declaredName,
		scope,
		isDev: !!isDev,
		manifestPaths,
		// Alias rétro-compat : CHAMPS DUPLIQUÉS RÉELS (pas des getters — les depRecords
		// sont spreadés dans des chemins chauds : cve-match.js:175, scan-completeness.js,
		// cve-report.js:1036, snyk.js:105 — un getter serait perdu au spread).
		// groupId/artifactId sont des strings jamais réassignées → pas de dérive.
		// pomPaths PARTAGE la référence de manifestPaths → les push restent synchrones.
		groupId: namespace || "",
		artifactId: name,
		pomPaths: manifestPaths,
	};
}

module.exports = { makeDepRecord, coordKeyFor };
