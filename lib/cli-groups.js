/**
 * lib/cli-groups.js — fold the long tail of boolean flags into -d / -a.
 *
 * `--help` had grown to eighty options across two screens, twenty-six of them a
 * `--no-<something>` and a dozen more an opt-in switch. Those are not really thirty-eight
 * decisions: they are two lists. `-d eol,nvd` turns things off, `-a licenses,snyk` turns
 * on what is off by default.
 *
 * The original flags still work — they are only HIDDEN from the help. Removing them would
 * break every script and CI job in the wild to save nothing: the goal was a readable help,
 * and hiding achieves it exactly. `--help-all` prints them for anyone who needs the mapping.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

/** Token → the commander option key it drives. Token names are the flag minus `--no-`. */
const DISABLE = {
	report: "report", transitive: "transitive", "all-libs": "allLibs", osv: "osv", nvd: "nvd", "nvd-mirror": "nvdMirror",
	"packagist-audit": "packagistAudit",
	epss: "epss", eol: "eol", kev: "kev", euvd: "euvd", certfr: "certfr", checksums: "checksums", "osv-db": "osvDb",
	retire: "retire", "vendored-js-inventory": "vendoredJsInventory",
	maven: "maven", gradle: "gradle", npm: "npm", yarn: "yarn", nuget: "nuget",
	composer: "composer", pypi: "pypi", go: "go", ruby: "ruby",
	binaries: "binaries", jars: "jars", certs: "certs", js: "js",
	"default-excludes": "defaultExcludes",
};

/** Token → option key, for things that are OFF unless asked for. */
const ACTIVATE = {
	licenses: "licenses", "eol-support": "eolSupport", typosquat: "typosquat", snyk: "snyk",
	"osv-db": "osvDb", "nvd-cpe-match": "nvdCpeMatch", "cve-refresh": "cveRefresh",
	"osv-db-refresh": "osvDbRefresh", "retire-refresh": "retireRefresh", "cve-offline": "cveOffline",
};

function parseList(raw) {
	return String(raw || "").split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
}

/**
 * Resolve -d / -a onto the option object.
 * An unknown token HARD FAILS rather than being ignored: a silently dropped `-d nvd` would
 * produce a report that claims coverage the run did not have — the same class of error the
 * --fail-on validation guards against.
 * @returns {{errors: string[]}}
 */
function applyGroups(options, { disable, activate } = {}) {
	const errors = [];
	const apply = (raw, table, value, flag) => {
		for (const tok of parseList(raw)) {
			const key = table[tok];
			if (!key) {
				const known = Object.keys(table).sort().join(", ");
				errors.push(`unknown ${flag} value "${tok}" — expected one of: ${known}`);
				continue;
			}
			options[key] = value;
		}
	};
	apply(disable, DISABLE, false, "--disable");
	apply(activate, ACTIVATE, true, "--activate");
	return { errors };
}

/** Output types, folded into -r. `--report-<type> [file]` still takes an explicit path. */
const REPORTS = ["html", "doc", "xlsx", "sbom", "csaf", "json", "sarif"];

/**
 * Cache, registry and configuration commands. They manage the TOOL, not a scan, and a
 * reader looking for how to run an audit does not need fifteen of them between --offline
 * and --lang. Still listed by --help-all.
 */
const ADMIN_FLAGS = [
	"--set-nvd-key", "--show-config", "--export-cache", "--import-cache", "--replace",
	"--include-config", "--export-anonymized", "--import-anonymized", "--force",
	"--add-repo", "--remove-repo", "--list-repos", "--auth", "--token", "--completion",
	"--source", "--config", "--transitive-depth", "--cert-expiry-days", "--retries", "--repo",
];

/** Apply -r: select exactly the output types named. Unknown token → error. */
function applyReports(options, raw) {
	const errors = [];
	const toks = parseList(raw);
	if (!toks.length) return { errors };
	for (const t of toks) {
		if (!REPORTS.includes(t)) { errors.push(`unknown --report value "${t}" — expected one of: ${REPORTS.join(", ")}`); continue; }
		const key = "report" + t.charAt(0).toUpperCase() + t.slice(1);
		if (options[key] === undefined) options[key] = true;
	}
	return { errors };
}

/** The flags -d / -a replace, so the help can hide them. */
function foldedFlags() {
	return [
		...Object.keys(DISABLE).map(t => `--no-${t}`),
		...Object.keys(ACTIVATE).map(t => `--${t}`),
	];
}

module.exports = { DISABLE, ACTIVATE, REPORTS, ADMIN_FLAGS, parseList, applyGroups, applyReports, foldedFlags };
