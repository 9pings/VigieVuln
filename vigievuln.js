#!/usr/bin/env node
/**
 * VigieVuln — autonomous dependency auditor — CLI entry point.
 *
 * Thin wrapper around lib/* modules. The heavy lifting lives in:
 *   lib/core.js          POM parsing & rewriting
 *   lib/cve-download.js  CVE bulk download + index build
 *   lib/cve-match.js     dependency collection + CVE matching
 *   lib/cve-report.js    HTML / Word report generation
 *   lib/outdated.js      EOL + obsolete + outdated checks
 *   lib/snyk.js          optional Snyk integration
 */
const fs = require("fs");
const path = require("path");
const { rimraf } = require("rimraf");
const chalk = require("chalk");
const pLimit = require("p-limit");
const { program } = require("commander");
const ui = require("./lib/ui");
const { createSourceHealth, guardedFetch, setActiveLedger, setRetryAttempts } = require("./lib/source-health");

const core = require("./lib/core");

// require() (not fs.readFileSync) so bun --compile statically bundles package.json
// into the binary — otherwise the compiled exe tries to read it off disk at runtime
// (from $bunfs/root) and crashes with ENOENT. Keeps the bun builds fully standalone.
const pkg = require("./package.json");

// -------- compiled-binary retire mode --------
// The bun-compiled single binary has no node_modules to spawn the retire CLI from,
// and an air-gapped box has no `retire` on PATH. So lib/retire.js re-execs THIS
// binary with __FAD_RETIRE__ set; here we hand off to the statically-bundled retire
// CLI (it self-runs, reading process.argv — bun's argv mirrors node's). The entire
// normal CLI body is gated behind `else` so fad's own commander setup never runs in
// retire mode (retire shares commander's singleton `program`). Lets vendored-JS
// scanning work fully offline from the one binary, no external retire needed.
if (process.env.__FAD_RETIRE__) {
	require("retire/lib/cli.js");
} else {

try {
	const routed = require("./lib/cli-command-routing").routeArguments(process.argv.slice(2));
	if (routed.help) { console.log(routed.help); process.exit(0); }
	process.argv = [...process.argv.slice(0, 2), ...routed.args];
} catch (error) { console.error(`❌  ${error.message}`); process.exit(2); }

if (["auth", "project", "watch"].includes(process.argv[2])) {
	require("./lib/cli-project-commands").run(process.argv.slice(2)).catch(err=>{
		console.error(`❌  ${err.message}`); process.exitCode=2;
	}).finally(()=>process.exit(process.exitCode || 0));
} else {

// -------- bash/zsh completion shortcut (must run before required-options parse) --------
if (process.argv.includes("--completion")) {
	const shellIdx = process.argv.indexOf("--completion") + 1;
	const shell = process.argv[shellIdx] && !process.argv[shellIdx].startsWith("-")
		? process.argv[shellIdx]
		: "bash";
	const completionPath = path.join(__dirname, "completions", `vigievuln.${shell}`);
	try {
		process.stdout.write(fs.readFileSync(completionPath, "utf8"));
		process.exit(0);
	} catch (_) {
		console.error(`Completion for ${shell} not available.`);
		process.exit(1);
	}
}

// -------- --set-nvd-key shortcut (must run before required-options parse) --------
if (process.argv.includes("--set-proxy-cache-token") || process.argv.includes("--unset-proxy-cache-token")) {
	const config = require("./lib/config");
	if (process.argv.includes("--unset-proxy-cache-token")) config.set("proxyCacheToken", null);
	else {
		const token = process.argv[process.argv.indexOf("--set-proxy-cache-token") + 1];
		if (!token || token.startsWith("-")) { console.error("--set-proxy-cache-token requires a key"); process.exit(1); }
		config.set("proxyCacheToken", token);
	}
	console.log("Proxy key configuration updated in " + config.CONFIG_PATH);
	process.exit(0);
}
if (process.argv.includes("--set-proxy-cache") || process.argv.includes("--unset-proxy-cache")) {
	const config = require("./lib/config");
	if (process.argv.includes("--unset-proxy-cache")) {
		config.set("proxyCache", null);
		console.log("Proxy cache removed from " + config.CONFIG_PATH);
	} else {
		const value = process.argv[process.argv.indexOf("--set-proxy-cache") + 1];
		if (!value || !(/^(vigievuln|default)$/i.test(value) || /^https?:\/\/[^\s]+$/i.test(value))) {
			console.error("--set-proxy-cache requires vigievuln, default, or an http(s) URL");
			process.exit(1);
		}
		config.set("proxyCache", value);
		console.log("Proxy cache saved to " + config.CONFIG_PATH);
	}
	process.exit(0);
}
if (process.argv.includes("--set-nvd-key")) {
	const config = require("./lib/config");
	const idx = process.argv.indexOf("--set-nvd-key");
	const key = process.argv[idx + 1];
	if (!key || key.startsWith("-")) {
		console.error(chalk.red("❌  --set-nvd-key requires a key argument"));
		console.error("   Get one (free, instant) at https://nvd.nist.gov/developers/request-an-api-key");
		process.exit(1);
	}
	config.set("nvd_api_key", key);
	console.log(chalk.green("✅ NVD API key saved to") + " " + chalk.cyan(config.CONFIG_PATH));
	console.log(chalk.gray("   Rate limit: 50 req / 30 s instead of 5 req / 30 s."));
	process.exit(0);
}
if (process.argv.includes("--show-config")) {
	const config = require("./lib/config");
	const cfg = config.load();
	const masked = { ...cfg };
	if (masked.nvd_api_key) masked.nvd_api_key = masked.nvd_api_key.slice(0, 8) + "…" + masked.nvd_api_key.slice(-4);
	if (masked.proxyCacheToken) masked.proxyCacheToken = "***";
	if (masked.registries && typeof masked.registries === "object") {
		masked.registries = Object.fromEntries(Object.entries(masked.registries).map(([eco, list]) =>
			[eco, (list || []).map(r => ({ ...r, auth: r.auth ? "***" : undefined, token: r.token ? "***" : undefined }))]));
	}
	console.log(JSON.stringify(masked, null, 2));
	console.log(chalk.gray("Config file: " + config.CONFIG_PATH));
	process.exit(0);
}

if (process.argv.includes("--list-app-plugins")) {
	const { allApplicationPlugins } = require("./lib/application-plugins");
	for (const plugin of allApplicationPlugins()) {
		console.log(`${plugin.id}\t${plugin.version}\tinventory: ${plugin.capabilities.inventory}\tadvisories: ${plugin.capabilities.advisories || "unavailable"}`);
	}
	process.exit(0);
}

// -------- --proxy <url> / serve-cache --upstream-proxy <url> (re-exec, before anything runs) --------
// A corporate forward proxy for EVERY outbound request. Node's built-in fetch only
// honours HTTP(S)_PROXY with NODE_USE_ENV_PROXY set at process start (verified: the
// env is read at bootstrap — setting it mid-run is silently ignored), so the process
// re-execs itself with the env applied and the child takes over. The sentinel env
// prevents recursion. A --proxy-cache URL given in the same command is added to
// NO_PROXY: traffic to the shared cache is local and must not enter the tunnel.
if (!process.env.__FAD_PROXY_REEXEC__) {
	const { parseProxyFlag, runtimeSupportsEnvProxy, reexecWithProxy } = require("./lib/proxy-cache");
	const corpProxy = parseProxyFlag();
	if (corpProxy) {
		if (!/^https?:\/\//i.test(corpProxy)) {
			console.error(chalk.red(`❌  ${process.argv[2] === "serve-cache" ? "--upstream-proxy" : "--proxy"} expects an http(s) URL, got "${corpProxy}"`));
			process.exit(2);
		}
		if (!runtimeSupportsEnvProxy()) {
			console.warn(chalk.yellow(`⚠️  Node ${process.versions.node} ignores HTTP(S)_PROXY for fetch (needs Node >= 24, or bun) — continuing anyway`));
		}
		let noProxyHost = null;
		const pcIdx = process.argv.indexOf("--proxy-cache");
		const pcUrl = pcIdx > -1 && process.argv[pcIdx + 1] && !process.argv[pcIdx + 1].startsWith("-") ? process.argv[pcIdx + 1] : null;
		if (pcUrl) { try { noProxyHost = new URL(pcUrl).hostname; } catch { /* ignore */ } }
		reexecWithProxy({ proxyUrl: corpProxy, noProxy: noProxyHost });
		return; // the child owns the run; this process just relays its exit code
	}
}

// -------- --add-repo / --remove-repo / --list-repos (run before program.parse) --------
if (process.argv.includes("--add-repo") || process.argv.includes("--remove-repo") || process.argv.includes("--list-repos")) {
	const config = require("./lib/config");
	const { SUPPORTED } = require("./lib/registries");
	const ecoErr = eco => {
		if (!SUPPORTED.includes(eco)) {
			console.error(chalk.red(`❌  unknown ecosystem "${eco}". Supported: ${SUPPORTED.join(", ")}`));
			process.exit(1);
		}
	};
	if (process.argv.includes("--list-repos")) {
		const map = config.getRegistryMap();
		const ecos = Object.keys(map).filter(e => (map[e] || []).length);
		if (!ecos.length) {
			console.log(chalk.gray("No custom registries configured (public registries are always the fallback)."));
		} else {
			for (const eco of ecos) {
				console.log(chalk.bold(`${eco} (tried in order, then public):`));
				for (const r of map[eco]) {
					const authMark = (r.auth || r.token) ? chalk.yellow(" [auth]") : "";
					console.log(`  • ${chalk.cyan(r.name)} → ${r.url}${authMark}`);
				}
			}
		}
		process.exit(0);
	}
	if (process.argv.includes("--add-repo")) {
		const idx = process.argv.indexOf("--add-repo");
		const [eco, name, url] = [process.argv[idx + 1], process.argv[idx + 2], process.argv[idx + 3]];
		if (!eco || !name || !url || [eco, name, url].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --add-repo requires <ecosystem> <name> <url>"));
			console.error("   Example: vigievuln --add-repo npm verdaccio https://npm.acme/ --token TOK");
			console.error("   Maven:   vigievuln --add-repo maven nexus https://nexus.acme/maven-public/ --auth user:pass");
			process.exit(1);
		}
		ecoErr(eco);
		const authIdx = process.argv.indexOf("--auth");
		const tokIdx = process.argv.indexOf("--token");
		config.addRegistry(eco, name, url, {
			auth: authIdx > -1 ? process.argv[authIdx + 1] : null,
			token: tokIdx > -1 ? process.argv[tokIdx + 1] : null,
		});
		console.log(chalk.green(`✅ Added ${eco} registry "${name}" → ${url}`));
		process.exit(0);
	}
	if (process.argv.includes("--remove-repo")) {
		const idx = process.argv.indexOf("--remove-repo");
		const [eco, name] = [process.argv[idx + 1], process.argv[idx + 2]];
		if (!eco || !name || [eco, name].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --remove-repo requires <ecosystem> <name>"));
			process.exit(1);
		}
		ecoErr(eco);
		const removed = config.removeRegistry(eco, name);
		console.log(removed ? chalk.green(`✅ Removed ${eco} registry "${name}"`) : chalk.yellow(`⚠️  No ${eco} registry named "${name}"`));
		process.exit(removed ? 0 : 1);
	}
}

// -------- --export-cache / --import-cache (handled before program.parse) --------
if (process.argv.includes("--export-cache") || process.argv.includes("--import-cache")) {
	(async () => {
		const { exportCache, importCache, FAD_CACHE_DIR } = require("./lib/cache-archive");
		const verbose = process.argv.includes("--verbose");
		const exportIdx = process.argv.indexOf("--export-cache");
		const importIdx = process.argv.indexOf("--import-cache");
		try {
			if (exportIdx !== -1) {
				const dest = process.argv[exportIdx + 1];
				if (!dest || dest.startsWith("-")) {
					console.error(chalk.red("❌  --export-cache requires a destination path (e.g. vigievuln-cache.tar.gz)"));
					process.exit(1);
				}
				const includeConfig = process.argv.includes("--include-config");
				const { path: out, size, excluded } = await exportCache(dest, { verbose, includeConfig });
				const mb = (size / 1024 / 1024).toFixed(2);
				console.log(chalk.green(`✅ Cache exported (${mb} MB) → ${out}`));
				console.log(chalk.gray(`   Source: ${FAD_CACHE_DIR}`));
				if (excluded?.length) console.log(chalk.gray(`   Excluded (pass --include-config to ship them too): ${excluded.join(", ")}`));
			} else {
				const src = process.argv[importIdx + 1];
				if (!src || src.startsWith("-")) {
					console.error(chalk.red("❌  --import-cache requires a source path"));
					process.exit(1);
				}
				const force = process.argv.includes("--force");
				const replace = process.argv.includes("--replace");
				const { dir, mode, stats } = await importCache(src, { verbose, force, replace });
				if (mode === "merge") {
					console.log(chalk.green(`✅ Cache merged → ${dir}`));
					console.log(chalk.gray(`   ${stats.added} new, ${stats.updated} refreshed, ${stats.merged} merged key-by-key, ${stats.kept} kept (local copy was fresher)`));
					if (stats.skipped.length) console.log(chalk.gray(`   Left untouched (machine-local): ${stats.skipped.join(", ")}`));
				} else {
					console.log(chalk.green(`✅ Cache imported → ${dir}`));
					console.log(chalk.gray(`   --replace: previous cache ${force ? "removed" : "moved to ~/.vigie-vuln.bak-<timestamp>"}`));
				}
			}
			process.exit(0);
		} catch (err) {
			console.error(chalk.red(`❌  ${err.message}`));
			process.exit(1);
		}
	})();
	return;
}

// -------- `fad diff <baseline.json> <current.json>` subcommand (pre-parse) --------
// Standalone differential audit between two findings JSON exports. Mirrors the other
// pre-parse intercepts so it never collides with the main option set (which requires -s).
if (process.argv[2] === "diff") {
	const { diffFindings, summarizeDiff, newProductionCveCount } = require("./lib/diff");
	const rest = process.argv.slice(3);
	const positionals = rest.filter(a => !a.startsWith("-"));
	const [basePath, curPath] = positionals;
	const failOnNew = rest.includes("--fail-on-new");
	const jIdx = rest.indexOf("--report-json");
	const jsonOut = jIdx > -1 && rest[jIdx + 1] && !rest[jIdx + 1].startsWith("-") ? rest[jIdx + 1] : null;
	if (!basePath || !curPath) {
		console.error(chalk.red("❌  usage: vigievuln diff <baseline.json> <current.json> [--report-json <out>] [--fail-on-new]"));
		process.exit(2);
	}
	let baseDoc, curDoc;
	try { baseDoc = JSON.parse(fs.readFileSync(basePath, "utf8")); }
	catch (e) { console.error(chalk.red(`❌  cannot read baseline ${basePath}: ${e.message}`)); process.exit(2); }
	try { curDoc = JSON.parse(fs.readFileSync(curPath, "utf8")); }
	catch (e) { console.error(chalk.red(`❌  cannot read current ${curPath}: ${e.message}`)); process.exit(2); }
	const d = diffFindings(baseDoc, curDoc);
	const s = summarizeDiff(d);
	const newProd = newProductionCveCount(d);
	console.log(chalk.bold(`\nDifferential audit  ${chalk.dim(basePath)} → ${chalk.dim(curPath)}\n`));
	const line = (label, c) => console.log(`  ${label.padEnd(10)} ${chalk.red(`+${c.added} new`)}  ${chalk.green(`-${c.removed} fixed`)}  ${chalk.dim(`${c.unchanged} unchanged`)}`);
	line("CVE", s.cve); line("EOL", s.eol); line("Obsolete", s.obsolete); line("Outdated", s.outdated); line("Licenses", s.licenses);
	console.log();
	const sev = Object.entries(s.cve.addedBySeverity).filter(([, n]) => n).map(([k, n]) => `${n} ${k.toLowerCase()}`).join(", ") || "none";
	console.log(`  ${chalk.bold("New production CVE findings:")} ${newProd ? chalk.red.bold(newProd) : chalk.green("0")}  ${chalk.dim(`(${sev})`)}`);
	const newCves = (d.cve.added || []).filter(f => !f.suppressed && !f.cpeFiltered);
	for (const f of newCves.slice(0, 25)) console.log(`    ${chalk.red("•")} ${f.id}  ${chalk.dim((f.severity || "") + " · " + ((f.dep && f.dep.coord) || "") + "@" + ((f.dep && f.dep.version) || ""))}`);
	if (newCves.length > 25) console.log(chalk.dim(`    …and ${newCves.length - 25} more`));
	if (jsonOut) {
		const out = { tool: "vigievuln", kind: "fad-diff/1", baseline: basePath, current: curPath, summary: s, diff: d };
		try { fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true }); } catch { /* ignore */ }
		fs.writeFileSync(jsonOut, JSON.stringify(out, null, 2) + "\n");
		console.log(chalk.green(`\n✅ diff written → ${jsonOut}`));
	}
	console.log();
	process.exit(failOnNew && newProd > 0 ? 1 : 0);
}

// -------- `vigievuln serve-cache` subcommand (pre-parse) --------
// A long-running shared cache for the public data sources. Other instances point at it
// with `--proxy-cache http://host:port` and stop making their own upstream calls:
// one lookup per URL per TTL for the whole fleet, served from a persistent on-disk
// store that survives restarts (and ships inside --export-cache archives). Mirrors
// the other pre-parse intercepts so it never collides with the main option set.
if (process.argv[2] === "serve-cache") {
	const arg = (name, def) => {
		const i = process.argv.indexOf(name);
		return i > -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("-") ? process.argv[i + 1] : def;
	};
	const port = parseInt(arg("--port", "8321"), 10);
	const host = arg("--host", "127.0.0.1");
	const cacheDir = arg("--cache-dir", null);
	const ttlS = parseInt(arg("--ttl", "0"), 10);
	const maxMb = parseFloat(arg("--max-body-mb", "32"));
	const token = arg("--token", null);
	const swr = !process.argv.includes("--no-swr");
	// --upstream-proxy was already applied by the pre-parse re-exec above (it must be
	// in the environment at process start); read it back just for the banner.
	const upstreamProxy = arg("--upstream-proxy", null);
	// API keys the SERVER injects upstream, so the instances behind it need none:
	// flags > env > persisted config. Same wire formats as the scan-side lanes
	// (lib/nvd.js `apiKey` header, Wordfence/GitHub `Authorization: Bearer`).
	const { getNvdApiKey } = require("./lib/config");
	const keys = {
		nvd: arg("--nvd-key", null) || process.env.NVD_API_KEY || getNvdApiKey() || null,
		wordfence: arg("--wordfence-key", null) || process.env.WORDFENCE_API_KEY || null,
		github: arg("--github-token", null) || process.env.GITHUB_TOKEN || null,
	};
	const { startProxyCacheServer, DEFAULT_CACHE_DIR, CLIENT_CACHE_DIR, createCacheStore } = require("./lib/proxy-cache");
	const storeDir = path.resolve(cacheDir || DEFAULT_CACHE_DIR());
	// The scan's per-pass caches and the shared server base are two different roles:
	// a store inside ~/.vigie-vuln/ would be bundled/swapped by --export-cache /
	// --import-cache together with the client's own caches. Separate roots, always.
	const clientRoot = path.resolve(CLIENT_CACHE_DIR());
	if (storeDir === clientRoot || storeDir.startsWith(clientRoot + path.sep)) {
		console.warn(chalk.yellow(`⚠️  --cache-dir is inside the client cache root (${clientRoot}) — --export-cache/--import-cache would bundle or swap the shared base together with the scan's own caches. Keep the two stores separate.`));
	}
	// --seed <dump.manifest.json>: fill the store from a vigievuln dump before serving
	// (an air-gapped relay seeded from a signed build). --trust-key <public.pem> makes the
	// signature mandatory; the payload sha256 is always checked. --seed-only exits after.
	const seedManifest = arg("--seed", null);
	const trustKey = arg("--trust-key", null);
	const seeding = !seedManifest ? Promise.resolve() : (async () => {
		const { openDump, seedResourceStore, keyFingerprint } = require("./lib/dump-format");
		const publicKeyPem = trustKey ? fs.readFileSync(trustKey, "utf8") : null;
		const { manifest, payloadPath } = await openDump(seedManifest, { publicKeyPem });
		if (!publicKeyPem) console.warn(chalk.yellow("⚠️  --seed without --trust-key: integrity checked (sha256), origin NOT verified"));
		else console.log(chalk.gray(`   signature ok — key ${keyFingerprint(publicKeyPem)}`));
		const r = await seedResourceStore(createCacheStore(storeDir), payloadPath);
		console.log(chalk.green(`✅  seeded from ${manifest.id} (${manifest.createdAt}): ${r.imported} entries imported, ${r.kept} kept (fresher locally)`));
		if (process.argv.includes("--seed-only")) process.exit(0);
	})();
	seeding.then(() => startProxyCacheServer({
		port, host,
		store: createCacheStore(storeDir),
		overrideTtlMs: ttlS > 0 ? ttlS * 1000 : null,
		maxBodyBytes: maxMb * 1024 * 1024,
		maxTransferBytes: Number(arg("--max-transfer-mb", "1024")) * 1024 * 1024,
		maxStoreBytes: Number(arg("--max-store-mb", "2048")) * 1024 * 1024,
		upstreamTimeoutMs: Number(arg("--upstream-timeout", "120")) * 1000,
		maxConcurrent: Number(arg("--max-concurrent", "16")),
		maxEntries: Number(arg("--max-entries", "10000")),
		token, swr, keys,
	})).then(({ server, url }) => {
		console.log(chalk.green(`✅  proxy-cache listening on ${url}`));
		console.log(chalk.gray(`   store:    ${storeDir}  (persists across restarts; separate from the scan's own ~/.vigie-vuln/ caches)`));
		console.log(chalk.gray(`   upstream: ${upstreamProxy ? "via corporate proxy" : "direct"}`));
		console.log(chalk.gray(`   stats:    ${url}/__stats    clear: POST ${url}/__clear`));
		const active = Object.entries(keys).filter(([, v]) => v).map(([k]) => k);
		console.log(chalk.gray(`   api keys: ${active.length ? active.join(", ") + " (injected upstream; instances behind --proxy-cache need none)" : "none configured (client-sent credentials are forwarded as-is)"}`));
		console.log(chalk.gray(`   point scans at it with:  --proxy-cache ${url}`));
		if (host === "0.0.0.0" && !token) console.log(chalk.yellow("⚠️  bound on all interfaces without --token: anyone on the network can read/drive this cache"));
		const stop = () => server.close(() => process.exit(0));
		process.on("SIGINT", stop);
		process.on("SIGTERM", stop);
	}).catch(err => {
		console.error(chalk.red(`❌  serve-cache failed to start: ${err.message}`));
		process.exit(1);
	});
	return;
}

const USAGE = `scan <dir> [options]
       vigievuln watch <dir> (--name <name> | --id <id> | --export <file>) [options]
       vigievuln login | logout | whoami`;

// Every help surface names the running build: a user reading `--help` (or a bare
// invocation) is often checking WHICH version they have before reporting something.
const TITLE_LINE = `${ui.TITLE_A} v${pkg.version} · ${ui.TITLE_B}`;

program
	.name(pkg.name)
	.version(pkg.version, "-v, --version", "output the version number")
	.showHelpAfterError()
	.addHelpText("beforeAll", () => chalk.cyan(TITLE_LINE) + "\n")
	.usage(USAGE)
	.description(require("./lib/cli-command-routing").COMMAND_HELP.trim())
	.option("-t, --target <target>", "EXTRACTION mode: write the cleaned tree to <dir>; non-empty dir requires --force")
	// Not a requiredOption: --import-anonymized scans a descriptor with no source tree.
	.option("-s, --src <src>", "source directory (legacy alternative to scan <dir>)")
	.option("--source <src>", "alias of --src")
	.option("--config <file>", "load default options from a trusted JSON file")
	.option("-d, --disable <list>", "turn features OFF (comma-separated) — see the token list below")
	.option("-a, --activate <list>", "turn ON what is off by default (comma-separated) — see below")
	.option("-r, --report <list>", "outputs to write, comma-separated: html,doc,xlsx,sbom,csaf,json,sarif (default: html,json)")
	.option("--help-all", "show all flags, cache and config commands")
	.option("-e, --exclude <exclude>", "regex of groupId/name to exclude, e.g. '^(client|private)\\.'")
	.option("--exclude-path <glob...>", "ignore sub-paths during the walk (gitignore-style glob, relative to --src). Repeatable")
	.option("--no-default-excludes", "walk everything, including node_modules/vendor/target/…")
	.option("--verbose", "verbose")   // -v is the version flag; verbose is long-form only
	// Defaults: report + transitive + allLibs all ON. Use --no-* to disable.
	.option("--no-report", "write NO output files at all — the scan, terminal summary and --fail-on gate still run (gate-only / CI mode)")
	.option("--no-transitive", "skip transitive dependency resolution")
	.option("--no-all-libs", "skip Maven Central queries (outdated check + missing-on-central check)")
	.option("--no-osv", "skip OSV.dev (Google/GitHub aggregated Maven CVE feed)")
	.option("--no-packagist-audit", "skip the Packagist security-advisories lane for Composer deps (the data `composer audit` queries — closes CVEs OSV carries without composer coordinates)")
	.option("--no-nvd", "skip NIST NVD enrichment of matched CVEs")
	.option("--nvd-cpe-match", "ALSO match deps against NVD CPE version ranges (opt-in, LOW PRECISION: ~12% of the findings it adds were corroborated by another scanner — triage aid, not a default)")
	.option("--no-epss", "skip EPSS (FIRST.org exploit-prediction) enrichment")
	.option("--no-eol", "skip the end-of-life check (endoflife.date)")
	.option("--no-kev", "skip CISA KEV (known-exploited) enrichment")
	.option("--no-euvd", "skip ENISA EUVD enrichment (EUVD id + ENISA exploited catalogue)")
	.option("--no-certfr", "skip CERT-FR (ANSSI) advisory references")
	// Output family: each --report-<type> takes an OPTIONAL path (omit → default name
	// under --report-output). With NO --report-* flag at all, HTML + findings JSON are written
	// by default. --no-report writes nothing (scan + gate only).
	.option("--report-html [file]", "write the self-contained HTML report (default: <report-output>/cve-report.html)")
	.option("--report-doc [file]", "write the Word-compatible .doc report (default: <report-output>/cve-report.doc)")
	.option("--report-xlsx [file]", "write an Excel workbook (default: <report-output>/findings.xlsx)")
	.option("--report-sbom [file]", "write a CycloneDX 1.6 SBOM, vulnerabilities inline (default: <report-output>/sbom.cdx.json)")
	.option("--report-csaf [file]", "write a CSAF 2.0 VEX document (default: <report-output>/csaf-vex.json)")
	.option("--report-json [file]", "write a flat machine-readable findings JSON (default: <report-output>/findings.json)")
	.option("--report-sarif [file]", "write a SARIF 2.1.0 log for GitHub/GitLab code scanning (default: <report-output>/fad.sarif)")
	.option("--fail-on <level>", "exit non-zero if a production finding meets <level>: low|medium|high|critical|kev|none", "none")
	.option("--baseline <file>", "diff this scan against a prior findings.json (adds a Δ chapter)")
	.option("--fail-on-new", "also fail on any NEW production CVE vs --baseline")
	.option("--fail-on-incomplete [capabilities]", "exit 2 for incomplete checks (inventory,advisories,recipes,sources)")
	.option("--no-checksums", "don't write a SHA256SUMS integrity manifest alongside the report files")
	.option("--ignore <file>", "triage file: CVE ids / coord globs to suppress")
	.option("--vex <file>", "ingest a CSAF VEX and suppress what it marks not-affected/fixed")
	.option("--licenses", "run license detection + copyleft policy check (off by default)")
	.option("--offline", "no network: use cached CVE/OSV/NVD/EPSS/KEV/POM data only")
	.option("--no-nvd-mirror", "NVD only: don't fall back to the fkie-cad/nvd-json-data-feeds mirror when NVD does not answer")
	.option("--retries <n>", "retries (waiting 5+n s each) before a data source is marked unavailable; 0 = none", "5")
	.option("--proxy-cache <url|vigievuln|default>", "shared data-source cache or official VigieVuln proxy")
	.option("--set-proxy-cache <url|vigievuln|default>", "save the proxy cache for future scans")
	.option("--unset-proxy-cache", "remove the saved proxy cache")
	.option("--set-proxy-cache-token <token>", "save a proxy key for future scans")
	.option("--unset-proxy-cache-token", "remove the saved proxy key")
	.option("--vigievuln-proxy [domain]", "legacy hosted cache option: fr or com")
	.option("--proxy-cache-token <token>", "authenticate to a shared proxy-cache server (or set VIGIEVULN_PROXY_CACHE_TOKEN)")
	.option("--proxy <url>", "corporate proxy for all requests")
	.option("--set-nvd-key <key>", "save NVD API key to ~/.vigie-vuln/config.json (10× faster NVD enrichment)")
	.option("--show-config", "print the persisted ~/.vigie-vuln/config.json")
	.option("--export-cache <file>", "tar.gz/zip the ~/.vigie-vuln/ caches to <file> (excludes config.json by default)")
	.option("--import-cache <file>", "merge a previously exported archive into ~/.vigie-vuln/ (keeps the local cache + config.json; newest entry wins)")
	.option("--replace", "with --import-cache: replace ~/.vigie-vuln/ wholesale instead of merging (previous dir kept as .bak unless --force)")
	.option("--include-config", "with --export-cache: also bundle config.json (contains the NVD API key)")
	.option("--export-anonymized <file>", "offline: write a path-free dependency descriptor and exit")
	.option("--prepare-project <file>", "offline: prepare a path-free project descriptor for review")
	.option("--import-anonymized <file>", "online, no --src: scan a descriptor to warm the caches")
	.option("--force", "allow replacing a non-empty --target directory; with --import-cache --replace, skip backup")
	.option("-o, --report-output <dir>", "report output directory", "./vigievuln-report")
	.option("--ignore-test", "skip test-scoped dependencies in report")
	.option("--cve-refresh", "force re-download of CVE database")
	.option("--cve-offline", "use cached CVE index only (no download)")
	.option("--osv-db", "import + match the full local OSV database (Maven, ~9 MB) — offline-complete recall, independent of the per-dep OSV cache. Never imported implicitly, and never under --offline; once imported, later Maven/Gradle scans reuse the cached index automatically")
	.option("--no-osv-db", "skip the local OSV database even when its index is already cached")
	.option("--osv-db-refresh", "force re-download of the local OSV database")
	.option("--snyk", "run snyk on cleaned POMs and merge into report (requires --target)")
	.option("--typosquat", "flag npm/PyPI deps whose name is one edit from a popular package (heuristic typosquat/slopsquat detection)")
	.option("--no-retire", "skip retire.js vendored-JS scan")
	.option("--no-vendored-js-inventory", "don't list ALL identified vendored JS libs (chapter 1D) — keep only the vulnerable ones (chapter 2)")
	.option("--retire-refresh", "ignore retire cache and re-scan")
	.option("--transitive-depth <n>", "max transitive resolution depth", "6")
	.option("--ecosystem <list>", "auto (default) | all | comma list of codec ids", "auto")
	.option("--app-plugins <list>", "auto (default) | none | all | comma list of bundled application plugins", "auto")
	.option("--scan-context <kind>", "application input context: source (default) | installation | component", "source")
	.option("--list-app-plugins", "list bundled application plugins and their qualified capabilities")
	.option("--private-component <path>", "mark an application component path private; repeatable", (value, list) => [...list, value], [])
	.option("--public-component <path=slug>", "verify a public WordPress plugin/theme catalogue slug; repeatable", (value, list) => [...list, value], [])
	.option("--wordfence-feed <file>", "local Wordfence v3 vulnerability feed JSON snapshot for WordPress advisories")
	.option("--drupal-advisories <file>", "local packages.drupal.org security-advisories JSON snapshot")
	.option("--wordfence-live", "query Wordfence advisories (targeted software projection through a proxy; direct feed requires a client key)")
	.option("--wordfence-feed-url <url>", "override the official Wordfence v3 production-feed URL for a live scan; custom URLs require a client API key")
	.option("--wordfence-api-key <key>", "Wordfence v3 bearer key for a live feed (or set WORDFENCE_API_KEY)")
	.option("--drupal-advisories-live [url]", "query the official packages.drupal.org security-advisories API live for the inventoried Drupal packages")
	.option("--prestashop-advisories <file>", "local PrestaShop Github security-advisories JSON snapshot (the publisher's own machine feed)")
	.option("--prestashop-advisories-live [url]", "query the official PrestaShop Github security-advisories feed live for the inventoried PrestaShop components")
	.option("--typo3-advisories <file>", "local TYPO3 Github security-advisories JSON snapshot (the publisher's own machine feed)")
	.option("--typo3-advisories-live [url]", "query the official TYPO3 Github security-advisories feed live for the inventoried TYPO3 components")
	.option("--spip-advisories <file>", "local NVD SPIP security-advisories JSON snapshot (the only machine-readable SPIP source)")
	.option("--spip-advisories-live [url]", "query the NVD SPIP product CVEs (cpe:2.3:a:spip:spip) live for the observed SPIP core version")
	.option("--wp-checksums <file>", "local api.wordpress.org core checksums JSON snapshot to compare the WordPress core files against")
	.option("--wp-checksums-live [url]", "fetch the official api.wordpress.org core checksums live and compare the WordPress core files; divergences are diagnostics, not CVEs")
	.option("--wp-checksums-locale <locale>", "locale of the WordPress distribution checksums reference (default en_US)", "en_US")
	.option("--max-advisory-age <duration>", "reject advisory snapshots older than this (e.g. 72h, 30d); the snapshot must declare its collection date")
	.option("--no-maven", "skip the Maven codec")
	.option("--no-gradle", "skip the Gradle codec")
	.option("--no-npm", "skip the npm codec")
	.option("--no-yarn", "skip the Yarn codec")
	.option("--no-nuget", "skip the NuGet (C#/.NET) codec")
	.option("--no-composer", "skip the Composer (PHP) codec")
	.option("--no-pypi", "skip the PyPI (Python) codec")
	.option("--no-go", "skip the Go codec")
	.option("--no-ruby", "skip the Ruby (Bundler) codec")
	.option("--no-binaries", "skip scanning committed native binaries (.dll/.exe/.so/.dylib)")
	.option("--no-jars", "skip scanning embedded .jar/.war/.ear binaries for Maven coordinates")
	.option("--no-certs", "skip scanning committed certificates, private/public keys (PEM/SSH/PuTTY/PGP) and keystores")
	.option("--cert-expiry-days <n>", "warn on certificates expiring within N days", "90")
	.option("--lang <code>", "report language: en (default) or fr. Chrome + CWE titles only, never the advisory text", "en")
	.option("--eol-support", "also report frameworks/runtimes whose active (bug-fix) support has ended but still receive security fixes (status: unsupported)")
	.option("--no-js", "alias: skip JS/npm/yarn manifests even if present (Maven-only)")
	.option("--repo <eco=url...>", "extra registry as <ecosystem>=<url>, tried before the public one. Repeatable")
	.option("--add-repo <eco>", "persist a registry: --add-repo <ecosystem> <name> <url> [--auth user:pass] [--token TOK]")
	.option("--remove-repo <eco>", "remove a persisted registry: --remove-repo <ecosystem> <name>")
	.option("--list-repos", "list configured registries (grouped by ecosystem) and exit")
	.option("--auth <user:pass>", "Basic auth for --add-repo")
	.option("--token <token>", "Bearer token for --add-repo")
	.option("--completion <shell>", "print shell completion script (bash|zsh)");

// The -d / -a vocabularies, laid out once under the options instead of wrapped inside two
// option descriptions where they cost fifteen lines.
program.addHelpText("after", `
  -d  eol nvd nvd-mirror osv packagist-audit epss kev euvd certfr retire transitive all-libs checksums
      osv-db report vendored-js-inventory default-excludes
      maven gradle npm yarn nuget composer pypi go ruby js jars binaries certs
  -a  licenses eol-support typosquat snyk osv-db nvd-cpe-match cve-refresh
      cve-offline osv-db-refresh retire-refresh

  e.g.  vigievuln scan . -d nvd,epss,certs -a licenses,typosquat -o ./audit
  --help-all lists the individual flags these replace.  Full guide: docs/USAGE.md`);
// -d / -a fold thirty-six boolean flags into two lists. The flags still WORK — hiding them
// costs nothing and breaks no existing script, whereas removing them would break every one
// in the wild to achieve the same one-screen help. --help-all shows them.
if (!process.argv.includes("--help-all")) {
	const { foldedFlags } = require("./lib/cli-groups");
	const { ADMIN_FLAGS, REPORTS } = require("./lib/cli-groups");
	const folded = new Set([...foldedFlags(), ...ADMIN_FLAGS, ...REPORTS.map(r => `--report-${r}`),
		"--list-app-plugins", "--scan-context", "--private-component", "--public-component", "--wordfence-live", "--wordfence-feed", "--drupal-advisories", "--wordfence-feed-url", "--drupal-advisories-live", "--prestashop-advisories", "--prestashop-advisories-live", "--typo3-advisories", "--typo3-advisories-live", "--spip-advisories", "--spip-advisories-live", "--wp-checksums", "--wp-checksums-live", "--wp-checksums-locale", "--max-advisory-age", "--fail-on-incomplete", "--proxy-cache-token"]);
	for (const opt of program.options) if (folded.has(opt.long)) opt.hidden = true;
} else {
	process.argv = process.argv.map(a => a === "--help-all" ? "--help" : a);
}
// Back-compat: -V was the version flag before -v was freed from --verbose. commander
// allows a single short flag per option, so alias it in argv rather than declare it.
if (process.argv.includes("-V")) process.argv = process.argv.map(a => a === "-V" ? "--version" : a);
// Back-compat: license detection is now OFF by default (enable with --licenses).
// A legacy `--no-licenses` is therefore a no-op — drop it so old invocations don't
// trip commander's unknown-option error.
if (process.argv.includes("--no-licenses")) process.argv = process.argv.filter(a => a !== "--no-licenses");
// -------- bare invocation → a mini help --------
// Typing just the tool's name is a question ("what is this, which version, how do I
// run it"), not a malformed command; commander's "required option --src" error answers
// none of it. Runs before parse so that error never fires. Exit stays non-zero: nothing
// was scanned, so this must not read as a clean run to a CI job that mis-invoked it.
// A lone --verbose is included: verbose modifies a scan, and there is no scan here, so it
// would otherwise die on "required option --src" without answering what the user asked.
const BARE_ARGV = process.argv.length <= 2
	|| (process.argv.length === 3 && process.argv[2] === "--verbose");
if (BARE_ARGV) {
	ui.banner(pkg.version);
	console.log(`
  Audit a source tree for ${chalk.bold("vulnerable")}, ${chalk.bold("end-of-life")}, ${chalk.bold("obsolete")} and ${chalk.bold("outdated")} dependencies.
  Maven · Gradle · npm · Yarn · pnpm · Composer · PyPI · NuGet · Go · Ruby — no build tool needed.

  ${chalk.cyan("vigievuln scan <dir>")}                 full report: CVE + EOL + obsolete + outdated + licenses
  ${chalk.cyan("vigievuln -s <dir> --offline")}         air-gapped: warmed cache only, zero network
  ${chalk.cyan("vigievuln -s <dir> --fail-on high")}    CI gate: exit 1 on a high+ production CVE
  ${chalk.cyan("vigievuln watch <dir> --name <name>")}    upload local dependencies for project monitoring
  ${chalk.cyan("vigievuln watch <dir> --export <file>")}  local descriptor only, no login or upload
  ${chalk.cyan("vigievuln login | logout | whoami")}     account session (legacy auth commands still work)
  ${chalk.cyan("vigievuln project status")}              list your monitored projects

  ${chalk.dim("-h, --help")} for every option · ${chalk.dim("-v, --version")} · ${chalk.dim("docs/USAGE.md")} for the full guide
`);
	process.exit(1);
}

program.parse(process.argv);

const options = program.opts();
// Layered config: CLI flags > explicitly selected config file (--config, JSON) >
// FAD_CHECKER_ENV (a CLI-flag string) > global ~/.vigie-vuln/config.json >
// commander defaults. A file/env value fills an option only if the CLI didn't
// set it. `registries` are unioned separately (below). Source has src/source aliases.
const { loadLayers, applyLayers } = require("./lib/options-env");
let _layers = { fileLayer: {}, envLayer: {}, envRepos: [] };
try {
	_layers = loadLayers({ cwd: process.cwd(), configPath: options.config, program });
} catch (err) {
	console.error(chalk.red(`❌  ${err.message}`));
	process.exit(1);
}
Object.assign(options, applyLayers(program, _layers, require("./lib/config").load()));
// An anonymized export is strictly local, including proxy resolution and preflight.
if (options.exportAnonymized || options.prepareProject) options.offline = true;
let hostedAccountSession = null;
if (!options.offline && !options.proxyCacheToken && !process.env.VIGIEVULN_PROXY_CACHE_TOKEN && !process.env.FAD_PROXY_CACHE_TOKEN &&
	(options.vigievulnProxy || /^(default|vigievuln|https:\/\/api\.vigievuln\.(fr|com)\/?$)$/i.test(String(options.proxyCache || "")))) {
	try { hostedAccountSession = require("./lib/account-session").createAccountSessionStore().read(); }
	catch (err) { console.error(chalk.red(`❌  ${err.message}`)); process.exit(2); }
}
try { Object.assign(options, require("./lib/hosted-proxy").resolveHostedProxy({ ...options, allowProxyLogin: !!hostedAccountSession || !!(process.stdin.isTTY && process.stderr.isTTY) })); }
catch (err) { console.error(chalk.red(`❌  ${err.message}`)); process.exit(2); }
// A saved official account key must never follow a changed proxy URL to an
// unrelated service. Custom proxies require a token supplied for this run.
if (options.proxyCache && !options.vigievulnProxy && options.proxyCacheToken &&
    !program.getOptionValueSource('proxyCacheToken')?.match(/^(cli|env)$/) &&
    !Object.hasOwn(_layers.fileLayer, 'proxyCacheToken') && !Object.hasOwn(_layers.envLayer, 'proxyCacheToken') &&
    !process.env.VIGIEVULN_PROXY_CACHE_TOKEN && !process.env.FAD_PROXY_CACHE_TOKEN) {
	console.error(chalk.red('❌  A saved proxy key cannot be sent to a custom proxy. Supply its token explicitly for this run.'));
	process.exit(2);
}
// --source CLI alias → src (applyLayers already maps the file/env JSON 'source' key).
if (!options.src && options.source) options.src = options.source;

// -d / -a are applied BEFORE the layered config so a config file can still override them
// the same way it overrides any other option.
{
	const { applyGroups } = require("./lib/cli-groups");
	const { applyReports } = require("./lib/cli-groups");
	const { errors } = applyGroups(options, { disable: options.disable, activate: options.activate });
	errors.push(...applyReports(options, options.report && options.report !== true ? options.report : "").errors);
	if (errors.length) {
		for (const e of errors) console.error(chalk.red(`❌  ${e}`));
		process.exit(2);
	}
}
const deps2Exclude = options.exclude ? new RegExp(options.exclude) : null;
if (options.vigievulnProxy && !options.offline && (options.osvDb === true || options.osvDbRefresh)) {
	console.error(chalk.red("❌  --osv-db and --osv-db-refresh download a bulk archive and cannot be used with the hosted proxy online."));
	process.exit(2);
}
const verbose = !!options.verbose;

// ---- Source health: a remote source that goes dark must not produce a quiet hole ----
// Online only, and installed before the first request of the run (collection and the Maven
// existence check both fetch before the report flow starts). Every module goes through
// globalThis.fetch, so wrapping it once covers all of them — and a lookup served from the
// warm cache issues no request at all, which IS the "100% from cache, stay silent" rule.
const sourceHealth = createSourceHealth();
try { setRetryAttempts(options.retries == null ? 5 : options.retries); }
catch (err) { console.error(chalk.red(`❌  ${err.message}`)); process.exit(2); }
if (!options.offline) {
	// The mirror/registry rotations report their own exhaustion (their requests bypass the
	// guard: they carry their own AbortSignal and failover).
	setActiveLedger(sourceHealth);
	const baseFetch = globalThis.fetch;
	// Public data clients call getResource(provider, type, params); configure its
	// transport once, before any lookup. Custom registry URLs stay direct.
	if (options.proxyCache) {
		const { configureResourceRoute } = require("./lib/providers");
		const { createCacheStore } = require("./lib/proxy-cache");
		try {
			configureResourceRoute({ proxyUrl: options.proxyCache, hosted: !!options.vigievulnProxy,
				token: options.proxyCacheToken || (process.env.VIGIEVULN_PROXY_CACHE_TOKEN ?? process.env.FAD_PROXY_CACHE_TOKEN) || null,
				health: sourceHealth, fetcher: baseFetch,
				store: options.vigievulnProxy ? null : createCacheStore(require("node:path").join(require("./lib/cache-directory").getCacheDir(), "resource-cache")) });
		} catch (err) {
			console.error(chalk.red(`❌  ${err.message}`));
			process.exit(2);
		}
		if (verbose) console.log(chalk.gray(`   proxy-cache: ${options.proxyCache}`));
	}
	globalThis.fetch = guardedFetch({
		health: sourceHealth,
		fetch: baseFetch,
		onRetry: r => ui.interject(`  ${chalk.yellow("⚠")} ${r.label} ${chalk.dim(`— ${r.code}, attempt ${r.attempt}/${r.of}, retrying in ${Math.round(r.delayMs / 1000)}s`)}`),
	});
} else if (options.proxyCache) {
	console.warn(chalk.yellow("⚠️  --proxy-cache ignored (--offline makes no requests at all)"));
}
/**
 * Provider outages are coverage warnings by default. Write the partial reports before
 * evaluating an explicitly requested --fail-on-incomplete gate.
 */
function warnIfDegraded() {
	const bad = sourceHealth.degraded();
	if (!bad.length) return;
	ui.warn(`Sources unavailable: ${bad.map(s => s.id).join(", ")}; report coverage is incomplete.`);
}

// Validate --fail-on early: an unrecognised value (typo like "hgih", wrong case)
// must HARD-FAIL, never silently disable the CI gate.
if (options.failOn) {
	const FAIL_ON_LEVELS = ["none", "low", "medium", "high", "critical", "kev"];
	const lvl = String(options.failOn).toLowerCase();
	if (!FAIL_ON_LEVELS.includes(lvl)) {
		console.error(chalk.red(`❌  invalid --fail-on "${options.failOn}" — expected one of: ${FAIL_ON_LEVELS.join(", ")}`));
		process.exit(2);
	}
	options.failOn = lvl;
}
// Read-only when no target is given. No need for an explicit --test flag.
const readOnly = !options.target;
// -t is an EXTRACTION step (walk + link the reactor + cleaned tree + POM analysis),
// not a scan. The vulnerability scan only joins the run when something explicitly
// needs its output: a Snyk merge, a report file, or a CI gate.
const scanRequested = !!(options.snyk || options.baseline || options.failOnNew
	|| options.failOnIncomplete
	|| (options.failOn && options.failOn !== "none")
	|| [options.reportHtml, options.reportDoc, options.reportXlsx, options.reportSbom, options.reportCsaf, options.reportJson, options.reportSarif].some(v => v !== undefined));
const extractOnly = !readOnly && !scanRequested;

// --src is required for every mode except --import-anonymized (which scans a
// descriptor and has no source tree).
if (!options.src && !options.importAnonymized) {
	console.error(chalk.red("❌  required option '-s, --src <src>' not specified"));
	process.exit(1);
}
if (options.src && options.importAnonymized) {
	console.warn(chalk.yellow("⚠️  --import-anonymized ignores --src (the descriptor is the source of deps)"));
}

function assertSafeExtractionTarget() {
	if (!options.src || !options.target) return;
	// --force may replace --target before writing, so it must NOT overlap --src in
	// EITHER direction: not the same dir, not a subdir of --src, and — the
	// catastrophic case — not a PARENT of --src (which would delete the source tree
	// and everything beside it).
	let srcAbs;
	try { srcAbs = fs.realpathSync(path.resolve(options.src)); }
	catch { console.error(chalk.red("❌  --src must be an existing directory")); process.exit(1); }
	const targetInput = path.resolve(options.target);
	const targetStat = fs.lstatSync(targetInput, { throwIfNoEntry: false });
	if (targetStat && (!targetStat.isDirectory() || targetStat.isSymbolicLink())) {
		console.error(chalk.red("❌  --target must be a real directory, not a file or symlink"));
		process.exit(1);
	}
	let ancestor = targetInput;
	const suffix = [];
	while (!fs.existsSync(ancestor) && path.dirname(ancestor) !== ancestor) {
		suffix.unshift(path.basename(ancestor));
		ancestor = path.dirname(ancestor);
	}
	const tgtAbs = path.join(fs.realpathSync(ancestor), ...suffix);
	const relFromSrc = path.relative(srcAbs, tgtAbs); // target as seen from src
	const relToSrc = path.relative(tgtAbs, srcAbs);   // src as seen from target
	const targetInsideSrc = !relFromSrc || (!relFromSrc.startsWith("..") && !path.isAbsolute(relFromSrc));
	const srcInsideTarget = !relToSrc || (!relToSrc.startsWith("..") && !path.isAbsolute(relToSrc));
	if (targetInsideSrc || srcInsideTarget) {
		console.error(chalk.red("❌  --target must not overlap --src (it cannot be the same as, a subdirectory of, or a parent of --src)"));
		process.exit(1);
	}
	if (targetStat) {
		if (fs.readdirSync(targetInput).length && !options.force) {
			console.error(chalk.red("❌  --target is non-empty; pass --force to replace it"));
			process.exit(1);
		}
	}
}
assertSafeExtractionTarget();

// Shared by source scans and descriptor imports, so the air-gapped warm-up also
// refreshes presence. Only per-entry, repository-scoped 404/410 evidence is trusted.
const MAVEN_EXISTS_CACHE_PATH = require("path").join(require("./lib/outdated").CACHE_DIR, "maven-exists-cache.json");
async function classifyMavenLibs(ids, repos) {
	const { loadJsonCache, saveJsonCache } = require("./lib/outdated");
	const { MAX_AGE_MS, discardUnverifiedEntries, checkMavenLibExist } = require("./lib/maven-presence");
	const cache = loadJsonCache(MAVEN_EXISTS_CACHE_PATH);
	const migrated = discardUnverifiedEntries(cache);
	let probeRepos = repos;
	if (!options.offline) {
		probeRepos = await require("./lib/maven-repo").reachableRepos(repos, { timeoutMs: 5000 });
		if (!probeRepos.length) ui.warn("no Maven repository reachable — existence check skipped, cache reused; pass --offline on an air-gapped box");
	}
	const noNetwork = options.offline || !probeRepos.length;
	const fresh = cache.meta?.fetchedAt && Date.now() - cache.meta.fetchedAt < MAX_AGE_MS;
	if (!fresh && !noNetwork) cache.entries = {};
	const limit = pLimit(10);
	const results = await Promise.all([...new Set(ids)].map(id => limit(async () => {
		const [g, a] = id.split(":");
		return { id, found: await checkMavenLibExist(g, a, probeRepos, cache, { offline: noNetwork, configuredRepos: repos }) };
	})));
	if (!noNetwork) cache.meta = { fetchedAt: Date.now() };
	if (!noNetwork || migrated) saveJsonCache(MAVEN_EXISTS_CACHE_PATH, cache);
	const absent = results.filter(r => r.found === false).map(r => r.id);
	const unknown = results.filter(r => r.found === null).length;
	if (absent.length) {
		ui.warn(`${absent.length} lib(s) absent from all configured Maven repositories (possibly private):`);
		for (const id of absent.slice(0, 10)) ui.info(chalk.magenta(id));
		if (absent.length > 10) ui.info(chalk.dim(`…and ${absent.length - 10} more`));
	}
	if (unknown) ui.info(chalk.dim(`${unknown} lib(s) with unknown registry presence — warm the presence cache online to classify them`));
	return absent;
}

/**
 * Build an onProgress callback for the embedded-JAR scan so the user sees what's
 * happening — the scan reads + unzips archives synchronously and can block for a
 * while on big or numerous fat-jars (incl. the silent recursion through a fat-jar's
 * bundled libs). The scanner reports EVERY archive (top-level + nested):
 *   - On a TTY: one transient line, rewritten in place, naming the archive being
 *     read right now (so a long pause clearly points at the culprit). Cleared at end.
 *   - Off a TTY (CI/pipe): a throttled line every ~250 archives so logs show forward
 *     motion without being spammed, plus a start and a final summary line.
 * Returns a fresh closure per codec.
 */
function makeJarProgress() {
	let total = 0, lastLogged = 0;
	const STEP = 250;
	return (ev) => {
		if (!ev) return;
		if (ev.phase === "start") {
			total = ev.total || 0;
			if (total && !ui.isTTY) ui.info(chalk.dim(`scanning ${total} embedded archive(s) (.jar/.war/.ear)…`));
		} else if (ev.phase === "scan" && total) {
			if (ui.isTTY) {
				const head = total ? `${ev.scanned}/${total}+` : String(ev.scanned);
				process.stdout.write(`\r  ${chalk.dim("·")} ${chalk.dim(`reading embedded JARs (${head})`)} ${chalk.dim(ev.path)}\x1b[K`);
			} else if (ev.scanned - lastLogged >= STEP) {
				lastLogged = ev.scanned;
				ui.info(chalk.dim(`… ${ev.scanned} archive(s) read (current: ${ev.path})`));
			}
		} else if (ev.phase === "done") {
			if (total && ui.isTTY) process.stdout.write("\r\x1b[K");
			else if (total && !ui.isTTY) ui.info(chalk.dim(`scanned ${ev.scanned} archive(s) → ${ev.found} embedded coord(s)`));
		}
	};
}

/**
 * Run `fn` (sync or async) while telling the user which phase is in flight, so a
 * long pause is attributable instead of a silent hang. TTY: a transient line that's
 * cleared when done. Non-TTY: a plain "· <label> …" line. Either way, a phase that
 * takes >3s prints "· <label> took Ns" so slow steps self-report even without -v.
 */
async function timedPhase(label, fn) {
	if (ui.isTTY) process.stdout.write(`  ${chalk.dim("·")} ${chalk.dim(label + " …")}\x1b[K`);
	else ui.info(chalk.dim(label + " …"));
	const t0 = Date.now();
	try {
		return await fn();
	} finally {
		const ms = Date.now() - t0;
		if (ui.isTTY) process.stdout.write("\r\x1b[K");
		if (ms > 3000) ui.info(chalk.dim(`${label} took ${(ms / 1000).toFixed(1)}s`));
		else if (verbose) ui.info(chalk.dim(`${label} done in ${ms}ms`));
	}
}

(async function main() {
	if (options.vigievulnProxy && !options.offline) {
		if (!options.proxyCacheToken) {
			try {
				const readline = require("node:readline");
				const { Writable } = require("node:stream");
				const ask = (prompt, secret = false) => new Promise(resolve => {
					process.stderr.write(prompt);
					const output = secret ? new Writable({ write(_chunk, _encoding, done) { done(); } }) : process.stderr;
					const rl = readline.createInterface({ input: process.stdin, output, terminal: true });
					rl.question("", answer => { rl.close(); if (secret) process.stderr.write("\n"); resolve(answer); });
				});
				if (hostedAccountSession) {
					const account = require("./lib/account-client").createAccountClient();
					const current = await account.me();
					await require("./lib/account-terms").requireTerms({account, terms:current.terms, ask});
					options.proxyCacheToken = await require("./lib/hosted-proxy").createProxyKey(account);
					require("./lib/config").set("proxyCacheToken", options.proxyCacheToken);
					require("./lib/providers").configureResourceRoute({proxyUrl:options.proxyCache,token:options.proxyCacheToken});
					console.error("Proxy key created from your signed-in account and saved for future scans.");
				} else {
				console.error("Sign in to your verified Vigie Vuln account to create a proxy key.");
				console.error("No account? Register at https://www.vigievuln.fr/account");
				const email = await ask("Email: ");
				const password = await ask("Password: ", true);
				options.proxyCacheToken = await require("./lib/hosted-proxy").loginForProxy({email,password,ask});
				require("./lib/config").set("proxyCacheToken", options.proxyCacheToken);
				require("./lib/providers").configureResourceRoute({proxyUrl:options.proxyCache,token:options.proxyCacheToken});
				console.error("Proxy key saved for future scans.");
				}
			} catch (err) { console.error(chalk.red(`❌  ${err.message}`)); process.exitCode = 2; return; }
		}
		try { await require("./lib/hosted-proxy").checkHostedProxy(options.proxyCache, options.proxyCacheToken); }
		catch (err) { console.error(chalk.red(`❌  ${err.message}`)); process.exitCode = 2; return; }
	}
	ui.banner(pkg.version);

	// Build the Maven repo list once: persisted repos (from ~/.vigie-vuln/config.json)
	// + ad-hoc --repo URLs + Maven Central as final fallback. Used by transitive
	// resolution, outdated-version check, and existence check.
	const { getRegistryMap } = require("./lib/config");
	const { buildRepoList } = require("./lib/maven-repo");
	const { buildRegistryList } = require("./lib/registries");
	// One-off --repo eco=url (from the CLI and the env layer), grouped by ecosystem.
	const cliRepoMap = {};
	for (const spec of [...(options.repo || []), ...(_layers.envRepos || [])]) {
		const m = /^([a-z]+)=(.+)$/i.exec(String(spec));
		if (!m) { console.error(chalk.red(`❌  --repo expects <ecosystem>=<url>, got "${spec}"`)); process.exit(1); }
		(cliRepoMap[m[1]] ||= []).push({ url: m[2] });
	}
	// Union the registry sources: global config + config-file JSON + CLI/env one-offs.
	const fileRegMap = (_layers.fileLayer && _layers.fileLayer.registries) || {};
	const globalRegMap = getRegistryMap();
	const regMap = {};
	for (const eco of new Set([...Object.keys(globalRegMap), ...Object.keys(fileRegMap), ...Object.keys(cliRepoMap)])) {
		regMap[eco] = buildRegistryList(eco, [globalRegMap[eco], fileRegMap[eco], cliRepoMap[eco]]);
	}
	const registriesFor = eco => regMap[eco] || [];
	const mavenRepos = buildRepoList(regMap.maven || [], []); // appends Maven Central last

	// Walk-pruning: union --exclude-path globs across every config layer (CLI + file
	// + env + global), like registries. `defaultExcludes` (a scalar, false via
	// --no-default-excludes) already flowed through applyLayers.
	const excludePath = [...new Set([
		...(options.excludePath || []),
		...((_layers.fileLayer && _layers.fileLayer.excludePath) || []),
		...((_layers.envLayer && _layers.envLayer.excludePath) || []),
		...(require("./lib/config").get("excludePath") || []),
	].filter(Boolean))];
	const defaultExcludes = options.defaultExcludes !== false;
	const walkOpts = { excludePath, defaultExcludes };
	// Anonymized export (phase 1, --export-anonymized) is a purely local operation — parse the tree,
	// emit public coordinates, exit. Force offline so no source ever touches the network.
	if (options.exportAnonymized || options.prepareProject) options.offline = true;
	const runMode = options.prepareProject ? "offline (project descriptor preparation)" : options.exportAnonymized ? "offline (anonymized export · phase 1)"
		: options.importAnonymized ? "import descriptor"
		: (options.offline ? "offline" : "online");
	if (options.src) ui.kv("source", chalk.white(options.src));
	if (mavenRepos.length > 1) ui.kv("repos", chalk.white(mavenRepos.map(r => r.name).join(chalk.dim(" → "))));
	const otherRegs = Object.keys(regMap).filter(e => e !== "maven" && regMap[e].length);
	if (otherRegs.length) ui.kv("registries", chalk.white(otherRegs.map(e => `${e}:${regMap[e].length}`).join(" ")));
	if (excludePath.length) ui.kv("exclude-path", chalk.white(excludePath.join(chalk.dim(", "))));
	if (!defaultExcludes) ui.kv("default-excludes", chalk.yellow("off (walking node_modules/vendor/.git/…)"));
	ui.kv("mode", chalk.white(runMode));

	let wrotePom = 0;

	// --- Anonymized phase 2: import a descriptor instead of collecting ---
	// Scans the descriptor's public coordinates online to WARM the coordinate-keyed
	// caches (OSV/NVD/CVE/registry/EOL) + retire signatures. Pair with --export-cache.
	if (options.importAnonymized) {
		const { deserializeDeps } = require("./lib/deps-descriptor");
		let descriptor;
		try { descriptor = JSON.parse(fs.readFileSync(options.importAnonymized, "utf8")); }
		catch (e) { console.error(chalk.red(`❌  could not read --import-anonymized file: ${e.message}`)); process.exit(1); }
		let imported;
		try { imported = deserializeDeps(descriptor); }
		catch (e) { console.error(chalk.red(`❌  invalid descriptor: ${e.message}`)); process.exit(1); }
		const { resolved, activeIds, runMaven, runNpm, externalParents = [], importBoms = [], propertyOverrides = {}, applications = [] } = imported;
		ui.section("Anonymized descriptor");
		ui.ok(`imported ${chalk.bold(resolved.size)} dep(s) across ${activeIds.join(", ") || "—"}`
			+ (applications.length ? ` · ${chalk.bold(applications.length)} application(s) (${[...new Set(applications.map(a => a.type))].join(", ")})` : ""));
		if (options.offline) ui.warn("--offline: caches won't warm; only useful to re-render from an already-warm cache");
		if (!resolved.size && !applications.length) { ui.warn("descriptor has no dependencies or applications — nothing to scan"); process.exit(0); }
		// Replay the external-parent / import-BOM backfill from the descriptor's carried hints.
		// Workflow B has no source tree here, so the mainline store-based backfill can't run —
		// without this, versionless deps (spring-boot-starter-*) stay unresolved and their CVE
		// caches never warm, forcing a SECOND air-gapped exchange. Online only (needs the POMs).
		if (runMaven && !options.offline && (externalParents.length || importBoms.length)) {
			const { resolveBomManagedVersions, backfillVersions } = require("./lib/maven-bom");
			const base = { repos: mavenRepos, offline: options.offline, verbose, effCache: new Map() };
			const mgmt = await resolveBomManagedVersions(importBoms, base);
			const parentMgmt = await resolveBomManagedVersions(externalParents, { ...base, via: "parent", propertyOverrides });
			for (const [k, v] of parentMgmt) if (!mgmt.has(k)) mgmt.set(k, v);
			const filled = backfillVersions(resolved, mgmt);
			if (filled) ui.ok(`backfilled ${chalk.bold(filled)} version(s) from ${externalParents.length} parent(s) + ${importBoms.length} BOM(s) in the descriptor`);
		}
		// Warm retire signatures (online) so --export-cache carries them for offline JS scanning.
		if (runNpm && !options.offline && options.retire !== false) {
			const { warmRetireSignatures } = require("./lib/retire");
			await warmRetireSignatures({ verbose });
		}
		// Warm the per-publisher CMS advisory snapshots the air-gapped phase 3 consumes
		// automatically (runner offline fallback): the Drupal feed is keyed by the
		// descriptor's drupal/* identities and PrestaShop/TYPO3 are whole-repository
		// feeds, so no source tree is needed. Application identities also justify SPIP
		// and WordPress snapshots; --wordfence-live can use a key held by the proxy.
		if (!options.offline) {
			const { warmCmsAdvisorySnapshots } = require("./lib/cms-snapshot-warm");
			try {
				const warmed = await warmCmsAdvisorySnapshots(resolved, {
					fetchImpl: (...args) => fetch(...args),
					advisoryCacheDir: path.join(require("./lib/cache-directory").getCacheDir(), "advisory-snapshots"),
					drupalUrl: typeof options.drupalAdvisoriesLive === "string" ? options.drupalAdvisoriesLive : undefined,
					prestashopUrl: typeof options.prestashopAdvisoriesLive === "string" ? options.prestashopAdvisoriesLive : undefined,
					typo3Url: typeof options.typo3AdvisoriesLive === "string" ? options.typo3AdvisoriesLive : undefined,
					spipUrl: typeof options.spipAdvisoriesLive === "string" ? options.spipAdvisoriesLive : undefined,
					applications,
					wordfenceApiKey: options.wordfenceApiKey || process.env.WORDFENCE_API_KEY || null,
					wordfenceUrl: options.wordfenceFeedUrl || undefined,
					wordfenceLive: !!(options.wordfenceLive || options.wordfenceFeedUrl),
					wpChecksumsLocale: options.wpChecksumsLocale || "en_US",
					nvdApiKey: require("./lib/config").getNvdApiKey(),
				});
				if (warmed.drupal) ui.ok(`Drupal advisory snapshot warmed (${warmed.drupal} package(s)) → advisory-snapshots/ — carried by --export-cache, reused offline`);
				if (warmed.prestashop) ui.ok("PrestaShop advisory snapshot warmed → advisory-snapshots/ — carried by --export-cache, reused offline");
				if (warmed.typo3) ui.ok("TYPO3 advisory snapshot warmed → advisory-snapshots/ — carried by --export-cache, reused offline");
				if (warmed.spip) ui.ok("SPIP advisory snapshot warmed (NVD product CVEs) → advisory-snapshots/ — carried by --export-cache, reused offline");
				for (const version of warmed.wpChecksums) ui.ok(`WordPress checksums reference warmed (${version}) → advisory-snapshots/ — carried by --export-cache, reused offline`);
				if (warmed.wordfence) ui.ok("Wordfence advisories warmed (targeted identities in proxy mode) → advisory-snapshots/ — carried by --export-cache, reused offline without a key");
			}
			catch (error) {
				console.error(chalk.red(`❌  CMS advisory snapshot warming failed: ${error.message}`));
				process.exit(2);
			}
		}
		// --import-anonymized is a cache-WARMING step (pair with --export-cache), not a
		// reporting one: the path-bearing report is produced later, offline, from the warmed
		// cache against the real source tree. So suppress the default HTML+JSON output here
		// (still honor an explicit --report-<type> if a user really wants a path-free one).
		const anyReportRequested = [options.reportHtml, options.reportDoc, options.reportXlsx, options.reportSbom, options.reportCsaf, options.reportJson, options.reportSarif].some(v => v !== undefined);
		if (!anyReportRequested) options.report = false;
		const privateLibIds = runMaven && options.allLibs
			? await classifyMavenLibs([...resolved.values()].filter(d => d.ecosystem === "maven")
				.map(d => `${d.namespace || d.groupId}:${d.name || d.artifactId}`), mavenRepos)
			: [];
		await runReportFlow(resolved, { activeIds, runMaven, runNpm, privateLibIds, mavenRepos, regMap, collectWarnings: [], walkOpts });
		return;
	}

	// --- Codec detection + selection ---
	const { detectCodecs, allCodecs, getCodec } = require("./lib/codecs");
	const { resolveActiveCodecs } = require("./lib/codecs/select");
	const eco = (options.ecosystem || "auto").toLowerCase();
	const detected = (eco === "auto")
		? (await timedPhase("detecting ecosystems", () => detectCodecs(options.src, walkOpts))).map(c => c.id)
		: allCodecs().map(c => c.id);
	// The binary scanner is a cross-cutting catch-all (committed native libs in ANY
	// project), and detectCodecs' manifest-glob matcher misses versioned sonames
	// (libz.so.1). Always make it a candidate in auto mode; --no-binaries removes it.
	if (eco === "auto" && !detected.includes("binary")) detected.push("binary");
	const noCodecs = ["maven", "gradle", "npm", "yarn", "nuget", "composer", "pypi", "go", "ruby"].filter(id => options[id] === false);
	// `--no-binaries` maps to options.binaries (plural) but the codec id is `binary`.
	if (options.binaries === false) noCodecs.push("binary");
	const activeIds = resolveActiveCodecs(eco, detected, { noCodecs, noJs: !options.js });
	const runMaven = activeIds.includes("maven");
	const runGradle = activeIds.includes("gradle");
	const runNpm = activeIds.includes("npm") || activeIds.includes("yarn");

	// --- Collect deps from every active codec into one Map (coordKeys never collide) ---
	// Section header first so the embedded-JAR scan can print live progress under it
	// (the scan reads + unzips archives synchronously and would otherwise block silently).
	ui.section("Collection");
	const resolved = new Map();
	let mavenCtx = null;
	let gradleCtx = null;
	let composerCtx = null;
	const collectWarnings = [];
	// Every descriptor file each codec actually parsed (tagged with its ecosystemType =
	// codec id), so the report's "Scanned dependency descriptors" appendix is a COMPLETE
	// inventory — including files parsed that contributed no scannable dep (ranges-only /
	// no lockfile), which would otherwise be invisible.
	const parsedManifests = [];
	for (const id of activeIds) {
		if (id === "yarn") continue;   // the npm codec already collects yarn.lock
		const codec = getCodec(id);
		let res;
		try {
			res = await timedPhase(`collecting ${codec.label || id}`, () => codec.collect(options.src, { ignoreTest: !!options.ignoreTest, deps2Exclude, verbose, scanJars: options.jars !== false, srcRoot: options.src, excludePath, defaultExcludes, onJarProgress: makeJarProgress(), onBinaryProgress: null }));
		} catch (err) {
			console.warn(chalk.red(`❌  ${id} collect failed:`), chalk.dim(err.message));
			continue;
		}
		for (const [k, v] of res.deps) {
			// Maven and Gradle both key a coordinate as bare `g:a`. In a hybrid tree the second
			// codec used to OVERWRITE the first's record — a Gradle constraint on a coord a pom
			// declares turned the Maven dependency into a managed-only pin, dropped later. Keep
			// both: the later one is filed under a build-tool-qualified key (matching reads
			// groupId/artifactId, not the key).
			const prev = resolved.get(k);
			if (prev && prev.ecosystem === v.ecosystem && (prev.ecosystemType || prev.ecosystem) !== (v.ecosystemType || v.ecosystem)) {
				const alt = `${v.ecosystemType}:${k}`;
				v.coordKey = alt;
				resolved.set(alt, v);
				continue;
			}
			resolved.set(k, v);
		}
		if (res.warnings?.length) collectWarnings.push(...res.warnings);
		for (const p of (res.parsedManifests || [])) parsedManifests.push({ path: p, ecosystemType: id });
		if (id === "maven") mavenCtx = res._maven;
		if (id === "gradle") gradleCtx = res._gradle;
		if (id === "composer") composerCtx = res._composer;
	}

	// --- Collection summary ---
	const ecoCount = {};
	let embeddedCount = 0;
	let binaryCount = 0;
	for (const d of resolved.values()) {
		if (d.provenance === "embedded") { embeddedCount++; continue; } // counted separately below
		if (d.provenance === "binary") { binaryCount++; continue; }     // committed native libs, no manifest
		// Key by ecosystemType so Gradle (ecosystem "maven") gets its own line/label.
		const ecoKey = d.ecosystemType || d.ecosystem;
		ecoCount[ecoKey] = (ecoCount[ecoKey] || 0) + 1;
	}
	if (runMaven) ui.ok(`${chalk.bold("Maven".padEnd(8))} ${mavenCtx ? mavenCtx.pomFiles.length + " module(s) · " : ""}${ecoCount.maven || 0} direct dep(s)`);
	if (runGradle) ui.ok(`${chalk.bold("Gradle".padEnd(8))} ${ecoCount.gradle || 0} direct dep(s)`);
	if (runNpm)   ui.ok(`${chalk.bold("npm/yarn".padEnd(8))} ${ecoCount.npm || 0} dep(s)`);
	for (const [id, n] of Object.entries(ecoCount)) {
		if (id === "maven" || id === "gradle" || id === "npm") continue;
		ui.ok(`${chalk.bold(((getCodec(id)?.label) || id).padEnd(8))} ${n} dep(s)`);
	}
	if (embeddedCount) ui.ok(`${chalk.bold("Embedded".padEnd(8))} ${embeddedCount} coord(s) in .jar/.war/.ear`);
	if (binaryCount) ui.ok(`${chalk.bold("Binary".padEnd(8))} ${binaryCount} native lib(s) (.dll/.exe/.so/.dylib)`);
	if (!ecoCount.maven && !ecoCount.npm && !Object.keys(ecoCount).length) ui.warn("no dependencies found in the source tree");
	if (collectWarnings.length) {
		ui.warn(`${collectWarnings.length} manifest warning(s) — best-effort / no lockfile:`);
		for (const w of collectWarnings.slice(0, 5)) ui.info(chalk.dim(w.message));
		if (collectWarnings.length > 5) ui.info(chalk.dim(`…and ${collectWarnings.length - 5} more`));
	}

	// --- Anonymized phase 1: export a descriptor and exit (no network, no report) ---
	if (options.prepareProject) {
		const descriptor = require("./lib/project-descriptor").buildProjectDescriptor(resolved, {generator:`vigievuln ${pkg.version}`});
		try { fs.writeFileSync(options.prepareProject, JSON.stringify(descriptor, null, 2) + "\n", {mode:0o600}); fs.chmodSync(options.prepareProject,0o600); }
		catch (e) { console.error(chalk.red(`❌  could not write project descriptor: ${e.message}`)); process.exitCode=1; return; }
		const counts = Object.fromEntries(["direct","transitive","unknown"].map(k=>[k,descriptor.deps.filter(d=>d.relation===k).length]));
		ui.ok(`Project descriptor saved: ${counts.direct} direct, ${counts.transitive} transitive, ${counts.unknown} unknown.`);
		ui.warn("Review coordinates before sharing: private package names and versions can identify your project.");
		return;
	}
	if (options.exportAnonymized) {
		const { serializeDeps } = require("./lib/deps-descriptor");
		const { collectExternalParents, collectImportBoms, collectPropertyOverrides, collectVersionPropertyNames } = require("./lib/maven-bom");
		const pkgVersion = require("./package.json").version;
		// Carry the Maven resolution hints so a no-source-tree online warm run (Phase 2) can
		// resolve the versionless deps' versions and warm their CVE caches in ONE exchange.
		const externalParents = mavenCtx?.store ? collectExternalParents(mavenCtx.store) : [];
		const importBoms = mavenCtx?.propsByPom ? collectImportBoms(mavenCtx.propsByPom) : [];
		const propertyOverrides = mavenCtx?.store ? collectPropertyOverrides(mavenCtx.store) : {};
		// Application identities (public product coordinates — type + core version, no
		// paths): they let a Phase-2 online run warm what no package coordinate carries
		// (WordPress checksums pinned by core version, publisher feeds of installs whose
		// lock holds none of the publisher's own packages). Local reads only — discovery
		// never touches the network, and a discovery failure only drops the section.
		let applications = [];
		if (options.appPlugins !== "none") {
			try {
				const { allApplicationPlugins } = require("./lib/application-plugins");
				const { runApplicationPlugins } = require("./lib/application-plugins/runner");
				const appState = await runApplicationPlugins(options.src, { plugins: allApplicationPlugins(),
					selection: options.appPlugins, resolvedDeps: resolved, activeCodecIds: activeIds, offline: true,
					publicComponents: options.publicComponent, privateComponentPaths: options.privateComponent });
				applications = appState.applications.map(app => {
					const core = appState.inventory.find(c => c.applicationId === app.id && c.kind === "core");
					// Public catalogue identities only — private/custom components never
					// leave the enclave, exactly like the live query that filters them out.
					const components = app.type === "wordpress"
						? require("./lib/application-providers/wordfence-projection").componentQueries(
							appState.inventory.filter(c => c.applicationId === app.id)).map(q => `wordpress:${q.type}:${q.slug}`)
						: [...new Set(appState.inventory
						.filter(c => c.applicationId === app.id && c.visibility !== "private"
							&& typeof c.coord === "string" && c.coord)
						.map(c => c.coord.toLowerCase()))].sort();
					return { type: app.type, version: core?.version || null, ...(components.length ? { components } : {}) };
				});
			} catch { /* the descriptor stays valid without application identities */ }
		}
		let omittedProperties = 0;
		const descriptor = serializeDeps(resolved, { generator: `vigievuln ${pkgVersion}`, externalParents, importBoms,
			propertyOverrides, versionPropertyNames: collectVersionPropertyNames(mavenCtx?.store), applications,
			onOmittedProperties: n => { omittedProperties = n; } });
		try { fs.writeFileSync(options.exportAnonymized, JSON.stringify(descriptor, null, 2) + "\n"); }
		catch (e) { console.error(chalk.red(`❌  could not write --export-anonymized file: ${e.message}`)); process.exit(1); }
		const ecoSummary = Object.entries(descriptor.summary.byEcosystem).map(([k, v]) => `${k}:${v}`).join(", ");
		ui.section("Anonymized export");
		ui.ok(`${chalk.bold(descriptor.summary.total)} dep(s) (${ecoSummary || "none"}) → ${chalk.white(options.exportAnonymized)}`);
		ui.info(chalk.dim("dependency coordinates and filtered version hints — exclude private coordinates and review before transfer."));
		if (omittedProperties) ui.warn(`${omittedProperties} Maven property value(s) omitted for privacy. Unusual version-property overrides used only by uncached external parents may require review.`);
		if (!descriptor.summary.total) ui.warn("no dependencies collected — descriptor is empty");
		// Guide the operator through the remaining two phases (the descriptor file +
		// this run's --src are filled in so the commands are copy-paste ready).
		const descFile = options.exportAnonymized;
		const srcShown = options.src || "./proj";
		ui.section("Next steps");
		ui.info(`${chalk.dim("Phase 2 —")} ${chalk.cyan("ONLINE")} ${chalk.dim("(any box, no --src): warm the caches, then bundle them")}`);
		ui.info("  " + chalk.white(`vigievuln --import-anonymized ${descFile}`));
		ui.info("  " + chalk.white("vigievuln --export-cache fad-cache.tar.gz"));
		ui.info(`${chalk.dim("Phase 3 —")} ${chalk.cyan("OFFLINE")} ${chalk.dim("(back here): import the cache, then run the full report")}`);
		ui.info("  " + chalk.white("vigievuln --import-cache fad-cache.tar.gz"));
		ui.info("  " + chalk.white(`vigievuln -s ${srcShown} --offline`));
		return;
	}

	if (!readOnly) {
		assertSafeExtractionTarget();
		if (options.force) await rimraf(options.target);
	}

	// Maven POM rewrite (cleanup feature). Parse + inheritance already happened
	// inside the maven codec's collect(); we reuse its metadata store here.
	if (runMaven && mavenCtx) {
		const { store, propsByPom, pomFiles } = mavenCtx;
		const rewriteOpts = { srcRoot: options.src, targetRoot: options.target, deps2Exclude, verbose, readOnly };
		for (const pom of pomFiles) {
			try {
				if (await core.rewritePoms(pom, store, propsByPom, rewriteOpts)) wrotePom++;
			} catch (err) {
				console.error(chalk.red(`  ✗ rewrite failed for ${pom}:`), err.message);
			}
		}
	}

	// Mirror every non-Maven lockfile/manifest (npm/yarn/pnpm, composer, pypi, nuget,
	// go, ruby) into the cleaned tree so `snyk test --all-projects` scans the WHOLE
	// polyglot project, not just the cleaned POMs. Maven POMs are the rewrite above.
	let copiedManifests = 0;
	if (!readOnly) {
		try {
			const { copyEcosystemManifests } = require("./lib/manifest-copy");
			const r = await copyEcosystemManifests(options.src, options.target, { excludePath, defaultExcludes });
			copiedManifests = r.copied;
		} catch (err) { console.error(chalk.red("  ✗ manifest copy failed:"), err.message); }
	}

	// ---------- Maven POM analysis summary (parents missing / excluded) ----------
	let privateLibIds = [];
	if (runMaven && mavenCtx) {
		const allPomMetadata = mavenCtx.store;   // reuse the codec's parsed metadata
		ui.section("Maven POM analysis");

		const missingParents = Object.keys(allPomMetadata.missingById)
			.filter(id => {
				const parts = id.split(":");
				if (parts.length === 2) return false;
				return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
			});
		if (missingParents.length) {
			// A parent absent from the source tree is EXTERNAL, not necessarily private. fad
			// resolves a PUBLIC one (spring-boot-starter-parent, …) from Maven Central / warmed
			// cache and backfills its managed versions — so only classify as "likely private"
			// the ones it genuinely can't resolve. effectivePom is cache-first + offline-aware,
			// and warms the cache the BOM/parent backfill reuses later in the report flow.
			const { effectivePom } = require("./lib/transitive");
			const resolvable = [], unresolved = [];
			await Promise.all(missingParents.map(async id => {
				const [g, a, v] = id.split(":");
				let eff = null;
				if (g && a && v) { try { eff = await effectivePom(g, a, v, { repos: mavenRepos, offline: options.offline }); } catch { eff = null; } }
				(eff && eff.depMgmt && eff.depMgmt.length ? resolvable : unresolved).push(id);
			}));
			if (resolvable.length) {
				ui.ok(`${resolvable.length} external parent POM(s) resolved from Maven Central${options.offline ? " (cache)" : ""} — managed versions backfilled`);
				for (const id of resolvable.slice(0, 10)) ui.info(chalk.green(id));
				if (resolvable.length > 10) ui.info(chalk.dim(`…and ${resolvable.length - 10} more`));
			}
			if (unresolved.length) {
				ui.warn(`${unresolved.length} parent POM(s) not resolvable — likely private${options.offline ? " (or not in the warmed cache)" : ""}; Snyk will fail on these:`);
				for (const id of unresolved.slice(0, 10)) ui.info(chalk.yellow(id));
				if (unresolved.length > 10) ui.info(chalk.dim(`…and ${unresolved.length - 10} more`));
			}
		} else {
			ui.ok("no missing Maven parent POMs");
		}

		// Private-lib detection asks each configured repo whether a missing coord
		// exists (→ absent = likely private). Results are cached + bundled, so an
		// --offline run reads the online-warmed cache instead of probing the network.
		// A coord that's neither cached nor probeable (offline + cold) stays UNKNOWN —
		// we never fake it as "private", which is what made offline both wrong and slow.
		if (options.allLibs) {
			const anyMissingLibs = Object.keys(allPomMetadata.anyMissingById)
				.filter(id => {
					const parts = id.split(":");
					if (parts.length === 3) return false;
					return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
				});
			privateLibIds = await classifyMavenLibs(anyMissingLibs, mavenRepos);
		}

		if (deps2Exclude) {
			const excludedLibs = Object.keys(allPomMetadata.excludedById)
				.filter(id => {
					const parts = id.split(":");
					if (parts.length === 2) return false;
					return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
				});
			if (excludedLibs.length) {
				ui.warn(`${excludedLibs.length} excluded-and-missing library(ies):`);
				for (const id of excludedLibs.slice(0, 10)) ui.info(chalk.magenta(id));
				if (excludedLibs.length > 10) ui.info(chalk.dim(`…and ${excludedLibs.length - 10} more`));
			} else {
				ui.ok("no excluded-and-missing libraries");
			}
		}

		if (!readOnly) ui.ok(`${chalk.bold(wrotePom)} cleaned POM(s) written → ${chalk.white(options.target)}`);
		else ui.info(chalk.dim(`${wrotePom} POM(s) cleanable (read-only — pass -t <dir> to write them)`));
	}

	if (!readOnly && copiedManifests) {
		ui.ok(`${chalk.bold(copiedManifests)} non-Maven lockfile/manifest(s) mirrored → ${chalk.white(options.target)} ${chalk.dim("(so snyk --all-projects scans every ecosystem)")}`);
	}

	// ---------- Extraction mode: -t without an explicit scan consumer stops here ----------
	// The tree is written, the reactor is linked, the POM analysis (incl. the online
	// existence check, when online) is printed. No CVE/EOL/outdated pass, no report.
	if (extractOnly) {
		ui.section("Extraction done");
		ui.info(chalk.dim("-t is an extraction step: cleaned tree + POM analysis only, no vulnerability scan."));
		ui.info(chalk.dim("for the vigievuln report: ") + chalk.white(`vigievuln -s ${options.src}`) + chalk.dim("  ·  or add --snyk / --report-<type> / --fail-on to this command"));
		ui.section("Next step");
		ui.info(`run Snyk on the cleaned tree:`);
		console.log("    " + chalk.white(`cd ${options.target} && snyk test --json --all-projects | snyk-to-html -o ../snyk-deps-check.html`));
		return;
	}

	// ---------- Scan flow (CVE / EOL / Obsolete) ----------
	// The scan always runs — it feeds the terminal summary, the file outputs and the
	// CI gate. Which files get written is decided by the --report-* family inside
	// (HTML + findings JSON by default; --no-report writes nothing).
	await runReportFlow(resolved, { activeIds, runMaven, runGradle, runNpm, privateLibIds, mavenRepos, regMap, collectWarnings, mavenPropsByPom: mavenCtx?.propsByPom, mavenStore: mavenCtx?.store, gradlePlatformBoms: gradleCtx?.platformBoms || [], parsedManifests, composerPlatforms: composerCtx?.platforms || [], walkOpts });
	if (!readOnly) {
		ui.section("Next step");
		ui.info(`run Snyk on the cleaned tree:`);
		console.log("    " + chalk.white(`cd ${options.target} && snyk test --json --all-projects | snyk-to-html -o ../snyk-deps-check.html`));
	}
})();

async function runReportFlow(resolved, ecoFlags = {}) {
	const { activeIds = [], runMaven = true, runGradle = false, runNpm = false, privateLibIds = [], mavenRepos = [], regMap = {}, collectWarnings = [], mavenPropsByPom = null, mavenStore = null, gradlePlatformBoms = [], parsedManifests = [], composerPlatforms = [], walkOpts = {} } = ecoFlags;
	const { excludePath = [], defaultExcludes = true } = walkOpts;
	const registriesFor = eco => regMap[eco] || [];
	const { expandWithTransitives } = require("./lib/cve-match");
	const { writeReports, computeStats } = require("./lib/cve-report");
	const { getCodec } = require("./lib/codecs");
	const outdated = require("./lib/outdated");
	const { getNvdApiKey } = require("./lib/config");
	const offline = !!options.offline;


	// Collection counts already shown in the "Collection" section by main();
	// for --import-anonymized they were shown in the "Anonymized descriptor" section.
	const npmWarnings = collectWarnings || [];
	let scanWarnings = [];
	let registryPrivateHits = [];
	const directCount = resolved.size;
	let appState = { applications: [], inventory: [], findings: [], coverage: [], diagnostics: [] };
	let applicationRelations = [];
	if (options.src) {
		const wordfenceApiKey = options.wordfenceApiKey || process.env.WORDFENCE_API_KEY || null;
		const { DRUPAL_ADVISORIES_URL, WORDFENCE_PRODUCTION_URL, PRESTASHOP_GITHUB_ADVISORIES_URL, TYPO3_GITHUB_ADVISORIES_URL } = require("./lib/application-providers/live-snapshot");
		const wordfenceLiveUrl = options.wordfenceFeedUrl || ((options.wordfenceLive || wordfenceApiKey) && !options.wordfenceFeed ? WORDFENCE_PRODUCTION_URL : null);
		const spipLiveUrl = options.spipAdvisoriesLive
			? (options.spipAdvisoriesLive === true ? require("./lib/application-providers/spip-advisories").SPIP_ADVISORIES_URL : options.spipAdvisoriesLive) : null;
		if (offline && (wordfenceLiveUrl || options.drupalAdvisoriesLive || options.prestashopAdvisoriesLive || options.typo3AdvisoriesLive || options.wpChecksumsLive || spipLiveUrl)) {
			console.error(chalk.red("❌  --offline cannot fetch live advisory sources; supply a local --wordfence-feed / --drupal-advisories / --prestashop-advisories / --typo3-advisories / --spip-advisories / --wp-checksums snapshot instead"));
			process.exit(2);
		}
		if (wordfenceLiveUrl && !wordfenceApiKey && !(wordfenceLiveUrl === WORDFENCE_PRODUCTION_URL && options.proxyCache)) {
			ui.warn("Wordfence live scan requires an API key: use --wordfence-api-key or WORDFENCE_API_KEY. No report was written.");
			process.exit(2);
		}
		let maxAdvisoryAgeMs = 0;
		if (options.maxAdvisoryAge) {
			const { parseMaxAge } = require("./lib/advisory-freshness");
			try { maxAdvisoryAgeMs = parseMaxAge(options.maxAdvisoryAge); }
			catch (error) {
				console.error(chalk.red(`❌  ${error.message}`));
				process.exit(2);
			}
		}
		const drupalLiveUrl = options.drupalAdvisoriesLive
			? (options.drupalAdvisoriesLive === true ? DRUPAL_ADVISORIES_URL : options.drupalAdvisoriesLive) : null;
		const prestashopLiveUrl = options.prestashopAdvisoriesLive
			? (options.prestashopAdvisoriesLive === true ? PRESTASHOP_GITHUB_ADVISORIES_URL : options.prestashopAdvisoriesLive) : null;
		const typo3LiveUrl = options.typo3AdvisoriesLive
			? (options.typo3AdvisoriesLive === true ? TYPO3_GITHUB_ADVISORIES_URL : options.typo3AdvisoriesLive) : null;
		const wpChecksumsLiveUrl = options.wpChecksumsLive
			? (options.wpChecksumsLive === true ? require("./lib/application-providers/wp-checksums").WP_CHECKSUMS_API : options.wpChecksumsLive) : null;
		try {
			const { allApplicationPlugins } = require("./lib/application-plugins");
			const { runApplicationPlugins } = require("./lib/application-plugins/runner");
			const { buildApplicationRelations } = require("./lib/application-inventory");
			appState = await runApplicationPlugins(options.src, { plugins: allApplicationPlugins(), selection: options.appPlugins,
				reportProviderFailures: true,
				resolvedDeps: resolved, activeCodecIds: activeIds, excludePath, defaultExcludes, scanContext: options.scanContext,
				privateComponentPaths: options.privateComponent || [], publicComponents: options.publicComponent || [],
				wordfenceFeedPath: options.wordfenceFeed || null, drupalAdvisoriesPath: options.drupalAdvisories || null,
				prestashopAdvisoriesPath: options.prestashopAdvisories || null, typo3AdvisoriesPath: options.typo3Advisories || null,
				spipAdvisoriesPath: options.spipAdvisories || null,
				liveWordfenceUrl: wordfenceLiveUrl, wordfenceApiKey, liveDrupalAdvisoriesUrl: drupalLiveUrl,
				livePrestashopAdvisoriesUrl: prestashopLiveUrl, liveTypo3AdvisoriesUrl: typo3LiveUrl,
				liveSpipAdvisoriesUrl: spipLiveUrl, spipAdvisoriesApiKey: getNvdApiKey(),
				wpChecksumsPath: options.wpChecksums || null, liveWpChecksumsUrl: wpChecksumsLiveUrl,
				wpChecksumsLocale: options.wpChecksumsLocale || "en_US",
				advisoryCacheDir: path.join(require("./lib/cache-directory").getCacheDir(), "advisory-snapshots"),
				offline,
				fetchImpl: (...args) => fetch(...args),
				maxAdvisoryAgeMs,
				requiredProviderIds: [options.wordfenceFeed && "wordfence-v3", options.drupalAdvisories && "drupal-security-advisories",
					wordfenceLiveUrl && "wordfence-v3", options.drupalAdvisoriesLive && "drupal-security-advisories",
					(options.prestashopAdvisories || prestashopLiveUrl) && "github-prestashop-advisories",
					(options.typo3Advisories || typo3LiveUrl) && "github-typo3-advisories",
					(options.spipAdvisories || spipLiveUrl) && "spip-security-advisories",
					(options.wpChecksums || wpChecksumsLiveUrl) && "wordpress-checksums"].filter(Boolean) });
			applicationRelations = buildApplicationRelations(options.src, appState.applications, appState.inventory, resolved);
			if (appState.applications.length) ui.info(chalk.dim(`${appState.applications.length} application(s), ${appState.inventory.length} component(s) inventoried`));
			// Cached advisory snapshots (drupal/prestashop/typo3 feeds, wp checksums) auto-
			// reused under --offline carry completeness "tool-fetched" — live fetches are
			// impossible here, so any such row is a cache reuse worth announcing.
			if (offline && appState.coverage.some(c => c.sourceSnapshot?.completeness === "tool-fetched"))
				ui.info(chalk.dim("--offline: advisory snapshot(s) reused from the imported cache (advisory-snapshots/)"));
			// The lanes may have run from a cached snapshot (auto-consumed) — only warn
			// when the coverage rows say the lane genuinely did not execute.
			const laneRan = sourceId => appState.coverage.some(c => c.sourceId === sourceId && c.execution !== "not-run");
			if (appState.applications.some(app => app.type === "wordpress") && !options.wordfenceFeed && !wordfenceLiveUrl && !laneRan("wordfence-v3"))
				ui.warn("WordPress advisory scan did not run: supply --wordfence-feed, or a Wordfence API key for the live feed (a warmed catalogue snapshot is reused without one).");
			if (appState.applications.some(app => app.type === "prestashop") && !options.prestashopAdvisories && !prestashopLiveUrl && !laneRan("github-prestashop-advisories"))
				ui.warn("PrestaShop advisory scan did not run: supply --prestashop-advisories, use --prestashop-advisories-live — or warm it once so the cached snapshot is reused.");
			if (appState.applications.some(app => app.type === "typo3") && !options.typo3Advisories && !typo3LiveUrl && !laneRan("github-typo3-advisories"))
				ui.warn("TYPO3 advisory scan did not run: supply --typo3-advisories, use --typo3-advisories-live — or warm it once so the cached snapshot is reused.");
			if (appState.applications.some(app => app.type === "spip") && !options.spipAdvisories && !spipLiveUrl && !laneRan("spip-security-advisories"))
				ui.warn("SPIP advisory scan did not run: supply --spip-advisories, use --spip-advisories-live — or warm it once so the cached NVD snapshot is reused.");
		} catch (error) {
			console.error(chalk.red(`❌  application plugin selection failed: ${error.message}`));
			process.exit(2);
		}
	}
	// NOTE: scan-completeness (unresolved-versions) is computed LATER — after the BOM
	// version-resolution step backfills external-BOM-managed versions — so it reflects
	// what's *genuinely* still unresolved, not what a Maven Central BOM fetch will fix.

	// ---- Vulnerability database update (global step progress) ----
	ui.section("Vulnerability database update");
	if (offline) ui.info(chalk.dim("--offline: cached data only, no network"));
	else ui.info(chalk.dim("First scans may take longer while caches fill."));

	const hasNvdKey = !!getNvdApiKey();
	if (options.nvd && !offline && !hasNvdKey) {
		ui.warn(chalk.yellow("No NVD API key — enrichment throttled to 5 req/30s (slow)."));
		ui.info(chalk.dim("Free & instant key: https://nvd.nist.gov/developers/request-an-api-key"));
		ui.info(chalk.dim("then: vigievuln --set-nvd-key <KEY>"));
	}

	// Decide which update steps will run (from flags) so the [n/N] counter is accurate.
	// Gradle deps are Maven coordinates (ecosystem "maven"), so the Maven CVE-index scanner
	// and the Maven-Central transitive/BOM/outdated/EOL passes cover them — they're EXCLUDED
	// from the per-codec registry loop below to avoid double-processing.
	const cveScanner = (runMaven || runGradle) ? (getCodec("maven").nativeScanners || []).find(s => s.kind === "cve") : null;
	const cveIndexExists = fs.existsSync(require("./lib/cve-download").CVE_INDEX_PATH);
	const otherRegistryIds = activeIds.filter(id => id !== "maven" && id !== "gradle" && id !== "npm" && id !== "yarn" && getCodec(id)?.checkRegistry);
	const willCve = !!cveScanner && (!(options.cveOffline || offline) || cveIndexExists);
	// Maven with a source tree: every module is resolved on ITS OWN effective model
	// (lib/maven-reactor.js) and the scan set is rebuilt from the union — this replaces the
	// old global merged pass + additive per-module overlay, which let one project's pins
	// re-version another's. Runs even with --no-transitive (directs and their managed
	// versions are still per module). The global pass remains for Gradle records and for a
	// descriptor import without a source tree.
	const willReactor = !!(runMaven && mavenPropsByPom && mavenStore);
	const willTransitive = !!(options.transitive && (runGradle || (runMaven && !willReactor)));
	// External import BOMs (e.g. spring-boot-dependencies): resolve their managed
	// versions to backfill declared deps that pin no version of their own (the usual
	// Spring Boot setup). Cached via poms-cache; offline-aware (uses warmed POMs,
	// never the network — same as transitive resolution).
	const importBoms = (runMaven && mavenPropsByPom)
		? require("./lib/maven-bom").collectImportBoms(mavenPropsByPom) : [];
	// Gradle `platform(...)` BOMs are the same as Maven `<scope>import</scope>` BOMs — feed
	// them through the same managed-version backfill (e.g. spring-boot-dependencies → all the
	// versionless spring-boot-starter-* declared in build.gradle get their version).
	const gradleBoms = (gradlePlatformBoms || [])
		.map(b => ({ groupId: b.group, artifactId: b.name, version: b.version }))
		.filter(b => b.groupId && b.artifactId && b.version);
	const allBoms = importBoms.concat(gradleBoms);
	// External <parent> POMs (e.g. spring-boot-starter-parent) manage versionless declared
	// deps via their own inherited depMgmt (spring-boot-dependencies). core.js only follows
	// LOCAL parents, so feed the external ones through the SAME backfill as import BOMs. This
	// runs in the MAINLINE flow (not just the --transitive overlay) so the warmed cache always
	// captures the parent POMs for offline reuse.
	const externalParents = (runMaven && mavenStore)
		? require("./lib/maven-bom").collectExternalParents(mavenStore) : [];
	const willBom = allBoms.length > 0 || externalParents.length > 0;
	const willOsv = !!options.osv;
	// Packagist security-advisories lane (Composer): the advisory DB `composer audit`
	// queries. OSV misses CVEs that exist there only as CVEProject entries without
	// Packagist coordinates (measured: twig/twig CVE-2026-46636/46627, knp-snappy
	// CVE-2026-46643 on the real-instance corpus) — this lane is their official home.
	const willPackagistAudit = options.packagistAudit !== false &&
		[...resolved.values()].some(d => d.ecosystem === "composer");
	// Local OSV DB import (Maven): offline-complete OSV recall, independent of the per-dep
	// OSV.dev cache. Opt-in (downloads ~9 MB once); then matches online or offline.
	const { autoEnableOsvDb, hasOsvDbIndex } = require("./lib/osv-db");
	const willOsvDb = autoEnableOsvDb(options, { runMaven, runGradle, hasIndex: hasOsvDbIndex("maven") });
	const willOutdated = !!options.allLibs;
	const willNvd = !!options.nvd;
	const willEpss = !!options.epss;
	const willKev = !!options.kev;
	const willEuvd = options.euvd !== false;
	const willCertFr = options.certfr !== false;
	const willEol = options.eol !== false;
	const willLicenses = !!options.licenses;
	const willRetire = !!options.retire;
	// Committed crypto material (certs / keys / keystores) — local file scan, no network.
	const willCerts = options.certs !== false && !!options.src;
	const certExpiryDays = parseInt(options.certExpiryDays, 10) || 90;
	// Identify committed native binaries by checksum (deps.dev + CIRCL) when present.
	const willBinaryId = [...resolved.values()].some(d => d.provenance === "binary");
	// License detection piggybacks on the registry passes (same fetched metadata),
	// so it adds no progress step of its own.
	const totalSteps = [willBom, willReactor, willTransitive, willCve, willEol, willEol && composerPlatforms.length > 0,
		willOutdated, /*npm reg*/ true, ...otherRegistryIds.map(() => true), willOsv, willPackagistAudit, willOsvDb,
		willNvd, willEpss, willKev, willEuvd, willCertFr, willRetire, willCerts, willBinaryId].filter(Boolean).length;
	const progress = new ui.Progress(totalSteps);

	// The external import-BOM + <parent> managed table, kept for the transitive pass: Maven
	// pins transitive versions with it too, not only versionless declarations.
	let bomDepMgmt = new Map();
	if (willBom) {
		const st = progress.start("BOM / parent version resolution (Maven Central)");
		try {
			const { resolveBomManagedVersions, backfillVersions } = require("./lib/maven-bom");
			const effCache = new Map();
			const base = { repos: mavenRepos, offline, verbose, effCache };
			// Import BOMs first: a local <scope>import</scope> declaration wins over the
			// versions inherited from an external parent (Maven precedence). Import BOMs
			// resolve in their own context — the project's property overrides do NOT reach
			// them (Maven), so they get no propertyOverrides.
			const mgmt = await resolveBomManagedVersions(allBoms, base);
			// External parents second: fill only coords the BOMs didn't already manage, and
			// honor the project's own <properties> overrides (e.g. a patched <log4j2.version>)
			// so the version reflects the classpath, not the framework default.
			const propertyOverrides = require("./lib/maven-bom").collectPropertyOverrides(mavenStore);
			const parentMgmt = await resolveBomManagedVersions(externalParents, { ...base, via: "parent", propertyOverrides });
			for (const [k, v] of parentMgmt) if (!mgmt.has(k)) mgmt.set(k, v);
			bomDepMgmt = mgmt;
			const filled = backfillVersions(resolved, mgmt);
			st.done(`${filled} dep version(s) from ${allBoms.length} BOM(s) + ${externalParents.length} parent(s)`);
		} catch (err) { st.fail(err.message); }
	}

	if (willReactor) {
		const st = progress.start(options.transitive ? "Maven resolution, module by module (Maven Central)" : "Maven direct versions, module by module");
		try {
			const { resolveReactor } = require("./lib/maven-reactor");
			const rr = await resolveReactor(resolved, mavenStore, mavenPropsByPom, {
				verbose,
				offline,
				maxDepth: parseInt(options.transitiveDepth, 10) || 6,
				includeTestDeps: !options.ignoreTest,
				repos: mavenRepos,
				transitive: !!options.transitive,
				deps2Exclude,
			});
			st.done(`${rr.modules} module(s), ${resolved.size} dependencies${rr.dropped.length ? `, ${rr.dropped.length} managed-only coord(s) on no classpath` : ""}`);
			if (verbose && rr.dropped.length) console.log(chalk.gray(`   not on any classpath, not scanned: ${rr.dropped.slice(0, 10).join(", ")}${rr.dropped.length > 10 ? ", …" : ""}`));
		} catch (err) { st.fail(err.message); }
	}

	if (willTransitive) {
		const st = progress.start("Transitive resolution (Maven Central)");
		await expandWithTransitives(resolved, {
			verbose,
			offline,
			maxDepth: parseInt(options.transitiveDepth, 10) || 6,
			includeTestDeps: !options.ignoreTest,
			repos: mavenRepos,
			bomDepMgmt,
			// With the reactor in charge of the Maven records, only Gradle ones are seeded here.
			...(willReactor ? { only: d => d.ecosystemType === "gradle" } : {}),
		});
		st.done(`+${resolved.size - directCount} transitive (total ${resolved.size})`);
	}

	// <dependencyManagement>-only pins: keep the ones a resolution pass reached (now
	// transitives), drop the rest — a pin nothing pulls in is on no classpath.
	{
		const { settleManagedOnly } = require("./lib/cve-match");
		const settled = settleManagedOnly(resolved);
		if (verbose && settled.dropped.length) {
			console.log(chalk.gray(`   ${settled.dropped.length} <dependencyManagement>-only pin(s) not on any classpath, not scanned: ${settled.dropped.slice(0, 10).join(", ")}${settled.dropped.length > 10 ? ", …" : ""}`));
		}
	}

	// Scan-completeness signals — computed NOW (after BOM backfill) so only the deps
	// still without a concrete version (external BOM truly unreachable, or offline)
	// are flagged, not the ones we just resolved from spring-boot-dependencies & co.
	if (runMaven || runGradle) {
		const { detectScanCompletenessWarnings } = require("./lib/scan-completeness");
		scanWarnings = detectScanCompletenessWarnings(resolved, { ranSnyk: !!options.snyk, ranTransitive: !!options.transitive });
	}

	// 1. CVE — native scanner contributed by the maven codec (local cvelistV5 index).
	let cveMatches = [];
	let cveDataDate = null;
	if (willCve) {
		const st = progress.start("CVE index (CVEProject)");
		try {
			const r = await cveScanner.scan(resolved, { cveRefresh: !!options.cveRefresh, cveOffline: !!options.cveOffline, offline, verbose, hostedProxy: !!options.vigievulnProxy });
			cveMatches = r.matches || [];
			cveDataDate = r.meta?.cveDataDate || null;
			st.done(`${cveMatches.length} match(es)${cveDataDate ? ` · ${String(cveDataDate).slice(0, 10)}` : ""}`);
		} catch (err) {
			st.fail(err.message);
			scanWarnings.push({type:"source-unavailable",message:`CVEProject: ${err.message}; Maven CVE coverage is incomplete.`});
		}
	}

	// 1c. Identify committed native binaries by checksum (deps.dev → CIRCL).
	if (willBinaryId) {
		const st = progress.start("Binary identification (deps.dev + CIRCL)");
		try {
			const { enrichUnmanaged } = require("./lib/unmanaged");
			const s = await enrichUnmanaged(resolved, { offline, onProgress: (p, t) => st.tick(p, t) });
			const bits = [`${s.identified}/${s.total} identified`, s.pristine ? `${s.pristine} pristine` : null, s.unknown ? `${s.unknown} unknown` : null, s.malicious ? `${s.malicious} ⚠ malicious` : null].filter(Boolean).join(", ");
			st.done(bits);
		} catch (err) { st.fail(err.message); }
	}

	// 2. EOL frameworks (endoflife.date) — always a step. --eol-support adds the band
	// "active support ended, security fixes still provided" (status: unsupported).
	const eolSummaryLabel = list => {
		const u = list.filter(e => e.status === "unsupported").length;
		return `${list.length - u} EOL${u ? `, ${u} out of support` : ""}`;
	};
	let eolResults = [];
	let commercialBuildNotes = [];
	if (willEol) {
		const st = progress.start("EOL frameworks (endoflife.date)");
		try {
			eolResults = await outdated.checkEolDeps(resolved, { verbose, offline, eolSupport: !!options.eolSupport });
			st.done(eolSummaryLabel(eolResults));
		} catch (err) { st.fail(err.message); }
	}

	// 2b. PHP runtime — the Composer platform constraint against endoflife.date/php.
	// A FINDING, never a dependency: it does not enter `resolved` (no CVE/OSV/SBOM/purl).
	if (willEol && composerPlatforms.length) {
		const { evaluatePhpRuntime } = require("./lib/codecs/composer/platform");
		const st = progress.start("PHP runtime (endoflife.date/php)");
		try {
			const phpCycles = await outdated.getEolCycles("php", { offline });
			const r = evaluatePhpRuntime(composerPlatforms, phpCycles, { eolSupport: !!options.eolSupport });
			eolResults.push(...r.findings);
			st.done(r.findings.length ? eolSummaryLabel(r.findings) : "supported");
		} catch (err) { st.fail(err.message); }
	}

	// License findings accumulate from each registry pass (same fetched metadata)
	// plus Maven's cached POMs — assessed against the copyleft policy below.
	let licenseFindings = [];

	// 3. Obsolete / deprecated — local curated list, instant (no network step).
	let obsoleteResults = [];
	try { obsoleteResults = outdated.checkObsoleteDeps(resolved); }
	catch (err) { ui.warn(`obsolete check skipped: ${err.message}`); }

	// 4. Outdated (latest Maven Central) — gated by --all-libs.
	let outdatedResults = [];
	if (willOutdated) {
		const st = progress.start("Maven Central (outdated)");
		try {
			outdatedResults = await outdated.checkOutdatedDeps(resolved, { verbose, offline, repos: mavenRepos, onProgress: (p, t) => st.tick(p, t) });
			st.done(`${outdatedResults.length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// 4a. npm registry — deprecation (always, authoritative) + outdated (with --all-libs).
	// Covers npm deps and WebJars, so it runs even in Maven-only mode.
	{
		const st = progress.start("npm registry");
		try {
			const { checkNpmRegistryDeps } = require("./lib/codecs/npm/registry");
			const npmReg = await checkNpmRegistryDeps(resolved, { verbose, offline, allLibs: options.allLibs, registries: registriesFor("npm"), onProgress: (p, t) => st.tick(p, t) });
			obsoleteResults = obsoleteResults.concat(npmReg.deprecated);
			outdatedResults = outdatedResults.concat(npmReg.outdated);
			licenseFindings = licenseFindings.concat(npmReg.licensed || []);
			registryPrivateHits = registryPrivateHits.concat(npmReg.private || []);
			st.done(`${npmReg.deprecated.length} deprecated, ${npmReg.outdated.length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// Coordinates every configured registry answered 404/410 for — internal packages.
	// Maven finds these with a dedicated probe; the other ecosystems get it for free from the
	// registry pass they already run.
	// 4b. Per-codec registry for ecosystems beyond maven/npm (composer/pypi/nuget).
	for (const id of otherRegistryIds) {
		const codec = getCodec(id);
		const st = progress.start(`${codec.label || id} registry`);
		try {
			const reg = await codec.checkRegistry(resolved, { verbose, offline, allLibs: options.allLibs, registries: registriesFor(id), onProgress: (p, t) => st.tick(p, t) });
			obsoleteResults = obsoleteResults.concat(reg.deprecated || []);
			outdatedResults = outdatedResults.concat(reg.outdated || []);
			licenseFindings = licenseFindings.concat(reg.licensed || []);
			registryPrivateHits = registryPrivateHits.concat(reg.private || []);
			st.done(`${(reg.deprecated || []).length} deprecated, ${(reg.outdated || []).length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// Cross-section dedup: drop entries from outdated that already appear in EOL/Obsolete
	const eolKeys = new Set(eolResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	const obsKeys = new Set(obsoleteResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	outdatedResults = outdatedResults.filter(r => {
		const k = `${r.dep.groupId}:${r.dep.artifactId}`;
		return !eolKeys.has(k) && !obsKeys.has(k);
	});
	// Outdated is a maintenance signal for deps you actually declare and can bump. An
	// INDIRECT (transitive) dep's "latest" isn't directly actionable — you'd bump the parent
	// — so drop transitives from the Outdated chapter (EOL/obsolete keep them: security).
	// scope==="transitive" is the marker set by the Maven/Gradle resolver and the npm parser.
	// The Maven pass (checkOutdatedDeps) already skips transitives at FETCH time (perf);
	// this filter covers the npm/composer/pypi/nuget registry passes, which must still
	// query transitives for the authoritative deprecation signal.
	outdatedResults = outdatedResults.filter(r => r.dep.scope !== "transitive");

	// 4b. OSV.dev — Maven-native CVE+GHSA feed (huge recall win over raw CVEProject)
	if (willOsv) {
		const st = progress.start("OSV.dev");
		try {
			const { queryOsvForDeps } = require("./lib/osv");
			const osvMatches = await queryOsvForDeps(resolved, { verbose, offline,
				onProgress: (p, t) => st.tick(p, t), onWarning: w => scanWarnings.push(w) });
			const before = cveMatches.length;
			cveMatches = mergeBySource(cveMatches, osvMatches);
			st.done(`${osvMatches.length} vulns · +${cveMatches.length - before} after merge`);
		} catch (err) {
			st.fail(err.message);
			if (err.code === "OSV_INCOMPLETE") {
				scanWarnings.push({type:"source-unavailable",message:`OSV: ${err.message}; advisory coverage is incomplete. Existing package caches were preserved.`});
			}
		}
	}

	// 4b-bis. Packagist security advisories (Composer) — the database `composer audit`
	// queries. Default-on like OSV: silently missing it shrinks the report; `-d
	// packagist-audit` turns it off. Only package NAMES travel to packagist.org.
	if (willPackagistAudit) {
		const st = progress.start("Packagist security advisories");
		try {
			const { queryPackagistAudit } = require("./lib/packagist-audit");
			let skippedOtherRegistry = [];
			let unknownPackages = [];
			const pkMatches = await queryPackagistAudit(resolved, { verbose, offline,
				onProgress: (p, t) => st.tick(p, t), onSkipped: names => { skippedOtherRegistry = names; },
				onUnknown: names => { unknownPackages = names; } });
			const before = cveMatches.length;
			cveMatches = mergeBySource(cveMatches, pkMatches);
			st.done(`${pkMatches.length} advisories matched · +${cveMatches.length - before} after merge` +
				(skippedOtherRegistry.length ? ` · ${skippedOtherRegistry.length} non-Packagist package(s) skipped` : "") +
				(unknownPackages.length ? ` · ${unknownPackages.length} package(s) with unknown coverage` : ""));
			if (skippedOtherRegistry.length) scanWarnings.push({ type: "packagist-non-packagist-package",
				message: `${skippedOtherRegistry.length} Composer package(s) from another registry were not queried against Packagist: ${skippedOtherRegistry.join(", ")}. Their application advisory coverage remains incomplete.` });
			if (unknownPackages.length) scanWarnings.push({ type: "packagist-advisory-data-unknown",
				message: `Packagist returned no advisory data for ${unknownPackages.length} Composer package(s): ${unknownPackages.join(", ")}. Their Packagist advisory coverage is unknown.` });
		} catch (err) {
			st.fail(err.message);
			scanWarnings.push({type:"source-unavailable",message:`Packagist: ${err.message}; advisory coverage is incomplete.`});
		}
	}

	// 4b'. Local OSV database (Maven) — offline-COMPLETE recall. The per-dep OSV.dev
	// queries above only cover deps cached online; the imported full OSV DB matches every
	// dep offline, deterministically, regardless of cache warmth (the OSV-Scanner model).
	if (willOsvDb) {
		const st = progress.start("OSV database (local, Maven)");
		try {
			const { ensureOsvDb, matchOsvDbDeps } = require("./lib/osv-db");
			if (!offline && !hasOsvDbIndex("maven")) st.tick("first run — importing the OSV Maven database (~9 MB)");
			const index = await ensureOsvDb({ offline: offline || (!!options.vigievulnProxy && options.osvDb !== true && !options.osvDbRefresh), refresh: !!options.osvDbRefresh, verbose, ecosystem: "maven" });
			if (!index) {
				st.done(offline ? "no local OSV DB (run once online with --osv-db)" : "unavailable");
			} else {
				const dbMatches = matchOsvDbDeps(resolved, index);
				const before = cveMatches.length;
				cveMatches = mergeBySource(cveMatches, dbMatches);
				st.done(`${index.count} advisories · ${dbMatches.length} matched · +${cveMatches.length - before} new`);
			}
		} catch (err) { st.fail(err.message); }
	}

	// Application-provider findings enter the shared enrichment, priority and gate
	// pipeline through the same alias-aware seam as every other CVE source: a publisher
	// constat that the standard Composer lane already found (same coord+version+CVE —
	// e.g. the exact pin in a TYPO3 sysext manifest alongside the observed core marker)
	// merges into ONE finding with the union of sources, and the application attribution
	// is rebuilt from the physical occurrence (expandComposerFindings). Findings the
	// standard lanes cannot see (Drupal core, WordPress catalogue) pass through intact.
	if (appState.findings.length) cveMatches = require("./lib/merge-sources").mergeBySource(cveMatches, appState.findings);

	// 4c. NVD enrichment — canonical description + full CVSS for matched CVEs.
	if (willNvd) {
		const st = progress.start("NVD enrichment");
		if (!cveMatches.length) {
			st.skip("no CVE to enrich");
		} else {
			try {
				const { enrichMatches } = require("./lib/nvd");
				await enrichMatches(cveMatches, { verbose, offline, mirror: options.nvdMirror !== false, onProgress: (p, t) => st.tick(p, t) });

				// 4c-bis. NVD CPE ranges as an ADDITIVE tier, curated coordinates only.
				// OSV/GHSA declare affected ranges per release BRANCH; NVD declares them for
				// every affected branch. For CVE-2020-9546, OSV covers 2.9.0–2.9.10.4 while
				// NVD also covers 2.0.0–2.7.9.7, so jackson-databind 2.5.2 is affected and
				// never got a fix. The data was already in the NVD cache and only ever used
				// to FILTER. Bounded on purpose: `data/cpe-coord-map.json` coordinates only
				// (no name heuristics — that is what makes CPE-driven scanners noisy), and
				// only CVEs already enriched, so this adds no network path of its own.
				let nvdAdded = 0;
				if (options.nvdCpeMatch) try {
					const { matchDepsAgainstNvdCpe } = require("./lib/cpe");
					const records = {};
					for (const m of cveMatches) {
						const id = m.cve?.id;
						if (id && m.cve.configurations?.length && !records[id]) records[id] = m.cve;
					}
					const extra = matchDepsAgainstNvdCpe(resolved, records);
					if (extra.length) {
						const before = cveMatches.length;
						cveMatches = mergeBySource(cveMatches, extra);
						nvdAdded = cveMatches.length - before;
					}
				} catch (err) { ui.warn(`NVD CPE matching skipped: ${err.message}`); }
				// 4d. CPE refinement — use NVD's CPE configurations to upgrade match
				// confidence and flag likely false positives (version outside CPE range).
				let filtered = 0;
				try {
					const { refineMatchesWithCpe } = require("./lib/cpe");
					refineMatchesWithCpe(cveMatches);
					filtered = cveMatches.filter(m => m.cpeFiltered).length;
				} catch (err) { ui.warn(`CPE refinement skipped: ${err.message}`); }
				const uniqueCves = new Set(cveMatches.map(m => m.cve?.id)).size;
				st.done(`${uniqueCves} CVE${nvdAdded ? ` · +${nvdAdded} via CPE ranges` : ""}${filtered ? ` · ${filtered} false-positive(s) filtered` : ""}${hasNvdKey ? "" : " · no key (slow)"}`);
			} catch (err) { st.fail(err.message); }
		}
	}

	// 4e. EPSS — exploit-prediction percentile for each matched CVE (FIRST.org).
	if (willEpss) {
		const st = progress.start("EPSS (FIRST.org)");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichEpss } = require("./lib/epss");
				await enrichEpss(cveMatches, { verbose, offline, onProgress: (p, t) => st.tick(p, t) });
				const scored = cveMatches.filter(m => m.cve?.epssPercentile != null).length;
				st.done(`${scored} scored`);
			} catch (err) { st.fail(err.message); scanWarnings.push({type:"source-unavailable",message:`EPSS: ${err.message}; enrichment is incomplete.`}); }
		}
	}

	// 4f. CISA KEV — flag CVEs known to be exploited in the wild.
	if (willKev) {
		const st = progress.start("CISA KEV");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichKev } = require("./lib/kev");
				await enrichKev(cveMatches, { verbose, offline, hostedProxy: !!options.vigievulnProxy });
				const kevd = cveMatches.filter(m => m.cve?.kev).length;
				st.done(`${kevd} known-exploited`);
			} catch (err) { st.fail(err.message); scanWarnings.push({type:"source-unavailable",message:`CISA KEV: ${err.message}; exploitation status is incomplete.`}); }
		}
	}

	// 4f-bis. European references — GCVE id (defined by the GCVE rules, no request), the
	// ENISA EUVD id + exploited flag, and the CERT-FR advisories citing the CVE. All three
	// are bulk/incremental reads directly, or targeted CVE lookups in hosted proxy mode.
	if (cveMatches.length) {
		try { require("./lib/gcve").enrichGcve(cveMatches); }
		catch (err) { ui.warn(`GCVE ids skipped: ${err.message}`); }
	}
	if (willEuvd) {
		const st = progress.start("ENISA EUVD");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichEuvd } = require("./lib/euvd");
				await enrichEuvd(cveMatches, { verbose, offline, hostedProxy: !!options.vigievulnProxy });
				const ids = new Set(cveMatches.filter(m => m.cve?.euvd?.id).map(m => m.cve.id)).size;
				const exploited = new Set(cveMatches.filter(m => m.cve?.euvd?.exploitedSince != null).map(m => m.cve.id)).size;
				st.done(`${ids} EUVD id(s) · ${exploited} exploited per ENISA`);
			} catch (err) { st.fail(err.message); scanWarnings.push({type:"source-unavailable",message:`EUVD: ${err.message}; enrichment is incomplete.`}); }
		}
	}
	if (willCertFr) {
		const st = progress.start("CERT-FR advisories");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichCertFr } = require("./lib/certfr");
				await enrichCertFr(cveMatches, { verbose, offline, hostedProxy: !!options.vigievulnProxy, onProgress: (p, t) => st.tick(p, t) });
				const cited = new Set(cveMatches.filter(m => m.cve?.certfr?.length).map(m => m.cve.id)).size;
				st.done(`${cited} CVE(s) cited by CERT-FR`);
			} catch (err) { st.fail(err.message); scanWarnings.push({type:"source-unavailable",message:`CERT-FR: ${err.message}; enrichment is incomplete.`}); }
		}
	}

	// 4g. Composite priority (KEV > EPSS-weighted CVSS). Always — cheap, pure.
	try {
		const { attachPriority } = require("./lib/priority");
		attachPriority(cveMatches);
	} catch (err) { ui.warn(`priority scoring skipped: ${err.message}`); }

	// 5. retire.js — native "vendored" scanner contributed by the npm codec. Scans
	//    vendored JS files (jquery copies, bootstrap, pdf.js, …) that live in the
	//    source tree without any lockfile to back them.
	// Not gated by an active npm ecosystem: retire scans the source tree for
	// vendored .js (which can live in a Maven project's resources too). The
	// scanner is owned by the npm codec but runs whenever --retire is on.
	let retireMatches = [];
	let vendoredJsInventory = [];
	let retireWarnings = [];
	if (willRetire) {
		const st = progress.start("retire.js (vendored JS)");
		const sc = (getCodec("npm").nativeScanners || []).find(s => s.kind === "vendored");
		if (!sc) { st.skip("scanner unavailable"); }
		else if (!options.src) { st.skip("no source tree (descriptor import)"); }
		else {
			try {
				const r = await sc.scan(resolved, { src: options.src, verbose, retireRefresh: !!options.retireRefresh, offline, excludePath, defaultExcludes });
				retireMatches = r.matches || [];
				if (options.vendoredJsInventory !== false) vendoredJsInventory = r.meta?.inventory || [];
				const invN = vendoredJsInventory.length;
				if (r.meta?.error) {
					// A genuine scan failure — surface it instead of letting an empty
					// vendored-JS chapter look like "nothing found".
					st.fail(r.meta.error);
					retireWarnings.push({ type: "retire-failed", message: `${r.meta.error} — the vendored-JS scan (chapters 1D / 2) could not run, so any vendored \`.js\` (jQuery, Bootstrap, …) is NOT covered. Re-run with \`-v\` for the exact error; check the \`--src\` path exists and is readable.` });
				} else {
					// The vendored-JS chapter lists CWEs on the library row — retire.js itself
					// has none, so the matches join the SAME NVD enrichment the composer/npm
					// findings already went through (per-CVE cache, only CVE-shaped ids queried).
					// The enrichment also upgrades retire's one-line summary to NVD's canonical
					// description. Folded into this step so the progress count stays exact.
					if (retireMatches.length && willNvd) {
						try {
							const { enrichMatches } = require("./lib/nvd");
							await enrichMatches(retireMatches, { verbose, offline, mirror: options.nvdMirror !== false, onProgress: (p, t) => st.tick(p, t) });
						} catch (err) { if (verbose) ui.warn(`vendored-JS NVD enrichment skipped: ${err.message}`); }
					}
					st.done(`${retireMatches.length} finding(s)${invN ? ` · ${invN} lib(s) inventoried` : ""}`);
				}
			} catch (err) { st.fail(err.message); retireWarnings.push({ type: "retire-failed", message: `retire.js scan failed: ${err.message} — vendored-JS chapters (1D / 2) not covered.` }); }
		}
	}

	// 5b. Certificate / key-material scan — committed certs, private/public keys
	// (PEM, OpenSSH every algorithm, PuTTY, PGP, SSH one-liners) and keystores.
	// Pure local file walk: no network, so it runs the same online or offline.
	let certFindings = [];
	if (willCerts) {
		const st = progress.start("Certificates & keys");
		try {
			const { scanCertificates } = require("./lib/certs");
			certFindings = scanCertificates(options.src, { srcRoot: options.src, excludePath, defaultExcludes, expiryDays: certExpiryDays });
			const priv = certFindings.filter(c => c.kind === "private-key").length;
			const expired = certFindings.filter(c => c.issues.some(i => i.type === "cert-expired")).length;
			st.done(`${certFindings.length} item(s)${priv ? ` · ${priv} private key(s)` : ""}${expired ? ` · ${expired} expired` : ""}`);
		} catch (err) { st.fail(err.message); }
	}

	// 6. Snyk (optional)
	let snykMatches = [];
	if (options.snyk) {
		if (!options.target) {
			ui.warn("--snyk requires --target (snyk runs on cleaned POMs)");
		} else {
			const snyk = require("./lib/snyk");
			try {
				const raw = await snyk.runSnykTest(options.target, { verbose });
				snykMatches = snyk.parseSnykResults(raw);
				cveMatches = snyk.mergeWithFadResults(cveMatches, snykMatches);
				ui.ok(`Snyk: ${snykMatches.length} findings merged`);
			} catch (err) {
				ui.warn(`Snyk run failed: ${err.message}`);
			}
		}
	}

	// 6a-bis. Attribute every match to the manifest/module that actually resolves the
	// version it matched on. A depRecord is coord-wide (versions[] and manifestPaths[]
	// with no link between them); a match carries ONE version. Must run after ALL match
	// sources are merged and before anything reads scope/paths (exec summary, charts,
	// chapters, exports, gate) — otherwise, on a root spanning several independent
	// projects, every version is reported against every manifest holding the coord.
	{
		const { attributeMatchOrigins } = require("./lib/attribution");
		const reattributed = attributeMatchOrigins(cveMatches);
		if (reattributed && verbose) console.log(`   re-attributed ${reattributed} match(es) to their resolving manifest/module`);
	}
	// 6a-ter. Paid support past the open-source end of life (endoflife.date extendedSupport):
	// per EOL finding, the build of its own branch that fixes the CVEs found, the newest
	// vendor build when a vendor repository is configured, and — when the project already
	// runs a vendor build — the finding leaves the EOL list for a chapter-0 note.
	if (eolResults.length) {
		try {
			const { annotateCommercialSupport } = require("./lib/commercial-support");
			const { commercialBuilds } = await annotateCommercialSupport(eolResults, cveMatches, { offline, repos: mavenRepos });
			if (commercialBuilds.length) {
				eolResults = eolResults.filter(e => e.status !== "commercial");
				commercialBuildNotes = commercialBuilds;
			}
		} catch (err) { if (verbose) console.warn(chalk.yellow(`   commercial-support annotation skipped: ${err.message}`)); }
	}
	if (options.src) {
		const { expandComposerFindings } = require("./lib/application-inventory");
		cveMatches = expandComposerFindings(cveMatches, options.src, applicationRelations);
	}
	{
		const { coalescePhysicalFindings } = require("./lib/finding-summary");
		cveMatches = coalescePhysicalFindings(cveMatches, options.src || null);
		const { attachPriority } = require("./lib/priority");
		attachPriority(cveMatches);
	}

	// 6b. Supply-chain risk lane (pure + offline): flag KNOWN-MALICIOUS advisories
	// (OSV MAL-… already in the match set) always, and detect suspected TYPOSQUATS
	// (opt-in --typosquat, heuristic — names one edit from a popular package).
	const { flagMalicious, detectTyposquats } = require("./lib/malware");
	const maliciousCount = flagMalicious(cveMatches);
	const typosquats = options.typosquat ? detectTyposquats(resolved) : [];
	if (maliciousCount || typosquats.length) {
		ui.section("Supply-chain risk");
		if (maliciousCount) ui.warn(chalk.red.bold(`${maliciousCount} KNOWN-MALICIOUS package advisory(ies) (MAL-…) — treat the build as compromised`));
		if (typosquats.length) {
			ui.warn(`${typosquats.length} suspected typosquat(s) — heuristic, verify each is intentional:`);
			for (const t of typosquats.slice(0, 15)) console.log("    " + chalk.yellow(t.name) + chalk.dim(` (${t.ecosystem}) ≈ ${t.resembles}`));
			if (typosquats.length > 15) console.log(chalk.dim(`    …and ${typosquats.length - 15} more (see JSON export)`));
		}
	}

	// Split prod vs dev based on the dep's isDev flag (set at collection time
	// from Maven scope=test/provided and npm dev/devOptional/optional). Keep the
	// full per-bucket list (including cpeFiltered) so the HTML report can render
	// its "Likely false positives" appendix — only the CLI headline excludes
	// cpeFiltered to avoid alarming on triaged-out matches.
	// Triage — suppress accepted-risk / false-positive findings (--ignore / --vex).
	// Marked in place; kept in the machine exports (flagged) but dropped from the
	// human report's active chapters and from CI gating.
	let suppressedCount = 0;
	if (options.ignore || options.vex) {
		try {
			const { parseIgnoreFile, parseVex, applySuppressions } = require("./lib/suppress");
			const rules = [];
			if (options.ignore) rules.push(...parseIgnoreFile(fs.readFileSync(options.ignore, "utf8")));
			if (options.vex) rules.push(...parseVex(JSON.parse(fs.readFileSync(options.vex, "utf8"))));
			suppressedCount = applySuppressions(cveMatches, rules);
			const via = [options.ignore && "--ignore", options.vex && "--vex"].filter(Boolean).join(" + ");
			if (suppressedCount) ui.info(chalk.dim(`triage: ${suppressedCount} finding(s) suppressed by ${via}`));
		} catch (err) { ui.warn(`suppression skipped: ${err.message}`); }
	}

	const { sortByPriority } = require("./lib/priority");
	const isEmbedded  = m => m.dep?.provenance === "embedded";
	// Embedded-binary findings get their own chapter, so keep them out of the
	// declared prod/dev sets (a coord that's both declared AND embedded yields two
	// distinct records — one in each — which is the intended, audit-useful split).
	const prodMatches     = cveMatches.filter(m => !m.dep?.isDev && !m.suppressed && !isEmbedded(m));
	const devMatches      = cveMatches.filter(m =>  m.dep?.isDev && !m.suppressed && !isEmbedded(m));
	const embeddedMatches = cveMatches.filter(m => isEmbedded(m) && !m.suppressed);
	const prodActive  = sortByPriority(prodMatches.filter(m => !m.cpeFiltered));
	const devActive   = sortByPriority(devMatches.filter(m => !m.cpeFiltered));
	const embeddedActive = sortByPriority(embeddedMatches.filter(m => !m.cpeFiltered));
	const kevCount    = prodActive.filter(m => m.cve?.kev).length;
	const cpeFilteredCount = (prodMatches.length - prodActive.length) + (devMatches.length - devActive.length);

	const stats = computeStats(prodActive);
	const devStats = computeStats(devActive);
	const sev = ui.sevColor;
	// A vendor-less coord (the PHP runtime finding: namespace "" / name "php") has no group to show.
	const depLabel = d => d.ecosystem === "npm" ? `npm:${d.artifactId}` : d.groupId ? `${d.groupId}:${d.artifactId}` : `${d.ecosystem}:${d.artifactId}`;
	const coordOf = depLabel;   // npm deps show as "npm:name", others as "g:a"
	// Where a finding's dependency was declared — the pom.xml / package.json / jar
	// (embedded jars carry a "app.jar!/BOOT-INF/lib/…" manifestPath). Shown so EOL /
	// obsolete / outdated entries point at the file the reader has to edit.
	const definedInOf = d => {
		const paths = (d?.manifestPaths?.length ? d.manifestPaths : d?.pomPaths?.length ? d.pomPaths : []);
		if (!paths.length) return "";
		const rel = paths.map(p => { try { return path.relative(options.src, p); } catch { return p; } });
		return chalk.dim(`  ← ${rel[0]}${rel.length > 1 ? ` (+${rel.length - 1})` : ""}`);
	};
	const fmtStats = s => [
		s.critical ? sev("CRITICAL")(`${s.critical} critical`) : null,
		s.high ? sev("HIGH")(`${s.high} high`) : null,
		s.medium ? sev("MEDIUM")(`${s.medium} medium`) : null,
		s.low ? sev("LOW")(`${s.low} low`) : null,
		s.unknown ? chalk.gray(`${s.unknown} unknown`) : null,
	].filter(Boolean).join("  ") || chalk.gray("none");
	const heading = (label, n, extra = "") => console.log("\n  " + chalk.bold(label) + chalk.dim(`  (${n})`) + (extra ? "  " + extra : ""));

	ui.section("Results");

	heading("CVE · production", prodActive.length, fmtStats(stats) + (kevCount ? "  " + chalk.bgRed.white(` ${kevCount} KEV `) : ""));
	for (const m of prodActive.slice(0, 12)) {
		const epss = m.cve?.epssPercentile != null ? chalk.dim(` epss ${Math.round(m.cve.epssPercentile * 100)}%`) : "";
		const kev = m.cve?.kev ? " " + chalk.bgRed.white(" KEV ") : "";
		console.log("    " + sev(m.cve.severity)((m.cve.severity || "UNKNOWN").padEnd(8)) + " " + chalk.white(m.cve.id) + "  " + chalk.dim(`${depLabel(m.dep)}:${m.dep.version}`) + epss + kev);
	}
	if (prodActive.length > 12) console.log(chalk.dim(`    …and ${prodActive.length - 12} more (see report)`));
	if (cpeFilteredCount) console.log(chalk.dim(`    ${cpeFilteredCount} likely false positive(s) → report appendix`));

	heading("CVE · dev", devActive.length, devActive.length ? fmtStats(devStats) : "");

	if (embeddedActive.length) {
		heading("CVE · embedded binaries", embeddedActive.length, fmtStats(computeStats(embeddedActive)));
		for (const m of embeddedActive.slice(0, 8)) {
			const top = (m.dep.manifestPaths?.[0] || "").split("!/")[0];
			console.log("    " + sev(m.cve.severity)((m.cve.severity || "UNKNOWN").padEnd(8)) + " " + chalk.white(m.cve.id) + "  " + chalk.dim(`${depLabel(m.dep)}:${m.dep.version}`) + chalk.dim(`  ⊂ ${top}`));
		}
		if (embeddedActive.length > 8) console.log(chalk.dim(`    …and ${embeddedActive.length - 8} more (see report ch.1B)`));
	}

	{
		const { buildInventory } = require("./lib/unmanaged");
		const inv = buildInventory(resolved);
		if (inv.length) {
			heading("Unmanaged binaries", inv.length);
			for (const e of inv.slice(0, 10)) {
				const id = e.identity ? `${e.identity.ecosystem ? e.identity.ecosystem + ":" : ""}${e.identity.name || ""}${e.identity.version ? "@" + e.identity.version : ""}` : chalk.dim("unknown");
				const flags = [e.knownMalicious ? chalk.bgRed.white(" malicious ") : null, e.nameMismatch ? chalk.yellow("name≠checksum") : null, e.shouldBeManaged ? chalk.cyan("should-be-managed") : null, (e.noOnlineInfo ? chalk.dim("unknown") : null)].filter(Boolean).join(" ");
				console.log("    " + chalk.white(path.basename(String(e.path))) + "  " + chalk.dim(id) + (flags ? "  " + flags : ""));
			}
			if (inv.length > 10) console.log(chalk.dim(`    …and ${inv.length - 10} more (see report ch.1C)`));
		}
	}

	if (certFindings.length) {
		const privN = certFindings.filter(c => c.kind === "private-key").length;
		const expiredN = certFindings.filter(c => c.issues.some(i => i.type === "cert-expired")).length;
		heading("Certificates & keys", certFindings.length, [privN ? chalk.red(`${privN} private key`) : null, expiredN ? chalk.yellow(`${expiredN} expired`) : null].filter(Boolean).join("  "));
		for (const c of certFindings.slice(0, 10)) {
			const vis = c.keyVisibility ? chalk.dim(`[${c.keyVisibility}]`) : "";
			const label = c.kind === "certificate" ? `${c.subject || "?"}` : `${c.algorithm || ""} ${c.kind}`.trim();
			console.log("    " + sev(c.severity.toUpperCase())((c.severity || "?").padEnd(8)) + " " + chalk.white(path.basename(String(c.path))) + " " + vis + " " + chalk.dim(label));
		}
		if (certFindings.length > 10) console.log(chalk.dim(`    …and ${certFindings.length - 10} more (see report ch.2.4)`));
	}

	const eolDirectN = eolResults.filter(e => e.dep?.scope !== "transitive").length;
	heading("EOL frameworks", eolResults.length, eolResults.length ? chalk.dim(`${eolDirectN} direct, ${eolResults.length - eolDirectN} transitive`) : "");
	const eolWhenText = e => e.status === "unsupported" ? `support ended ${e.support}` : (e.eol === true || e.eol === "true" ? "EOL" : `EOL ${e.eol}`);
	for (const e of eolResults.slice(0, 8)) console.log("    " + chalk.yellow(e.product.padEnd(18)) + " " + chalk.dim(`${coordOf(e.dep)}:${e.dep.version}`) + " " + chalk.dim(eolWhenText(e)) + (e.components?.length > 1 ? chalk.dim(` (+${e.components.length - 1} components)`) : "") + definedInOf(e.dep));
	if (eolResults.length > 8) console.log(chalk.dim(`    …and ${eolResults.length - 8} more`));

	heading("Obsolete / deprecated", obsoleteResults.length);
	for (const o of obsoleteResults.slice(0, 8)) console.log("    " + chalk.dim(`${coordOf(o.dep)}:${o.dep.version}`) + " → " + (o.replacement || chalk.dim("n/a")) + definedInOf(o.dep));
	if (obsoleteResults.length > 8) console.log(chalk.dim(`    …and ${obsoleteResults.length - 8} more`));

	heading("Outdated", outdatedResults.length, options.allLibs ? "" : chalk.dim("pass -a/--allLibs to query registries"));

	if (retireMatches.length) {
		heading("Vendored JS (retire.js)", retireMatches.length);
		for (const m of retireMatches.slice(0, 8)) console.log("    " + sev(m.cve.severity)((m.cve.severity || "?").padEnd(8)) + " " + chalk.white(m.cve.id) + " " + chalk.dim(`${m.dep.artifactId}@${m.dep.version}`));
		if (retireMatches.length > 8) console.log(chalk.dim(`    …and ${retireMatches.length - 8} more`));
	}

	if (scanWarnings.length) {
		console.log();
		ui.warn(`${scanWarnings.length} scan-completeness note(s) — a real Maven/Snyk run may surface more:`);
		for (const w of scanWarnings) {
			ui.info(chalk.dim(`[${w.type}] ${w.message}`));
			// Items may be plain strings or { id, manifestPaths } objects (the
			// unresolved-versions warning carries the defining manifest paths).
			for (const it of (w.items || []).slice(0, 4)) {
				const id = typeof it === "string" ? it : it.id;
				console.log("      " + chalk.dim(`· ${id}`));
			}
			if ((w.items || []).length > 4) console.log("      " + chalk.dim(`· …and ${w.items.length - 4} more`));
		}
	}

	// License assessment — Maven licenses come (network-free) from cached POMs;
	// the registry passes already filled licenseFindings for the other ecosystems.
	let licenseResults = null;
	if (willLicenses) {
		try {
			if (runMaven || runGradle) {
				const { collectMavenLicenses } = require("./lib/maven-license");
				licenseFindings = licenseFindings.concat(collectMavenLicenses(resolved));
			}
			const { assessLicenses } = require("./lib/license-policy");
			licenseResults = assessLicenses(licenseFindings);
			const flaggedN = licenseResults.flagged.length;
			heading("Licenses", licenseResults.assessed.length, flaggedN ? chalk.yellow(`${flaggedN} to review`) : "");
			for (const e of licenseResults.flagged.slice(0, 8)) {
				console.log("    " + chalk.yellow((e.category).padEnd(16)) + " " + chalk.dim(`${coordOf(e.dep)}`) + " " + chalk.dim((e.ids.concat(e.raw)).join(", ") || "—"));
			}
			if (licenseResults.flagged.length > 8) console.log(chalk.dim(`    …and ${licenseResults.flagged.length - 8} more`));
		} catch (err) { ui.warn(`license assessment skipped: ${err.message}`); }
	}

	const reportDir = options.reportOutput || "./vigievuln-report";
	// --import-anonymized has no source tree; keep the report path-free (consistent
	// with the anonymized descriptor it was fed).
	const srcResolved = options.src ? path.resolve(options.src) : null;
	const projectInfo = {
		name: srcResolved ? path.basename(srcResolved) : "anonymized-descriptor",
		src: srcResolved || "(anonymized descriptor — source path withheld)",
		generatedAt: new Date().toISOString(),
		toolVersion: pkg.version,
		cveDataDate,
	};
	// Scan-provenance manifest: data-source freshness + run configuration, for a
	// reproducible/defensible audit. Surfaced in the report's Methodology chapter and
	// the JSON export's `provenance` block.
	try {
		const { buildScanProvenance } = require("./lib/provenance");
		projectInfo.provenance = buildScanProvenance({ toolVersion: pkg.version, generatedAt: projectInfo.generatedAt, options });
	} catch (err) { if (verbose) ui.warn(`provenance manifest skipped: ${err.message}`); }

	// --- Output target resolution -------------------------------------------------
	// One --report-<type> flag per output, each taking an OPTIONAL path: a string is
	// an explicit path, `true` means "use the default name under --report-output",
	// undefined means "not requested". If NO --report-* flag is given at all, fall
	// back to the default set: HTML + findings JSON. The JSON is there so the NEXT run has
	// something to --baseline against without anyone having to remember a flag; the .doc is
	// still one --report-doc away but is no longer written for people who never open it.
	// file outputs (the scan, terminal summary and --fail-on gate still ran).
	const DEFAULT_NAMES = { html: "cve-report.html", doc: "cve-report.doc", xlsx: "findings.xlsx", sbom: "sbom.cdx.json", csaf: "csaf-vex.json", json: "findings.json", sarif: "fad.sarif" };
	const sel = { html: options.reportHtml, doc: options.reportDoc, xlsx: options.reportXlsx, sbom: options.reportSbom, csaf: options.reportCsaf, json: options.reportJson, sarif: options.reportSarif };
	const anySpecified = Object.values(sel).some(v => v !== undefined);
	const resolveOut = key => {
		const v = sel[key];
		if (v === undefined) return (!anySpecified && (key === "html" || key === "json")) ? path.join(reportDir, DEFAULT_NAMES[key]) : null;
		return (v === true) ? path.join(reportDir, DEFAULT_NAMES[key]) : v;
	};
	const out = options.report === false
		? { html: null, doc: null, xlsx: null, sbom: null, csaf: null, json: null, sarif: null }
		: { html: resolveOut("html"), doc: resolveOut("doc"), xlsx: resolveOut("xlsx"), sbom: resolveOut("sbom"), csaf: resolveOut("csaf"), json: resolveOut("json"), sarif: resolveOut("sarif") };
	const ensureDir = async p => { if (p) await fs.promises.mkdir(path.dirname(path.resolve(p)), { recursive: true }); };

	// Ignored-directories appendix: re-walk --src ONCE under the same prune policy the
	// codec walkers use (the default-exclude union at any depth + --exclude-path,
	// anchored to --src) so the report can list exactly which directories the scan
	// skipped, and why. Only computed when an output that renders it is requested.
	let excludedDirs = [];
	if (options.src && (out.html || out.doc || out.xlsx || out.json)) {
		try {
			const { collectExcludedDirs } = require("./lib/path-filter");
			excludedDirs = collectExcludedDirs({ srcRoot: options.src, excludePath, defaultExcludes });
		} catch { /* best effort — never block the report on the appendix walk */ }
	}

	const reportWarnings = [
		...sourceHealth.degraded().map(s => ({type:"source-unavailable",count:1,
			message:`${s.id}: source unavailable (${s.codes.join(", ") || "no response"}); coverage may be incomplete.`})),
		...sourceHealth.stale().map(s => ({ type:"source-stale", count:1,
			message:`${s.id}: the source could not be refreshed; cached data${s.at ? ` from ${new Date(s.at).toISOString()}` : " of unknown age"} was used. Coverage may be incomplete.` })),
		// A project already on a vendor build of an open-source-EOL cycle: covered by the paid
		// support that build comes from, so it is a note, not an EOL finding.
		...commercialBuildNotes.map(e => ({ type: "commercial-build",
			product: e.product, cycle: e.cycle, coord: `${e.dep.groupId}:${e.dep.artifactId}`,
			version: e.commercialBuild.version, lastPublic: e.commercialBuild.lastPublic, until: e.extendedSupport,
			...(e.dep.manifestPaths?.[0] ? { manifestPath: e.dep.manifestPaths[0] } : {}),
			message: `${e.dep.groupId}:${e.dep.artifactId} ${e.commercialBuild.version} is not on Maven Central and is newer than the last public ${e.product} ${e.cycle} release (${e.commercialBuild.lastPublic}): a vendor build under paid support${e.extendedSupport && e.extendedSupport !== "true" ? ` (until ${e.extendedSupport})` : ""}, not reported as end-of-life.` })),
		...appState.diagnostics.map(d => ({ type: d.sourceIds?.length ? "source-unavailable" : "cms-coverage", code: d.code,
			applicationId: d.applicationId || null, ...(d.path ? { path: d.path } : {}),
			message: `${d.applicationId || d.pluginId || "application"}: ${d.message}` })),
		// CMS coverage gaps are grouped per (application, capability, source, diagnostic)
		// cause: 14 unassessed themes are one cause with 14 components, not 14 identical
		// alerts. The structured fields let the report render reason, action and the
		// component list in its own language; the English message stays for JSON consumers.
		...(() => {
			const componentById = new Map(appState.inventory.map(c => [c.id, c]));
			const groups = new Map();
			for (const c of appState.coverage) {
				if (c.execution !== "partial" && c.execution !== "not-run" && c.execution !== "failed") continue;
				if (appState.diagnostics.some(d => d.applicationId === c.applicationId && d.code === c.diagnostic)) continue;
				const diagnostic = c.diagnostic || "CMS_INCOMPLETE";
				const key = `${c.applicationId}\0${c.capability}\0${c.sourceId || ""}\0${diagnostic}`;
				if (!groups.has(key)) groups.set(key, { applicationId: c.applicationId, capability: c.capability,
					sourceId: c.sourceId || null, execution: c.execution, diagnostic, checks: [] });
				groups.get(key).checks.push(c);
			}
			return [...groups.values()].map(g => {
				const items = g.checks.map(c => {
					const component = componentById.get(c.occurrenceId);
					return { id: component ? `${component.kind || "component"} · ${component.name || component.coord || component.id}`
							: c.occurrenceId || g.applicationId,
						manifestPaths: component?.path ? [path.join(options.src, component.path)] : [] };
				});
				return { type: "cms-coverage", code: g.diagnostic, count: g.checks.length,
					applicationId: g.applicationId, capability: g.capability, sourceId: g.sourceId,
					execution: g.execution, diagnostic: g.diagnostic, items,
					message: `${g.applicationId}: ${g.capability}${g.sourceId ? ` (${g.sourceId})` : ""} — ` +
						`${g.checks.length} component(s) not evaluated (${g.diagnostic})` };
			});
		})(),
		...(suppressedCount ? [{
			type: "suppressed",
			count: suppressedCount,
			message: `${suppressedCount} finding(s) suppressed via triage (--ignore/--vex) — excluded from the chapters above and from CI gating, but retained (flagged) in the JSON/SBOM/CSAF exports.`,
		}] : []),
		...npmWarnings,
		...scanWarnings,
		...retireWarnings,
		...(() => {
			// Maven probes for these explicitly; every other ecosystem now reports the same thing
			// out of its registry pass. One warning either way — an auditor wants "here is what
			// is internal", not one list per package manager.
			const { buildPrivateItems } = require("./lib/private-deps");
			const mavenItems = privateLibIds.map(id => {
				const dep = resolved.get(id);
				const paths = (dep?.pomPaths || []).map(p => path.relative(options.src, p));
				return { id, ecosystem: "maven", manifestPaths: paths };
			});
			const otherItems = buildPrivateItems(registryPrivateHits, { relativise: p => path.relative(options.src, p) });
			const items = [...mavenItems, ...otherItems];
			if (!items.length) return [];
			const ecos = [...new Set(items.map(i => i.ecosystem))].sort().join(", ");
			return [{
				type: "private-libs",
				count: items.length,
				items,
				message: `${items.length} coordinate(s) absent from all configured registries (${ecos}) — possibly private/internal, removed, or incorrect coordinates. This does not exclude them from CVE matching against available data; coverage is not guaranteed. Audit internal packages against your internal feed. Only definitive 404/410 answers from every configured registry count; timeouts and errors leave presence unknown.`,
			}];
		})(),
	];

	// Differential audit vs --baseline: build the current findings doc once, diff it
	// against the prior export → a `diff` block for the report + JSON export, and a
	// `--fail-on-new` gate signal. Best-effort: a missing/unreadable baseline warns.
	let diff = null, jsonDiff = null;
	if (options.baseline) {
		try {
			const baseDoc = JSON.parse(fs.readFileSync(options.baseline, "utf8"));
			const { buildFindings } = require("./lib/json-export");
			const curDoc = buildFindings({ cveMatches, retireMatches, vendoredJsInventory, eolResults, obsoleteResults, outdatedResults, licenseResults,
				excludedDirs, resolvedDeps: resolved, projectInfo, toolVersion: pkg.version, typosquats,
				applications: appState.applications, applicationInventory: appState.inventory,
				applicationRelations, coverage: appState.coverage, warnings: reportWarnings });
			const { diffFindings, summarizeDiff } = require("./lib/diff");
			const dd = diffFindings(baseDoc, curDoc);
			diff = { ...dd, summary: summarizeDiff(dd) };
			jsonDiff = { summary: diff.summary, cve: { added: dd.cve.added, removed: dd.cve.removed, unassessed: dd.cve.unassessed } };
		} catch (err) { ui.warn(`baseline diff skipped (${options.baseline}): ${err.message}`); }
	}

	const wrote = [];
	let xlsxFailed = false;
	// Announce coverage gaps for every output combination, including JSON-only.
	warnIfDegraded();
	if (out.html || out.doc) {
		await ensureDir(out.html); await ensureDir(out.doc);
		// Include collection/registry outages even when they preceded step progress.
		const { htmlPath, docPath } = await writeReports({
			cveMatches: prodMatches, devCveMatches: devMatches, embeddedMatches, retireMatches, vendoredJsInventory, certFindings,
			eolResults, obsoleteResults, outdatedResults, licenseResults, excludedDirs,
			resolvedDeps: resolved, projectInfo, warnings: reportWarnings, parsedManifests, diff, locale: options.lang,
			applications: appState.applications, applicationInventory: appState.inventory, applicationRelations, coverage: appState.coverage,
			htmlPath: out.html, docPath: out.doc,
		});
		if (htmlPath) wrote.push(["HTML report", htmlPath]);
		if (docPath) wrote.push(["Word .doc", docPath]);
	}

	// Machine-readable exports. Use the full match set (prod + dev + cpe-filtered) so
	// the artifacts are complete; cpeFiltered is marked as a property/flag, not dropped.
	if (out.sbom) {
		try {
			const { writeCycloneDx } = require("./lib/sbom-export");
			await ensureDir(out.sbom);
			writeCycloneDx(resolved, cveMatches, out.sbom, { projectInfo, toolVersion: pkg.version, timestamp: projectInfo.generatedAt, licenseResults });
			wrote.push(["CycloneDX SBOM", out.sbom]);
		} catch (err) { ui.warn(`SBOM export failed: ${err.message}`); }
	}
	if (out.csaf) {
		try {
			const { writeCsaf } = require("./lib/csaf-export");
			await ensureDir(out.csaf);
			writeCsaf(resolved, cveMatches, out.csaf, { projectInfo, toolVersion: pkg.version, timestamp: projectInfo.generatedAt });
			wrote.push(["CSAF 2.0 VEX", out.csaf]);
		} catch (err) { ui.warn(`CSAF export failed: ${err.message}`); }
	}
	if (out.json) {
		try {
			const { writeFindings } = require("./lib/json-export");
			await ensureDir(out.json);
			writeFindings({ cveMatches, retireMatches, vendoredJsInventory, certFindings, eolResults, obsoleteResults,
				outdatedResults, licenseResults, excludedDirs, resolvedDeps: resolved, projectInfo, toolVersion: pkg.version,
				typosquats, diff: jsonDiff, applications: appState.applications, applicationInventory: appState.inventory,
				applicationRelations, coverage: appState.coverage, warnings: reportWarnings }, out.json);
			wrote.push(["Findings JSON", out.json]);
		} catch (err) { ui.warn(`JSON export failed: ${err.message}`); }
	}
	if (out.xlsx) {
		try {
			const { writeXlsx } = require("./lib/xlsx-export");
			await ensureDir(out.xlsx);
			writeXlsx({ cveMatches, retireMatches, vendoredJsInventory, certFindings, eolResults, obsoleteResults,
				outdatedResults, licenseResults, excludedDirs, resolvedDeps: resolved, projectInfo, toolVersion: pkg.version,
				typosquats, diff: jsonDiff, applications: appState.applications, applicationInventory: appState.inventory,
				applicationRelations, coverage: appState.coverage, warnings: reportWarnings }, out.xlsx);
			wrote.push(["Excel workbook", out.xlsx]);
		} catch (err) { xlsxFailed = true; ui.warn(`XLSX export failed: ${err.message}`); }
	}
	if (out.sarif) {
		try {
			const { writeSarif } = require("./lib/sarif-export");
			await ensureDir(out.sarif);
			writeSarif(cveMatches.filter(m => !m.suppressed), out.sarif, { projectInfo, toolVersion: pkg.version, certFindings });
			wrote.push(["SARIF", out.sarif]);
		} catch (err) { ui.warn(`SARIF export failed: ${err.message}`); }
	}

	// Integrity manifest: a standard SHA256SUMS over every artifact written this run,
	// for a tamper-evident deliverable (verify with `sha256sum -c SHA256SUMS`). On by
	// default; --no-checksums disables. Written beside the first artifact.
	if (wrote.length && options.checksums !== false) {
		try {
			const { writeChecksums } = require("./lib/report-integrity");
			const files = wrote.map(([, p]) => p);
			const manifestDir = path.dirname(path.resolve(files[0]));
			const manifestPath = path.join(manifestDir, "SHA256SUMS");
			writeChecksums(files, manifestPath, { baseDir: manifestDir });
			wrote.push(["Integrity (SHA-256)", manifestPath]);
		} catch (err) { ui.warn(`checksum manifest skipped: ${err.message}`); }
	}

	if (wrote.length) {
		ui.section("Output");
		for (const [label, p] of wrote) ui.ok(`${label} → ${chalk.white(p)}`);
	} else if (options.report === false) {
		ui.info(chalk.dim(options.importAnonymized
			? "import-anonymized: caches warmed, no report written (pair with --export-cache, then report offline from the real source tree)"
			: "--no-report: no files written (scan + gate only)"));
	}
	console.log();

	// Differential-audit summary (vs --baseline).
	if (diff && diff.summary) {
		const s = diff.summary;
		ui.section("Baseline diff");
		const sev = Object.entries(s.cve.addedBySeverity).filter(([, n]) => n).map(([k, n]) => `${n} ${k.toLowerCase()}`).join(", ") || "none";
		console.log(`  CVE  ${chalk.red(`+${s.cve.added} new`)}  ${chalk.green(`-${s.cve.removed} fixed`)}  ${chalk.dim(`${s.cve.unchanged} unchanged`)}`);
		console.log(`  ${chalk.bold("New production CVE:")} ${s.cve.addedProduction ? chalk.red.bold(s.cve.addedProduction) : chalk.green("0")} ${chalk.dim(`(${sev})`)}`);
		console.log();
	}

	// CI gating — set a non-zero exit code (after all reports/exports are written)
	// when a production finding meets the --fail-on threshold, OR (--fail-on-new) when
	// the scan introduces any new production CVE finding vs the --baseline.
	const newProd = (options.failOnNew && diff && diff.summary) ? diff.summary.cve.addedProduction : 0;
	if ((options.failOn && options.failOn !== "none") || options.failOnNew) {
		const { evaluateGate } = require("./lib/gate");
		// Embedded-binary findings are real production risk → gate on them too.
		const gate = (options.failOn && options.failOn !== "none")
			? evaluateGate([...prodActive, ...embeddedActive], options.failOn)
			: { failed: false, reason: "" };
		// A known-malicious package always blocks, regardless of the --fail-on level.
		const maliciousActive = [...prodActive, ...embeddedActive].filter(m => m.malicious);
		if (gate.failed || maliciousActive.length || newProd > 0) {
			ui.section("Gate");
			if (maliciousActive.length) console.log(chalk.red.bold(`✗ ${maliciousActive.length} known-malicious package(s) detected — always blocks`));
			if (gate.failed) console.log(chalk.red(`✗ --fail-on ${options.failOn}: ${gate.reason}`));
			if (newProd > 0) console.log(chalk.red(`✗ --fail-on-new: ${newProd} new production CVE finding(s) vs baseline`));
			process.exitCode = 1;
		} else if (verbose) {
			ui.info(chalk.dim(`gate: no blocking finding`));
		}
	}
	if (options.failOnIncomplete) {
		const { requiredCoverageComplete } = require("./lib/scan-coverage");
		const raw = options.failOnIncomplete === true ? "inventory,advisories,sources" : String(options.failOnIncomplete);
		const required = [...new Set(raw.split(",").map(x => x.trim()).filter(Boolean))];
		const known = new Set(["inventory", "advisories", "recipes", "sources"]);
		if (!required.length || required.some(x => !known.has(x))) {
			console.error(chalk.red(`❌  invalid --fail-on-incomplete capabilities: ${raw}`));
			process.exitCode = 2;
		} else if ((required.includes("sources") && (sourceHealth.degraded().length || sourceHealth.stale().length || reportWarnings.some(w => w.type === "source-unavailable" || w.type === "source-stale"))) || !requiredCoverageComplete(appState.coverage, required.filter(x => x !== "sources"))) {
			ui.section("Coverage gate");
			console.log(chalk.red(`✗ required application checks incomplete: ${required.join(", ")}`));
			process.exitCode = 2;
		}
	}
	if (xlsxFailed) process.exitCode = 2;
}

// mergeBySource now lives in lib/merge-sources.js (extracted to be unit-testable,
// and made alias-aware: the same advisory can arrive keyed by its CVE from one source
// and by its GHSA remoteId from another — see that module's header).
const { mergeBySource } = require("./lib/merge-sources");

} // end: regular scan / dedicated CLI commands
} // end: compiled-binary retire-mode guard (see top of file)
