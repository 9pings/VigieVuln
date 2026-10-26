/**
 * lib/options-env.js — layered option resolution.
 *
 * Layers (highest → lowest): CLI flags > config file (--config / ./.fad-env.json,
 * JSON) > FAD_CHECKER_ENV (a CLI-flag string) > global ~/.fad-checker/config.json
 * > commander defaults. Scalar options follow precedence; `registries` are unioned
 * elsewhere (lib/registries.js). The source flag has aliases (src/source).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { Command } = require("commander");

/** Quote/escape-aware shell-ish tokenizer (single+double quotes, backslash). */
function tokenize(str) {
	const out = [];
	let cur = "", q = null, esc = false, has = false;
	for (const ch of String(str)) {
		if (esc) { cur += ch; esc = false; has = true; continue; }
		if (ch === "\\" && q !== "'") { esc = true; continue; }
		if (q) { if (ch === q) q = null; else cur += ch; has = true; continue; }
		if (ch === '"' || ch === "'") { q = ch; has = true; continue; }
		if (/\s/.test(ch)) { if (has) { out.push(cur); cur = ""; has = false; } continue; }
		cur += ch; has = true;
	}
	if (has) out.push(cur);
	return out;
}

function loadConfigFile(p) {
	const raw = fs.readFileSync(p, "utf8");
	try { return JSON.parse(raw); }
	catch (e) { throw new Error(`invalid JSON in config file ${p}: ${e.message}`); }
}

/** Map `source` → `src` (src wins if both present). Returns a NEW object. */
function normalizeSource(obj) {
	const o = { ...obj };
	if (o.source != null && o.src == null) o.src = o.source;
	delete o.source;
	return o;
}

/**
 * Parse a CLI-flag string into { options, repos } using a throwaway clone of the
 * real program. Only options whose source !== "default" are returned, so unset
 * flags don't clobber higher layers. `repos` (variadic --repo) returned separately.
 */
function parseEnvFlags(str, program) {
	const tokens = tokenize(str);
	if (!tokens.length) return { options: {}, repos: [] };
	const clone = new Command();
	clone.exitOverride().allowUnknownOption(true).configureOutput({ writeErr() {}, writeOut() {} });
	for (const o of program.options) clone.addOption(o);
	try { clone.parse(tokens, { from: "user" }); } catch { /* tolerate */ }
	const all = clone.opts();
	const options = {};
	for (const name of Object.keys(all)) {
		const src = clone.getOptionValueSource(name);
		if (src && src !== "default") options[name] = all[name];
	}
	const repos = Array.isArray(options.repo) ? options.repo : [];
	delete options.repo;
	return { options: normalizeSource(options), repos };
}

/** Resolve { fileLayer, envLayer, envRepos }. */
function loadLayers({ cwd = process.cwd(), configPath = null, envStr = process.env.VIGIEVULN_ENV ?? process.env.FAD_CHECKER_ENV, program = null } = {}) {
	let fileLayer = {};
	const modern = path.join(cwd, ".vigievuln-env.json");
	const chosen = configPath || (fs.existsSync(modern) ? modern : path.join(cwd, ".fad-env.json"));
	if (configPath) fileLayer = loadConfigFile(chosen);
	else if (fs.existsSync(chosen)) fileLayer = loadConfigFile(chosen);
	fileLayer = normalizeSource(fileLayer || {});
	let envLayer = {}, envRepos = [];
	if (envStr && program) {
		// If FAD_CHECKER_ENV points to a readable file, treat its content as flags too.
		let s = envStr;
		try { if (fs.existsSync(envStr) && fs.statSync(envStr).isFile()) s = fs.readFileSync(envStr, "utf8"); } catch { /* inline */ }
		const parsed = parseEnvFlags(s, program);
		envLayer = parsed.options; envRepos = parsed.repos;
	}
	return { fileLayer, envLayer, envRepos };
}

/**
 * Merge layers onto the parsed program. A file/env/global value fills an option
 * ONLY when the CLI did not set it (source default/undefined). Order: file > env
 * > global. Returns the effective options object (a copy of program.opts()).
 */
function applyLayers(program, layers = {}, globalStore = {}) {
	const eff = normalizeSource(program.opts());
	const fileLayer = normalizeSource(layers.fileLayer || {});
	const envLayer = normalizeSource(layers.envLayer || {});
	const cliSet = name => {
		const s = program.getOptionValueSource(name);
		return s && s !== "default";
	};
	const candidates = new Set([...Object.keys(fileLayer), ...Object.keys(envLayer), ...Object.keys(globalStore || {})]);
	candidates.delete("registries");  // unioned separately
	candidates.delete("excludePath"); // unioned separately
	candidates.delete("source");
	for (const name of candidates) {
		if (cliSet(name)) continue; // CLI wins
		if (name in fileLayer) eff[name] = fileLayer[name];
		else if (name in envLayer) eff[name] = envLayer[name];
		else if (globalStore && name in globalStore) eff[name] = globalStore[name];
	}
	return eff;
}

module.exports = { tokenize, loadConfigFile, normalizeSource, parseEnvFlags, loadLayers, applyLayers };
