/**
 * lib/config.js — persistent user config in ~/.fad-checker/config.json
 *
 * Stores credentials and per-user preferences that should survive across runs.
 * Currently: NVD API key (so users don't have to re-export the env var).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CONFIG_DIR = path.join(require("./cache-directory").getCacheDir());
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

function load() {
	try { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); }
	catch { return {}; }
}

function save(cfg) {
	fs.mkdirSync(CONFIG_DIR, { recursive: true });
	// 0o600 so an API key isn't world-readable
	fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
	try { fs.chmodSync(CONFIG_PATH, 0o600); } catch { /* ignore on platforms without chmod */ }
}

function set(key, value) {
	const cfg = load();
	if (value == null || value === "") delete cfg[key];
	else cfg[key] = value;
	save(cfg);
	return cfg;
}

function get(key) {
	return load()[key];
}

/** NVD API key resolution: env var first, then ~/.fad-checker/config.json. */
function getNvdApiKey() {
	return process.env.NVD_API_KEY || get("nvd_api_key") || null;
}

/**
 * Per-ecosystem custom registries (Nexus/Artifactory/JBoss, Verdaccio, devpi,
 * Gemfury, Athens, …) the user has configured. Stored under config key
 * `registries`: { <ecosystem>: [{ name, url, auth?, token? }] } where `auth` is
 * "user:pass" (→ Basic) and `token` is a Bearer token.
 *
 * Public registries (Maven Central, registry.npmjs.org, …) are intentionally
 * NOT stored here — callers append them as the final fallback so the user's
 * registries stay in priority order while the public one is always a safety net.
 */
function getRegistryMap() {
	const m = get("registries");
	return (m && typeof m === "object" && !Array.isArray(m)) ? m : {};
}

function getRegistries(ecosystem) {
	const list = getRegistryMap()[ecosystem];
	return Array.isArray(list) ? list : [];
}

function setRegistryMap(map) {
	return set("registries", map && Object.keys(map).length ? map : null);
}

function addRegistry(ecosystem, name, url, { auth = null, token = null } = {}) {
	const map = getRegistryMap();
	const list = (map[ecosystem] || []).filter(r => r.name !== name);
	list.push({ name, url, ...(auth ? { auth } : {}), ...(token ? { token } : {}) });
	map[ecosystem] = list;
	setRegistryMap(map);
	return list;
}

function removeRegistry(ecosystem, name) {
	const map = getRegistryMap();
	const before = (map[ecosystem] || []).length;
	map[ecosystem] = (map[ecosystem] || []).filter(r => r.name !== name);
	if (!map[ecosystem].length) delete map[ecosystem];
	setRegistryMap(map);
	return before !== (map[ecosystem]?.length || 0);
}

module.exports = {
	CONFIG_PATH,
	CONFIG_DIR,
	load,
	save,
	set,
	get,
	getNvdApiKey,
	getRegistryMap,
	getRegistries,
	setRegistryMap,
	addRegistry,
	removeRegistry,
};
