/**
 * lib/codecs/composer/platform.js — the PHP runtime a Composer project declares.
 *
 * A Composer version constraint says which PHP versions the app ACCEPTS, not which one it
 * runs on. So the only zero-false-positive verdict is: "even the NEWEST PHP this constraint
 * allows is end-of-life". That needs a finite upper bound (`^7.4` = <8.0) or an exact pin
 * (`config.platform.php`). An open constraint (`>=7.2.5`) proves nothing → a chapter-0 note.
 *
 * Constraint grammar handled (Composer): `^X.Y.Z`, `~X.Y`, `~X.Y.Z`, `X.Y.*`, exact, `=`,
 * `<`, `<=`, `>`, `>=`, `!=`, AND by space/comma, OR by `||`/`|`, hyphen ranges `A - B`,
 * stability suffixes (`@dev`, `-dev`) stripped.
 *
 * The PHP runtime is a FINDING, never a dependency: nothing here touches `resolved`.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { makeDepRecord } = require("../../inventory/dep-record");
const { lifecycleStatus } = require("../../maintenance/outdated");

// "7.4" → [7, 4, null]; "v7.4.33-dev" → [7, 4, 33]; garbage → null
function parseVer(s) {
	const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(String(s ?? "").trim());
	if (!m) return null;
	return [Number(m[1]), m[2] == null ? null : Number(m[2]), m[3] == null ? null : Number(m[3])];
}
const fill = v => [v[0], v[1] ?? 0, v[2] ?? 0];
function cmp(a, b) { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; }

// The exclusive upper bound implied by a PARTIAL version used as a range end ("7.4" → <7.5.0,
// "7" → <8.0.0); a full version is inclusive.
function partialUpper(v) {
	if (v[2] != null) return { max: fill(v), inclusive: true };
	if (v[1] != null) return { max: [v[0], v[1] + 1, 0], inclusive: false };
	return { max: [v[0] + 1, 0, 0], inclusive: false };
}

/**
 * Tightest upper bound of one AND-group of constraint tokens.
 * → { max, inclusive } | null when no token bounds it from above.
 * Throws on an unparsable token (caller maps that to "unbounded").
 */
function upperBoundOf(tokens) {
	let best = null;
	const tighten = (max, inclusive) => {
		if (!best) { best = { max, inclusive }; return; }
		const c = cmp(max, best.max);
		if (c < 0 || (c === 0 && !inclusive && best.inclusive)) best = { max, inclusive };
	};
	for (const raw of tokens) {
		const tok = raw.replace(/@\w+$/, "").replace(/-(dev|alpha|beta|rc|stable)\d*$/i, "").trim();
		if (!tok || tok === "*") continue;
		let m;
		if ((m = /^\^(.+)$/.exec(tok))) {                       // ^X.Y.Z → <(X+1).0.0 ; ^0.Y.Z → <0.(Y+1).0
			const v = parseVer(m[1]); if (!v) throw new Error(tok);
			tighten(v[0] === 0 && v[1] != null ? [0, v[1] + 1, 0] : [v[0] + 1, 0, 0], false);
		} else if ((m = /^~(.+)$/.exec(tok))) {                 // ~X.Y → <(X+1).0.0 ; ~X.Y.Z → <X.(Y+1).0
			const v = parseVer(m[1]); if (!v) throw new Error(tok);
			tighten(v[2] == null ? [v[0] + 1, 0, 0] : [v[0], v[1] + 1, 0], false);
		} else if ((m = /^(\d+)(?:\.(\d+))?\.\*$/.exec(tok))) { // 7.4.* / 7.*
			tighten(m[2] == null ? [Number(m[1]) + 1, 0, 0] : [Number(m[1]), Number(m[2]) + 1, 0], false);
		} else if ((m = /^(<=|<|>=|>|!=|==?)\s*(.+)$/.exec(tok))) {
			const op = m[1], v = parseVer(m[2]); if (!v) throw new Error(tok);
			if (op === "<") tighten(fill(v), false);
			else if (op === "<=") tighten(fill(v), true);
			else if (op === "=" || op === "==") { const u = partialUpper(v); tighten(u.max, u.inclusive); }
			// ">", ">=", "!=" bound nothing from above
		} else {                                                // exact "7.4.33", or partial "7.4" (= 7.4.*)
			const v = parseVer(tok); if (!v) throw new Error(tok);
			const u = partialUpper(v); tighten(u.max, u.inclusive);
		}
	}
	return best;
}

/**
 * The highest version a Composer constraint can ever accept.
 * → { max: [x,y,z], inclusive } | null when unbounded (or unparsable — treated as unbounded:
 *   we must never turn "we don't understand it" into a verdict).
 */
function phpCeiling(constraint) {
	const s = String(constraint ?? "").trim();
	if (!s) return null;
	let ceiling = null;
	for (const branch of s.split(/\s*\|\|?\s*/)) {
		const b = branch.trim();
		if (!b) continue;
		let ub;
		try {
			const hy = /^(\S+)\s+-\s+(\S+)$/.exec(b);
			const tokens = hy
				? [`>=${hy[1]}`, `<=${hy[2]}`]               // "7.2 - 7.4": lower inclusive, upper partial → widened below
				: b.split(/\s*,\s*|\s+/).filter(Boolean);
			ub = upperBoundOf(tokens);
			if (hy && ub) { const hv = parseVer(hy[2]); if (hv) ub = partialUpper(hv); }
		} catch { return null; }
		if (!ub) return null;                                   // one unbounded branch → unbounded
		if (!ceiling || cmp(ub.max, ceiling.max) > 0 || (cmp(ub.max, ceiling.max) === 0 && ub.inclusive && !ceiling.inclusive)) ceiling = ub;
	}
	return ceiling;
}

/** The newest endoflife.date cycle ("X.Y") whose first release X.Y.0 the ceiling allows. */
function highestCycleUnder(ceiling, cycles) {
	if (!ceiling || !Array.isArray(cycles)) return null;
	let best = null, bestStart = null;
	for (const c of cycles) {
		const v = parseVer(c.cycle); if (!v) continue;
		const start = fill(v);
		const k = cmp(start, ceiling.max);
		if (k < 0 || (k === 0 && ceiling.inclusive)) {
			if (!best || cmp(start, bestStart) > 0) { best = c; bestStart = start; }
		}
	}
	return best;
}

function readJson(p) {
	try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

/**
 * The PHP constraint a Composer project declares, from the most authoritative source
 * present (first hit wins):
 *   1. composer.lock  platform-overrides.php   — exact pin, from config.platform.php
 *   2. composer.json  config.platform.php
 *   3. composer.lock  platform.php             — require.php as it was locked
 *   4. composer.json  require.php
 * → { constraint, source, manifestPath } | null
 */
function readPlatformPhp(lockPath, jsonPath) {
	const lock = lockPath ? readJson(lockPath) : null;
	const json = jsonPath ? readJson(jsonPath) : null;
	const pick = (v, source, manifestPath) =>
		(typeof v === "string" && v.trim()) ? { constraint: v.trim(), source, manifestPath } : null;
	return pick(lock?.["platform-overrides"]?.php, "lock:platform-overrides", lockPath)
		|| pick(json?.config?.platform?.php, "json:config.platform", jsonPath)
		|| pick(lock?.platform?.php, "lock:platform", lockPath)
		|| pick(json?.require?.php, "json:require", jsonPath)
		|| null;
}

const str = v => (v === true ? "true" : v === false ? "false" : v == null ? "" : String(v));

/**
 * Verdict per declared platform. A finding ONLY when even the newest PHP the constraint
 * allows is EOL (or out of active support, with eolSupport). An undeterminable runtime is
 * NOT a report warning: a deployed runtime is not a manifest property, the note fired on
 * virtually every source tree and drowned the real chapter-0 warnings (removed by user
 * decision). It stays silent — never a verdict, never a note.
 */
function evaluatePhpRuntime(platforms, phpCycles, opts = {}) {
	const { eolSupport = false, now = Date.now() } = opts;
	const findings = [];
	for (const p of platforms || []) {
		if (!p || !p.constraint) continue;
		const ceiling = phpCeiling(p.constraint);
		if (!ceiling) continue;               // open constraint: a supported PHP may satisfy it
		if (!Array.isArray(phpCycles) || !phpCycles.length) continue;
		const cycle = highestCycleUnder(ceiling, phpCycles);
		if (!cycle) continue;
		const status = lifecycleStatus(cycle, now);
		if (status === "ok") continue;         // its newest allowed PHP is still supported
		if (status === "unsupported" && !eolSupport) continue;

		// Synthetic record for the report/exports only — it is NEVER put into `resolved`.
		const dep = makeDepRecord({ ecosystem: "composer", namespace: "", name: "php", version: str(cycle.cycle), manifestPath: p.manifestPath, scope: "runtime", provenance: "platform" });
		findings.push({
			dep,
			product: "PHP",
			productSlug: "php",
			via: "composer-platform",
			viaKey: p.source,
			frameworkId: null,
			cycle: str(cycle.cycle),
			status,
			eol: str(cycle.eol),
			support: str(cycle.support),
			latest: cycle.latest || null,
			notes: `Constraint "${p.constraint}" (${p.source}) allows nothing newer than PHP ${cycle.cycle}${cycle.latest ? ` — latest ${cycle.latest}` : ""}.`,
		});
	}
	return { findings };
}

module.exports = { phpCeiling, highestCycleUnder, readPlatformPhp, evaluatePhpRuntime };
