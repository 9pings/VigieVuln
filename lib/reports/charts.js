/**
 * lib/reports/charts.js — compact, dependency-free SVG charts for the HTML report's
 * "Overview" row (rendered right under the summary totals).
 *
 * Why hand-rolled inline SVG (not <canvas>, not a chart lib, not pure-CSS):
 *   - self-contained: the report ships zero external assets, and an SVG is just
 *     markup — no runtime, no CDN. It even renders in the static .doc (no JS).
 *   - copy-to-Word: each chart rasterises SVG→<canvas>→PNG entirely in the
 *     browser (see the report's chart-copy script) and a PNG pastes into Word
 *     perfectly. A <div> has no native "→ PNG" API; an SVG does.
 *
 * Every visual attribute is INLINE on the SVG elements (fill/font-size/…), never
 * a CSS class — a class would not survive the canvas rasterisation (the document
 * stylesheet is not applied to the serialised SVG).
 *
 * Charts: (1) CWE distribution, (2) findings by component, (3) exposure or
 * severity breakdown, and (4) fix-priority bands.
 * All four cards use donuts, including application reports. The legends show counts;
 * application categories and exposed instances may overlap.
 *
 * Pure: aggregators take match arrays + counts → plain data; renderers turn that
 * into SVG strings. No I/O, no network.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { computePriority } = require("../findings/priority");

const CWE_NAMES = (() => {
	try { const raw = { ...require("../../data/cwe-names.json") }; delete raw._comment; return raw; }
	catch { return {}; }
})();
const cweName = id => CWE_NAMES[String(id || "").toUpperCase()] || "";

// Default translator: English, and it INTERPOLATES. An identity function would leave a
// literal "{n}" in the text of any caller that passes no translator — which is every
// existing caller of the aggregators, and the whole test suite.
const EN_T = (k, vars) => vars
	? Object.entries(vars).reduce((s, [name, v]) => s.split(`{${name}}`).join(String(v)), k)
	: k;

function esc(s) {
	if (s == null) return "";
	return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Severity series (stacked bars) — colours mirror the report's severity badges.
const SEV_SERIES = [
	{ key: "critical", label: "Critical", color: "#7c0008" },
	{ key: "high",     label: "High",     color: "#c92a2a" },
	{ key: "medium",   label: "Medium",   color: "#f08c00" },
	{ key: "low",      label: "Low",      color: "#3b82f6" },
	{ key: "unknown",  label: "Unknown",  color: "#9ca3af" },
];
// Category colours describe *what* is affected. The outer ring describes *how badly*.
// Assign by key order so a change in the ranking cannot recolour existing categories.
const CATEGORY_COLORS = ["#2563eb", "#0d9488", "#7c3aed", "#d97706",
	"#db2777", "#4d7c0f", "#0891b2", "#795548"];
function colorizeCategories(rows) {
	const keys = rows.filter(r => !r.more).map(r => String(r.key)).sort();
	const byKey = new Map(keys.map((key, i) => [key, CATEGORY_COLORS[i % CATEGORY_COLORS.length]]));
	return rows.map(r => ({ ...r, color: r.more ? "#9ca3af" : byKey.get(String(r.key)) }));
}
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const sevKey = m => {
	const s = (m && m.cve && m.cve.severity || "").toLowerCase();
	return s in SEV_RANK ? s : "unknown";
};
const emptySeg = () => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

// Keep the top-N rows; fold the remainder into a single "+K more" aggregate row
// (a chart must never silently drop categories).
function capRows(rows, topN, { stacked = false, t = EN_T } = {}) {
	if (rows.length <= topN) return rows;
	const kept = rows.slice(0, topN);
	const rest = rows.slice(topN);
	if (stacked) {
		const seg = emptySeg();
		let total = 0;
		for (const r of rest) { for (const k of Object.keys(seg)) seg[k] += r.segments[k] || 0; total += r.total; }
		kept.push({ key: "__more__", label: t("+{n} more", { n: rest.length }), segments: seg, total, more: true });
	} else {
		const value = rest.reduce((a, r) => a + r.value, 0);
		kept.push({ key: "__more__", label: t("+{n} more", { n: rest.length }), value, color: "#9ca3af", more: true });
	}
	return kept;
}

// ---------------------------------------------------------------- aggregators

/** Chart 1 — CWE distribution of DIRECT production vulns, with per-severity counts. */
function cweByCriticality(prodMatches, { topN = 7, t = EN_T, cweTitle = cweName, includeTransitive = false } = {}) {
	const map = new Map();
	for (const m of prodMatches || []) {
		if (!includeTransitive && m.dep && m.dep.scope === "transitive") continue; // source direct findings by default
		const cwes = Array.isArray(m.cve && m.cve.cwes) ? m.cve.cwes : [];
		if (!cwes.length) continue;                                   // a "by CWE" chart only counts categorised findings
		const sev = sevKey(m);
		for (const c of cwes) {
			const id = String(c || "").toUpperCase();
			if (!id) continue;
			if (!map.has(id)) map.set(id, emptySeg());
			map.get(id)[sev]++;
		}
	}
	const rows = [...map.entries()].map(([id, segments]) => ({
		key: id,
		label: id,
		name: cweTitle(id),
		segments,
		total: SEV_SERIES.reduce((a, s) => a + segments[s.key], 0),
	})).sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
	return capRows(rows, topN, { stacked: true, t });
}

// Readable label for a root coordKey: the artifact / package name (the part a
// human recognises), e.g. "org.spring.boot:spring-boot-starter-web" → "spring-boot-starter-web".
function readableDepLabel(coordKey) {
	const s = String(coordKey || "");
	const seg = s.split("/").pop();                                   // npm "@scope/name" path tail
	const tail = seg.includes(":") ? seg.slice(seg.indexOf(":") + 1) : seg;
	return tail || s;
}

/** Findings grouped by actual image identity, with per-severity counts. */
function findingsByImage(matches, artifacts = [], { topN = 7, t = EN_T } = {}) {
 const by = new Map(), targets = new Map((artifacts || []).map(a => [a.id, a]));
 for (const match of matches || []) {
  const id = match.dep?.artifactTargetId; if (!id) continue;
  if (!by.has(id)) by.set(id, { segments: emptySeg(), total: 0 });
  const group = by.get(id); group.segments[sevKey(match)]++; group.total++;
 }
 const rows = [...by].map(([id, group]) => {
  const m = targets.get(id)?.metadata || {};
  const source = m.acquisition?.reference || m.registryEvidence?.reference || m.tags?.[0] || m.source || id;
  const platform = m.platform && typeof m.platform === 'object' ? [m.platform.os, m.platform.architecture, m.platform.variant].filter(Boolean).join('/') : m.platform;
  return { key: id, label: platform ? `${source} (${platform})` : source, segments: group.segments, total: group.total };
 }).sort((a, b) => b.total - a.total || String(a.label).localeCompare(String(b.label)));
 return capRows(rows, topN, { stacked: true, t });
}

/** Group each finding by image, application or module; show shared owners
 * together and retain unknown ownership in an unattributed group. */
function findingsByComponent(matches, { host = false, artifacts = [], applications = [], moduleNames = new Map(), topN = 7, t = EN_T } = {}) {
	const images = new Map(artifacts.map(a => [a.id, a]));
	const apps = new Map(applications.map(a => [a.id, a]));
	const groups = new Map(), occurrences = [], indexed = new Map();
	for (const m of matches || []) {
		const identity = m.findingId ? JSON.stringify([m.dep?.artifactTargetId || null, m.findingId]) : null;
		const prior = identity && indexed.get(identity);
		if (!prior) {
			const copy = { ...m, dep: { ...m.dep, manifestPaths: [...(m.dep?.manifestPaths || [])] }, applicationIds: [...(m.applicationIds || [])] };
			occurrences.push(copy); if (identity) indexed.set(identity, copy);
		} else {
			prior.applicationIds.push(...(m.applicationIds || []));
			prior.dep.manifestPaths.push(...(m.dep?.manifestPaths || []));
			if (SEV_RANK[sevKey(m)] > SEV_RANK[sevKey(prior)]) prior.cve = m.cve;
		}
	}
	for (const m of occurrences) {
		const artifact = m.dep?.artifactTargetId;
		let key, label;
		if (host) {
			label = m.dep?.artifactId || m.dep?.name || m.dep?.coordKey || t("Unknown");
			key = JSON.stringify([artifact, m.dep?.ecosystem, label]);
		} else if (artifact) {
			const meta = images.get(artifact)?.metadata || {};
			const source = meta.acquisition?.reference || meta.registryReference?.reference || meta.tags?.[0] || meta.source || artifact;
			const platform = meta.platform && typeof meta.platform === 'object' ? [meta.platform.os, meta.platform.architecture, meta.platform.variant].filter(Boolean).join('/') : meta.platform;
			key = `image:${artifact}`; label = platform ? `${source} (${platform})` : source;
		} else {
			const appIds = [...new Set((m.applicationIds || []).filter(Boolean))];
			// When parsed descriptors are available, they are the authoritative
			// module inventory. A dependency's own metadata path is not a project module.
			const paths = [...new Set((m.dep?.manifestPaths || []).filter(path => path && (!moduleNames.size || moduleNames.has(path))))];
			if (appIds.length === 1) {
				const app = apps.get(appIds[0]); key = `application:${appIds[0]}`;
				label = `${app?.type || t('Application')} · ${app?.root || appIds[0]}`;
			} else if (appIds.length > 1) {
				appIds.sort(); key = `shared-applications:${JSON.stringify(appIds)}`;
				label = `${t('Shared')}: ${appIds.map(id => apps.get(id)?.root || id).join(', ')}`;
			} else if (!appIds.length && paths.length === 1) {
				key = `module:${paths[0]}`; label = moduleNames.get(paths[0]) || paths[0];
			} else if (paths.length > 1) {
				paths.sort(); key = `shared-modules:${JSON.stringify(paths)}`;
				label = `${t('Shared')}: ${paths.map(path => moduleNames.get(path) || path).join(', ')}`;
			} else { key = '__unattributed__'; label = t('Unattributed'); }
		}
		if (!groups.has(key)) groups.set(key, { key, label, segments: emptySeg(), total: 0 });
		const group = groups.get(key); group.segments[sevKey(m)]++; group.total++;
	}
	const rows = [...groups.values()].sort((a,b) => b.total - a.total || String(a.label).localeCompare(String(b.label)));
	return capRows(rows, topN, { stacked: true, t });
}

/** Chart 2 — sub-dep CVEs grouped by their ROOT (direct) dep, by severity.
 *  Counts CVEs (a sub-dep with 3 CVEs contributes 3), each in its own bucket. */
function vulnSubdepsByDep(prodMatches, { topN = 7, t = EN_T } = {}) {
	const roots = new Map();                                          // rootKey -> segments
	for (const m of prodMatches || []) {
		if (!m.dep || m.dep.scope !== "transitive") continue;
		const root = m.dep.via && m.dep.via[0];
		if (!root) continue;                                          // rootless → unattributedSubdeps()
		if (!roots.has(root)) roots.set(root, emptySeg());
		roots.get(root)[sevKey(m)]++;                                 // one count per CVE, in its own severity
	}
	const rows = [...roots.entries()].map(([root, segments]) => ({
		key: root,
		label: readableDepLabel(root),
		segments,
		total: SEV_SERIES.reduce((a, s) => a + segments[s.key], 0),
	})).filter(r => r.total > 0).sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
	return capRows(rows, topN, { stacked: true, t });
}

/** Sub-dep CVEs on transitive deps with no resolved root (e.g. npm). */
function unattributedSubdeps(prodMatches) {
	let n = 0;
	for (const m of prodMatches || []) {
		if (!m.dep || m.dep.scope !== "transitive") continue;
		if (m.dep.via && m.dep.via[0]) continue;
		n++;
	}
	return n;
}

/**
 * Chart 2 (application scans) — indirect CVEs grouped by the component that INTRODUCES
 * them: the core, the framework, a plugin, a theme (plan §6.3: the application view
 * attributes each library to its origin). Unattributed indirect CVEs are counted in
 * `unknown` and shown as a note — an origin is never invented for them.
 */
function vulnByApplicationOrigin(prodMatches, inventory = [], { topN = 7, t = EN_T } = {}) {
	const componentById = new Map((inventory || []).map(c => [c.id, c]));
	const by = new Map();
	let unknown = 0;
	for (const m of prodMatches || []) {
		if (m.applicationRelation === "direct") continue;   // direct findings are chart 1's lane
		if (!m.applicationIds?.length) continue;           // a different axis — never mixed in
		const owners = [...new Set((m.applicationExposures || []).flatMap(e => e.ownerComponentIds || []))];
		const components = owners.map(id => componentById.get(id)).filter(Boolean);
		if (!components.length) { unknown++; continue; }
		for (const c of components) {
			let e = by.get(c.id);
			if (!e) { e = { segments: emptySeg(), total: 0 }; by.set(c.id, e); }
			e.segments[sevKey(m)]++; e.total++;
		}
	}
	const rows = [...by.entries()].map(([id, e]) => {
		const c = componentById.get(id);
		return { key: id, label: `${(c && c.kind) || "component"} ${(c && (c.name || c.coord)) || id}`,
			segments: e.segments, total: e.total };
	}).filter(r => r.total > 0).sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
	return { rows: capRows(rows, topN, { stacked: true, t }), unknown };
}

/** Chart 3 — where the risk lives: direct vs transitive production vulns, with
 *  each side's per-severity breakdown carried in the legend (e.g. "2C 1H 1M"). */
function directVsTransitive(prodMatches, t = EN_T) {
	const g = { direct: emptySeg(), transitive: emptySeg() };
	for (const m of prodMatches || []) {
		g[(m.dep && m.dep.scope === "transitive") ? "transitive" : "direct"][sevKey(m)]++;
	}
	const tot = seg => SEV_SERIES.reduce((a, s) => a + seg[s.key], 0);
	const summary = seg => SEV_SERIES.filter(s => seg[s.key] > 0).map(s => `${seg[s.key]}${t(s.label)[0]}`).join(" ");
	const out = [];
	if (tot(g.direct))     out.push({ key: "direct",     label: t("Direct"),     name: summary(g.direct),     value: tot(g.direct), segments: g.direct, color: "#4338ca" });
	if (tot(g.transitive)) out.push({ key: "transitive", label: t("Transitive"), name: summary(g.transitive), value: tot(g.transitive), segments: g.transitive, color: "#d97706" });
	return out;
}

/** critical + high — what "major" means for the component ranking. */
const MAJOR_SEVERITIES = new Set(["critical", "high"]);

/**
 * Chart 3 (multi-module projects) — which of the SCANNED PROJECT'S OWN modules carry the
 * most critical/high production vulns. Slices are poms / package.json / … of the tree being
 * audited, never the dependencies they pull in: "which of my modules do I fix first".
 *
 * A finding declared in several modules counts in each, because each of them really does
 * ship it — so the slice total is component-affecting findings, not distinct CVEs.
 * A match with no attributed manifest is skipped rather than charted as a phantom module.
 *
 * @param {Map<string,string>} moduleNames absolute descriptor path → label (lib/inventory/module-names.js)
 */
function mostVulnerableComponents(prodMatches, moduleNames, { topN = 7, t = EN_T } = {}) {
	const by = new Map(), seen = new Map();
	for (const m of prodMatches || []) {
		const sev = sevKey(m);
		if (!MAJOR_SEVERITIES.has(sev)) continue;
		for (const file of (m.dep && m.dep.manifestPaths) || []) {
			if (!file) continue;
			if (!seen.has(file)) seen.set(file, new Set());
			const identity = m.findingId || m;
			if (seen.get(file).has(identity)) continue;
			seen.get(file).add(identity);
			let e = by.get(file);
			if (!e) { e = { segments: emptySeg(), total: 0 }; by.set(file, e); }
			e.segments[sev]++; e.total++;
		}
	}
	const rows = [...by.entries()].map(([file, e]) => ({
		key: file,
		label: (moduleNames && moduleNames.get && moduleNames.get(file)) || file,
		value: e.total, total: e.total,
		segments: e.segments,
	}));
	// Alphabetical tie-break: a re-scan of unchanged code must render the same chart.
	rows.sort((a, b) => b.value - a.value || String(a.label).localeCompare(String(b.label)));
	return colorizeCategories(capRows(rows, topN, { stacked: true, t }).map(r => ({ ...r, value: r.total })));
}

/**
 * Chart 3 (application scans) — which CMS/framework INSTANCE carries the most
 * critical/high application findings (plan §6.4: instances are the projects).
 *
 * Instances overlap by construction: a shared physical occurrence counts in every
 * instance that ships it, so slice values are per-instance exposures, not distinct
 * findings. The returned `unique` keeps the distinct-finding count for the donut
 * center, and `incomplete` carries the advisories-coverage gaps so the chart can
 * state its own scope instead of implying exhaustive coverage.
 */
function mostVulnerableApplications(prodMatches, applications = [], coverage = [], { topN = 7, t = EN_T } = {}) {
	const by = new Map();
	const unique = new Set();
	const seen = new Map();
	for (const m of prodMatches || []) {
		const sev = sevKey(m);
		if (!MAJOR_SEVERITIES.has(sev)) continue;
		for (const appId of m.applicationIds || []) {
			const identity = m.findingId || m;
			unique.add(identity);
			if (!seen.has(appId)) seen.set(appId, new Set());
			if (seen.get(appId).has(identity)) continue;
			seen.get(appId).add(identity);
			let e = by.get(appId);
			if (!e) { e = { segments: emptySeg(), total: 0 }; by.set(appId, e); }
			e.segments[sev]++; e.total++;
		}
	}
	const appById = new Map((applications || []).map(a => [a.id, a]));
	const rows = [...by.entries()].map(([appId, e]) => {
		const app = appById.get(appId);
		return { key: appId, label: `${(app && app.type) || "application"} · ${(app && app.root) || appId}`,
			value: e.total, total: e.total, segments: e.segments };
	}).sort((a, b) => b.value - a.value || String(a.label).localeCompare(String(b.label)));
	return { rows: colorizeCategories(capRows(rows, topN, { stacked: true, t }).map(r => ({ ...r, value: r.total }))), unique: unique.size,
		incomplete: (coverage || []).filter(c => c.capability === "advisories" &&
			["not-run", "partial", "failed"].includes(c.execution)).length };
}

const FIX_BANDS = [
	{ key: "exploited", label: "Exploited", color: "#7c0008" },
	{ key: "critical",  label: "Critical",  color: "#b91c1c" },
	{ key: "high",      label: "High",      color: "#ea580c" },
	{ key: "medium",    label: "Medium",    color: "#ca8a04" },
	{ key: "low",       label: "Low",       color: "#2563eb" },
	{ key: "unknown",   label: "Unknown",   color: "#9ca3af" },
];
/** Chart 4 — fix-priority distribution (composite KEV/EPSS-weighted bands). */
function fixPriority(prodMatches, t = EN_T) {
	const counts = { exploited: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
	for (const m of prodMatches || []) {
		const p = (m.cve && m.cve.priority) || computePriority(m.cve || {});
		if (counts[p.band] != null) counts[p.band]++;
	}
	return FIX_BANDS.map(b => ({ key: b.key, label: t(b.label), value: counts[b.key], color: b.color })).filter(r => r.value > 0);
}

// ------------------------------------------------------------------ renderers

const FONT = "font-family='-apple-system,Segoe UI,Roboto,sans-serif'";

const legendStr = s => s.name ? `${s.label} · ${s.name} · ${s.value}` : `${s.label} · ${s.value}`;
const LEGEND_CHARW = 4.15;                          // ~px per char at the 7.5px legend font

// The viewBox width needed to fit the FULL legend text (no ellipsis). The caller
// takes the MAX across all four charts and feeds it to every donut, so they share
// one viewBox width → uniform donut size when each card is the same 25% slot.
function legendBoxWidth(slices, note) {
	const items = (slices || []).filter(s => s.value > 0);
	return Math.ceil(Math.max(0, ...items.map(s => 13 + legendStr(s).length * LEGEND_CHARW), note ? note.length * 4 : 0)) + 8;
}

// A donut + a legend underneath. Category slices may carry per-severity `segments`;
// these become a thin, aligned outer ring. Fix priority has no segments and stays plain.
function donutChart({ slices, width = 250, note, centerValue, t = EN_T }) {
	const items = (slices || []).filter(s => s.value > 0);
	const total = items.reduce((a, s) => a + s.value, 0);
	// Overlapping groups (per-instance exposures) must not read as exclusive parts of a
	// whole: when the caller supplies the distinct-finding count, the center carries it.
	const center = centerValue != null ? centerValue : total;
	const legendTxt = legendStr;
	// Donut radius — 20% taller than the original 47; every vertical coordinate below
	// (center, hole, legend start) derives from R, so the whole card scales with it.
	const R = 56.4, cy = R + 4, cx = width / 2;
	const severityRing = items.some(s => s.segments);
	const mainR = severityRing ? R - 9 : R;
	const parts = [];
	if (items.length === 1) {
		parts.push(`<circle cx="${cx}" cy="${cy}" r="${mainR}" fill="${items[0].color}"><title>${esc(`${items[0].label}: ${items[0].value}`)}</title></circle>`);
	} else {
		let a0 = -Math.PI / 2;
		for (const s of items) {
			const a1 = a0 + (s.value / total) * 2 * Math.PI;
			const x0 = cx + mainR * Math.cos(a0), y0 = cy + mainR * Math.sin(a0);
			const x1 = cx + mainR * Math.cos(a1), y1 = cy + mainR * Math.sin(a1);
			const large = (a1 - a0) > Math.PI ? 1 : 0;
			const tip = s.name ? `${s.label} — ${s.name}: ${s.value}` : `${s.label}: ${s.value}`;
			parts.push(`<path d="M${cx.toFixed(1)} ${cy.toFixed(1)} L${x0.toFixed(1)} ${y0.toFixed(1)} A${mainR} ${mainR} 0 ${large} 1 ${x1.toFixed(1)} ${y1.toFixed(1)} Z" fill="${s.color}" stroke="#ffffff" stroke-width="1"><title>${esc(tip)}</title></path>`);
			a0 = a1;
		}
	}
	if (severityRing) {
		const innerR = R - 8.5;
		let categoryStart = -Math.PI / 2;
		const point = (radius, angle) => `${(cx + radius * Math.cos(angle)).toFixed(2)} ${(cy + radius * Math.sin(angle)).toFixed(2)}`;
		for (const item of items) {
			const categoryAngle = item.value / total * 2 * Math.PI;
			let angle = categoryStart;
			for (const sev of SEV_SERIES) {
				const count = item.segments?.[sev.key] || 0;
				if (!count) continue;
				const next = angle + categoryAngle * count / item.value;
				const title = `${item.label} — ${t(sev.label)}: ${count}/${item.value} (${Math.round(count / item.value * 100)}%)`;
				if (next - angle >= 2 * Math.PI - 1e-9) {
					parts.push(`<circle class="severity-arc" cx="${cx}" cy="${cy}" r="${(R + innerR) / 2}" fill="none" stroke="${sev.color}" stroke-width="${R - innerR}"><title>${esc(title)}</title></circle>`);
				} else {
					const large = next - angle > Math.PI ? 1 : 0;
					const d = `M${point(R, angle)} A${R} ${R} 0 ${large} 1 ${point(R, next)} L${point(innerR, next)} A${innerR} ${innerR} 0 ${large} 0 ${point(innerR, angle)} Z`;
					parts.push(`<path class="severity-arc" d="${d}" fill="${sev.color}" stroke="#ffffff" stroke-width="0.6"><title>${esc(title)}</title></path>`);
				}
				angle = next;
			}
			categoryStart += categoryAngle;
		}
	}
	parts.push(`<circle cx="${cx}" cy="${cy}" r="${(R * 0.58).toFixed(1)}" fill="#ffffff"/>`);
	parts.push(`<text x="${cx}" y="${cy + 5}" text-anchor="middle" ${FONT} font-size="17" font-weight="700" fill="#374151">${center}</text>`);
	let ly = R * 2 + 23;                             // +10px breathing room donut → legend
	if (severityRing) {
		let x = 0;
		for (const sev of SEV_SERIES.filter(s => items.some(item => item.segments?.[s.key] > 0))) {
			const label = t(sev.label);
			parts.push(`<rect x="${x}" y="${ly - 7}" width="6" height="6" rx="1" fill="${sev.color}"/>`);
			parts.push(`<text x="${x + 9}" y="${ly - 1}" ${FONT} font-size="6.5" fill="#4b5563">${esc(label)}</text>`);
			x += 13 + label.length * 3.4;
		}
		ly += 12;
	}
	for (const s of items) {                         // full legend text — no ellipsis
		parts.push(`<rect x="0" y="${ly - 7}" width="8" height="8" rx="1" fill="${s.color}"/>`);
		parts.push(`<text x="11" y="${ly}" ${FONT} font-size="7.5" fill="#4b5563">${esc(legendTxt(s))}</text>`);
		ly += 11;
	}
	if (note) {
		const limit = Math.max(16, Math.floor(width / 4));
		let line = '';
		for (const word of String(note).split(/\s+/)) {
			if (line && `${line} ${word}`.length > limit) {
				parts.push(`<text x="0" y="${ly}" ${FONT} font-size="7" font-style="italic" fill="#9ca3af">${esc(line)}</text>`);
				ly += 11; line = '';
			}
			line += (line ? ' ' : '') + word;
		}
		if (line) { parts.push(`<text x="0" y="${ly}" ${FONT} font-size="7" font-style="italic" fill="#9ca3af">${esc(line)}</text>`); ly += 11; }
	}
	return { body: parts.join(""), width, height: ly + 2 };
}

function chartCard({ id, title, body, width, height, interactive, t = EN_T }) {
	// The title lives INSIDE the svg (so it travels with the copied PNG); the body
	// is shifted down to make room. The copy button is an HTML overlay (top-right).
	const titleH = 18;
	const h = Math.max(250, Math.round(height + titleH));
	const exportHeight = 250;
	const titleSvg = `<text x="0" y="12" ${FONT} font-size="10.5" font-weight="700" fill="#4b5563">${esc(title)}</text>`;
	const svg = `<svg class="chart-svg" xmlns="http://www.w3.org/2000/svg" width="${width}" height="${exportHeight}" viewBox="0 0 ${width} ${h}" role="img" aria-label="${esc(title)}"><rect x="0" y="0" width="${width}" height="${h}" fill="#ffffff"/>${titleSvg}<g transform="translate(0,${titleH})">${body}</g></svg>`;
	const copyBtn = interactive ? `<button class="btn-copy chart-copy" type="button" title="${esc(t("Copy this chart as a PNG — paste it into Word"))}">📋</button>` : "";
	return `<figure class="chart-card" id="${esc(id)}">${copyBtn}${svg}</figure>`;
}

function emptyCard(id, title, note) {
	return `<figure class="chart-card" id="${esc(id)}"><figcaption class="chart-head"><span class="chart-title">${esc(title)}</span></figcaption><div class="chart-empty">${esc(note)}</div></figure>`;
}

/**
 * Build the four-chart "Overview" row. Returns "" when there is nothing to plot.
 */
function renderChartsGroup(payload = {}, opts = {}) {
	// Injected by the report so this module needs no i18n dependency of its own; identity
	// by default, which keeps every existing caller and test rendering English.
	const t = typeof opts.t === "function" ? opts.t : EN_T;
	const prod = payload.prodMatches || [];
 const imageMatches = prod.filter(m => !!m.dep?.artifactTargetId);
 const sourceMatches = prod.filter(m => !m.dep?.artifactTargetId);
 const hasImages = !!payload.hasImages || imageMatches.length > 0 || (payload.artifacts || []).length > 0;
 const imageOnly = hasImages && !sourceMatches.length;
	const cweTitle = typeof opts.cweName === "function" ? opts.cweName : cweName;
	// Include direct application and source findings, plus image findings, in the
	// CWE distribution; the component chart includes all production findings.
	const applications = payload.applications || [];
	const appScan = applications.length > 0;
	const cweInput = payload.includeAllProjectFindings ? prod : appScan ? sourceMatches.filter(m => m.applicationRelation === "direct" || (!m.applicationIds?.length && m.dep?.scope !== 'transitive')).concat(imageMatches)
  : sourceMatches.filter(m => m.dep?.scope !== 'transitive').concat(imageMatches);
 const cwe = cweByCriticality(cweInput, { t, cweTitle, includeTransitive: hasImages || payload.includeAllProjectFindings });
 const subs = findingsByComponent(prod, { host:payload.host, artifacts: payload.artifacts || [], applications, moduleNames: payload.moduleNames instanceof Map ? payload.moduleNames : new Map(), t });
 const unattr = 0;
 const scope = directVsTransitive(sourceMatches, t);
	const prio = fixPriority(prod, t);
	// On a multi-module tree, "which of my modules is worst" is actionable; the direct vs
	// transitive split is not module-specific and keeps its slot on a single-descriptor scan,
	// where ranking one component against itself would say nothing.
	const moduleNames = payload.moduleNames instanceof Map ? payload.moduleNames : new Map();
	const multiModule = (Number(payload.descriptorCount) || 0) > 1;
	const components = multiModule ? mostVulnerableComponents(sourceMatches, moduleNames, { t }) : [];
	// Application scans rank exposed instances instead of modules (plan §6.4): plugins,
	// themes and extensions count as the direct lane, their dependencies as indirect.
	const appChart = appScan ? mostVulnerableApplications(sourceMatches, applications, payload.coverage || [], { t }) : null;

	if (!hasImages && !payload.showEmpty && !(cwe.length || subs.length || scope.length || prio.length || unattr || components.length || (appChart && appChart.rows.length))) return "";

	const interactive = opts.interactive !== false;       // copy button only in the interactive HTML
	const emptyFindings = t(payload.includeAllProjectFindings ? "No CVE matches." : "No production CVE.");

	const imageSeverity = SEV_SERIES.map(s => ({ ...s, label:t(s.label), value:imageMatches.filter(m => sevKey(m) === s.key).length })).filter(s => s.value);
	const moduleUnique = new Set(sourceMatches.filter(m => MAJOR_SEVERITIES.has(sevKey(m)) && (m.dep?.manifestPaths || []).some(Boolean)).map(m => m.findingId || m)).size;
	const cweSlices = colorizeCategories(cwe.map(r => ({ key: r.key, label: r.more ? r.label : r.key, name: r.name,
		value: r.total, segments: r.segments, more: r.more })));
	const subSlices = colorizeCategories(subs.map(r => ({ key: r.key, label: r.label,
		value: r.total, segments: r.segments, more: r.more })));
	const note2 = unattr
		? appScan ? t("+{n} indirect CVE(s) with no proven origin", { n: unattr })
			: t("+{n} transitive CVE(s) with no resolved root", { n: unattr })
		: "";

	// Share one viewBox width so the four donuts remain aligned.
	const W = Math.max(250, legendBoxWidth(cweSlices), legendBoxWidth(subSlices, note2),
		legendBoxWidth(imageOnly ? imageSeverity : appChart ? appChart.rows : multiModule ? components : scope), legendBoxWidth(prio));

	const cweHeading = hasImages || payload.includeAllProjectFindings ? t("CWE — findings (by severity)") : t("CWE — direct vulns (by criticality)");
 const card1 = cwe.length
		? chartCard({ t, id: "chart-cwe", title: cweHeading, interactive,
			...donutChart({ slices: cweSlices, width: W, t }) })
		: emptyCard("chart-cwe", cweHeading, hasImages ? t("No categorised finding.") : t("No categorised direct CVE."));

	const card2 = (subs.length || unattr)
		? chartCard({ t, id: "chart-subdeps",
			title: t("Findings per component"),
			interactive, ...donutChart({ slices: subSlices, width: W, note: note2, t }) })
		: emptyCard("chart-subdeps",
			t("Findings per component"), emptyFindings);

	const card3 = imageOnly ? (imageSeverity.length ? chartCard({ t, id: 'chart-image-severity', title:t('Findings by severity'), interactive, ...donutChart({slices:imageSeverity,width:W,t}) }) : emptyCard('chart-image-severity',t('Findings by severity'),t('No production CVE.'))) : appChart
		? (appChart.rows.length
			? chartCard({ t, id: "chart-instances", title: t("Most vulnerable instances"), interactive,
				...donutChart({ slices: appChart.rows, width: W, centerValue: appChart.unique, t,
					note: t("Critical/high application findings per exposed instance — a shared occurrence counts in each.") +
						(appChart.incomplete ? " " + t("{n} advisory check(s) incomplete.", { n: appChart.incomplete }) : "") }) })
			: emptyCard("chart-instances", t("Most vulnerable instances"), t("No critical or high application CVE.")))
		: multiModule
			? (components.length
				? chartCard({ t, id: "chart-components", title: t("Most vulnerable components"), interactive, ...donutChart({ slices: components, width: W, centerValue: moduleUnique, note:t('Shared findings count once per affected module.'), t }) })
				: emptyCard("chart-components", t("Most vulnerable components"), t("No critical or high production findings attributed to a project descriptor.")))
			: (scope.length
				? chartCard({ t, id: "chart-scope", title: t("Direct vs transitive (by severity)"), interactive, ...donutChart({ slices: scope, width: W, t }) })
				: emptyCard("chart-scope", t("Direct vs transitive (by severity)"), emptyFindings));

	const card4 = prio.length
		? chartCard({ t, id: "chart-priority", title: t("Fix priority"), interactive, ...donutChart({ slices: prio, width: W }) })
		: emptyCard("chart-priority", t("Fix priority"), emptyFindings);

	return `<section class="charts-row" aria-label="${esc(t("Overview charts"))}">${card1}${card2}${card3}${card4}</section>`;
}

// Source and image occurrences must stay in separate overview rows, even when
// the same package and advisory occur in both inventories.
function renderCharts(payload = {}, opts = {}) {
 const matches = payload.prodMatches || [];
 const source = matches.filter(m => !m.dep?.artifactTargetId);
 const images = matches.filter(m => !!m.dep?.artifactTargetId);
 const hasImages = !!payload.hasImages || images.length > 0 || (payload.artifacts || []).length > 0;
 const sourceRow = payload.hasSourceProject === false ? "" : renderChartsGroup({...payload, prodMatches:source, artifacts:[], hasImages:false, showEmpty:payload.hasSourceProject === true}, opts);
 const translate = typeof opts.t === 'function' ? opts.t : EN_T;
 const labelledSource = sourceRow ? `<h2 class="charts-heading">${esc(translate('Project overview'))}</h2>${sourceRow}` : '';
 const hostRow = payload.hostMatches ? renderChartsGroup({...payload, prodMatches:payload.hostMatches, artifacts:[], applications:[],
   moduleNames:new Map(), descriptorCount:0, host:true, hasImages:true},opts).replace(/id="chart-/g,'id="host-chart-')
   .replace('aria-label="'+esc(translate('Overview charts'))+'"','aria-label="'+esc(translate('Host overview'))+'"') : '';
 const labelledHost = hostRow ? '<h2 class="charts-heading">'+esc(translate('Host overview'))+'</h2>'+hostRow : '';
 const imageRow = hasImages ? renderChartsGroup({...payload, prodMatches:images, applications:[], moduleNames:new Map(), descriptorCount:0, hasImages:true}, opts)
  .replace(/id="chart-/g, 'id="image-chart-')
  .replace(`aria-label="${esc(translate("Overview charts"))}"`, `aria-label="${esc(translate("Image overview charts"))}"`) : '';
 return labelledSource + (imageRow ? `<h2 class="charts-heading">${esc(translate('Image overview'))}</h2>` + imageRow : '') + labelledHost;
}

module.exports = {
	cweByCriticality,
	findingsByImage,
	findingsByComponent,
	vulnSubdepsByDep,
	unattributedSubdeps,
	directVsTransitive,
	mostVulnerableComponents,
	mostVulnerableApplications,
	vulnByApplicationOrigin,
	fixPriority,
	renderCharts,
	SEV_SERIES,
};
