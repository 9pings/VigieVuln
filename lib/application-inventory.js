/**
 * Relate application components to Composer occurrences using local evidence.
 * Physical containment and Composer require edges are separate proofs; a shared
 * library may have several owners while its physical occurrence stays unique.
 */
const crypto = require("node:crypto");
const path = require("node:path");

const posix = value => String(value || "").split(path.sep).join("/").replace(/^\.\//, "");
const within = (child, parent) => parent === "." || child === parent || child.startsWith(parent + "/");
const relative = (root, file) => posix(path.relative(root, file)) || ".";
const coordOf = dep => `${dep.namespace || dep.groupId || ""}/${dep.name || dep.artifactId || ""}`.toLowerCase();

/**
 * Plan §6.3: the kinds an advisory can actually target — a CMS core, a framework, an
 * official framework component, a bundle, an extension, a theme. Only these may root a
 * require walk or hold a self "direct" relation. A lock `library` never self-attributes:
 * its CVEs are indirect under a proven target-kind origin, and explicitly unknown when
 * no origin is established.
 */
const TARGET_KINDS = new Set(["core", "framework", "framework-component", "bundle",
	"module", "component", "theme", "profile", "plugin", "mu-plugin", "drop-in"]);

function buildApplicationRelations(srcRoot, applications = [], components = [], resolvedDeps = new Map()) {
	const appById = new Map(applications.map(a => [a.id, a]));
	const componentsByApp = new Map();
	for (const component of components) {
		if (!appById.has(component.applicationId)) continue;
		const list = componentsByApp.get(component.applicationId) || [];
		list.push(component);
		componentsByApp.set(component.applicationId, list);
	}
	const occurrences = [];
	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem !== "composer") continue;
		for (const occurrence of dep.occurrences || []) {
			const relManifest = relative(srcRoot, occurrence.manifestPath);
			if (relManifest === ".." || relManifest.startsWith("../")) continue;
			occurrences.push({ dep, occurrence, relManifest, coord: coordOf(dep) });
		}
	}
	const relations = [];
	const seen = new Set();
	const resolvedOccurrenceKeys = new Set();
	const add = (app, component, item, proof, dependencyPath) => {
		const key = [app.id, component?.id || "", item.dep.coordKey, item.occurrence.version, item.occurrence.manifestPath].join("\0");
		const occurrenceKey = [app.id, item.dep.coordKey, item.occurrence.version, item.occurrence.manifestPath].join("\0");
		if (seen.has(key)) return;
		seen.add(key);
		if (component) resolvedOccurrenceKeys.add(occurrenceKey);
		relations.push({
			applicationId: app.id, ownerComponentId: component?.id || null,
			depCoordKey: item.dep.coordKey, version: item.occurrence.version,
			manifestPath: item.occurrence.manifestPath,
			applicationRelation: !component ? "unknown" :
				(component.coord?.toLowerCase() === item.coord && TARGET_KINDS.has(component.kind)) ||
				(["core","framework"].includes(component.kind) && path.posix.dirname(item.relManifest) === app.root &&
					item.occurrence.managerRelation === "direct") ? "direct" : "indirect",
			attributionStatus: component ? "confirmed" : "unknown", proof,
			dependencyPath,
		});
	};
	for (const app of applications) {
		const appRoot = posix(app.root || ".");
		const items = occurrences.filter(item => within(item.relManifest, appRoot));
		const owners = componentsByApp.get(app.id) || [];
		const byManifest = new Map();
		for (const item of items) {
			const list = byManifest.get(item.occurrence.manifestPath) || [];
			list.push(item);
			byManifest.set(item.occurrence.manifestPath, list);
			const candidates = owners.filter(c => TARGET_KINDS.has(c.kind) && c.kind !== "core" && c.path && within(item.relManifest, posix(c.path)));
			if (candidates.length) {
				const deepest = Math.max(...candidates.map(c => posix(c.path).length));
				for (const owner of candidates.filter(c => posix(c.path).length === deepest)) {
					add(app, owner, item, "physical-containment", [owner.coord || owner.id, item.coord]);
				}
			}
		}
		for (const [manifestPath, manifestItems] of byManifest) {
			const byCoord = new Map(manifestItems.map(item => [item.coord, item]));
			for (const owner of owners) {
				if (!TARGET_KINDS.has(owner.kind)) continue;
				const start = String(owner.coord || "").toLowerCase();
				if (!start) continue;
				const rootItem = byCoord.get(start);
				if (!rootItem) continue;
				const queue = [{ item: rootItem, chain: [start] }];
				const visited = new Set();
				while (queue.length && visited.size < 1000) {
					const { item, chain } = queue.shift();
					if (visited.has(item.coord)) continue;
					visited.add(item.coord);
					add(app, owner, item, "composer-require", chain);
					if (chain.length >= 20) continue;
					for (const required of Object.keys(item.occurrence.requires || {})) {
						const next = byCoord.get(required.toLowerCase());
						if (next && !visited.has(next.coord)) queue.push({ item: next, chain: [...chain, next.coord] });
					}
				}
			}
		}
		// The application's own root manifest installs the packages nothing else claimed:
		// they are dependencies of the application, attributed to its primary core/framework
		// on the manifest proof (plan §6.3, "Dépendances de l'application"). This covers the
		// drupal/drupal layout, where the root project `replace`s drupal/core and the lock
		// ships the core's own dependencies with no drupal/core entry to walk from.
		const primary = owners.find(c => c.kind === "core" || c.kind === "framework");
		if (primary) {
			for (const item of items) {
				if (path.posix.dirname(item.relManifest) !== (appRoot === "." ? "." : appRoot)) continue;
				const occurrenceKey = [app.id, item.dep.coordKey, item.occurrence.version, item.occurrence.manifestPath].join("\0");
				if (resolvedOccurrenceKeys.has(occurrenceKey)) continue;
				add(app, primary, item, "root-manifest", [primary.coord || primary.id, item.coord]);
			}
		}
		for (const item of items) {
			if (!resolvedOccurrenceKeys.has([app.id, item.dep.coordKey, item.occurrence.version, item.occurrence.manifestPath].join("\0"))) {
				add(app, null, item, "unresolved-origin", []);
			}
		}
	}
	return relations;
}

function expandComposerFindings(matches = [], srcRoot, relations = []) {
	const expanded = [];
	for (const match of matches) {
		const dep = match.dep;
		if (dep?.ecosystem !== "composer" || !Array.isArray(dep.occurrences) || !dep.occurrences.length) {
			expanded.push(match);
			continue;
		}
		const occurrences = dep.occurrences.filter(o => String(o.version) === String(dep.version))
			.sort((a, b) => relative(srcRoot, a.manifestPath).localeCompare(relative(srcRoot, b.manifestPath)));
		if (!occurrences.length) { expanded.push(match); continue; }
		for (const occurrence of occurrences) {
			const paths = [occurrence.manifestPath];
			const related = relations.filter(r => r.depCoordKey === dep.coordKey &&
				String(r.version) === String(dep.version) && r.manifestPath === occurrence.manifestPath);
			const owners = [...new Set(related.map(r => r.ownerComponentId).filter(Boolean))];
			const applications = [...new Set(related.map(r => r.applicationId))];
			const seed = [match.cve?.id || "", dep.coordKey, dep.version, relative(srcRoot, occurrence.manifestPath)].join("\0");
			const findingId = `fad-cve-${crypto.createHash("sha256").update(seed).digest("hex").slice(0, 24)}`;
			// Per-instance exposures: the same physical occurrence can be introduced by a
			// different component in each application, so each instance carries its own
			// owners, relation and introduction paths (plan §6.3; a shared occurrence is
			// detailed in every exposed instance section, never deduced from the first id).
			const exposuresByApp = new Map();
			for (const r of related) {
				const exposure = exposuresByApp.get(r.applicationId) || { applicationId: r.applicationId,
					ownerComponentIds: [], applicationRelation: null, dependencyPaths: [] };
				if (r.ownerComponentId && !exposure.ownerComponentIds.includes(r.ownerComponentId))
					exposure.ownerComponentIds.push(r.ownerComponentId);
				if (r.applicationRelation === "direct" || (r.applicationRelation === "indirect" && exposure.applicationRelation !== "direct") ||
					(!exposure.applicationRelation && r.applicationRelation)) exposure.applicationRelation = r.applicationRelation;
				if (r.ownerComponentId && r.dependencyPath?.length &&
					!exposure.dependencyPaths.some(p => p.join("→") === r.dependencyPath.join("→")))
					exposure.dependencyPaths.push(r.dependencyPath);
				exposuresByApp.set(r.applicationId, exposure);
			}
			expanded.push({
				...match, findingId, applicationIds: applications, ownerComponentIds: owners,
				...(exposuresByApp.size ? { applicationExposures: [...exposuresByApp.values()] } : {}),
				applicationRelation: related.some(r => r.applicationRelation === "direct") ? "direct" :
					related.some(r => r.applicationRelation === "indirect") ? "indirect" : related.length ? "unknown" : null,
				attributionStatus: owners.length ? "confirmed" : related.length ? "unknown" : "not-applicable",
				dependencyPaths: related.filter(r => r.ownerComponentId).map(r => r.dependencyPath),
				dep: { ...dep, version: occurrence.version, scope: occurrence.scope, isDev: occurrence.isDev,
					manifestPaths: paths, pomPaths: paths, occurrences: [occurrence] },
			});
		}
	}
	return expanded;
}

module.exports = { buildApplicationRelations, expandComposerFindings };
