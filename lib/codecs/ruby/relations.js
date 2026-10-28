// Read only lockfile evidence. Never execute a Gemfile or infer directness from scope.
function gemfileRelations(text) {
	const roots = new Map(), nodes = new Map(), byName = new Map();
	let section = '', specs = false, parent = null, rootSections = 0, valid = true;
	for (const line of String(text).split(/\r?\n/)) {
		if (/^(<<<<<<<|=======|>>>>>>>|\|{7})/.test(line)) valid = false;
		if (/^\S/.test(line)) {
			section = line.trim(); specs = false; parent = null;
			if (section === 'DEPENDENCIES') rootSections++;
			continue;
		}
		if (!line.trim()) continue;
		if (section === 'DEPENDENCIES') {
			const m = /^ {2}([A-Za-z0-9._-]+)(?: \([^()]+\))?(!)?\s*$/.exec(line);
			if (!m || roots.has(m[1])) { valid = false; continue; }
			roots.set(m[1], !m[2]);
			continue;
		}
		if (!['GEM', 'GIT', 'PATH'].includes(section)) continue;
		if (line === '  specs:') { specs = true; continue; }
		if (!specs) continue;
		const m = /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/.exec(line);
		if (m) {
			const version = m[2].split(/[ -]/)[0], key = `${m[1]}@${version}`;
			const safeVersion = /^\d[\dA-Za-z.]*(?:-(?:java|ruby|x86[^ ]*|arm[^ ]*|aarch[^ ]*|universal[^ ]*))?$/.test(m[2]);
			const node = nodes.get(key) || { name: m[1], version, registry: true, children: new Set() };
			node.registry &&= section === 'GEM' && safeVersion;
			nodes.set(key, node); parent = node;
			if (!byName.has(m[1])) byName.set(m[1], new Set());
			byName.get(m[1]).add(key);
			continue;
		}
		const edge = /^ {6}([A-Za-z0-9._-]+)(?: \([^()]+\))?\s*$/.exec(line);
		if (edge && parent) parent.children.add(edge[1]);
		else { valid = false; parent = null; }
	}
	const result = new Map();
	if (!valid || rootSections !== 1) return result;
	// Several versions of one gem inside a lock need platform/constraint resolution.
	const unique = name => byName.get(name)?.size === 1 ? nodes.get([...byName.get(name)][0]) : null;
	const queue = [];
	for (const [name, registryRoot] of roots) {
		const node = unique(name);
		if (!registryRoot || !node?.registry) continue;
		result.set(`${node.name}@${node.version}`, 'direct'); queue.push(node);
	}
	const visited = new Set();
	for (let i = 0; i < queue.length; i++) {
		const node = queue[i], key = `${node.name}@${node.version}`;
		if (visited.has(key)) continue;
		visited.add(key);
		for (const name of node.children) {
			const child = unique(name);
			if (!child?.registry || roots.get(name) === false) continue;
			const childKey = `${child.name}@${child.version}`;
			if (!result.has(childKey)) result.set(childKey, 'transitive');
			if (!visited.has(childKey)) queue.push(child);
		}
	}
	return result;
}
module.exports = { gemfileRelations };
