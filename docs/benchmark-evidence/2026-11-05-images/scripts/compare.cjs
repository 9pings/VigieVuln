'use strict';
// Run: node compare.cjs <benchmark-root> <output-dir> [VV report subdirectory]
// Compare exact package/version observations using only explicitly declared IDs.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [base, output, vvDirectory = 'vv-online'] = process.argv.slice(2);
if (!base || !output) throw Error('benchmark root and output directory required');
fs.mkdirSync(output, {recursive: true});
const read = file => JSON.parse(fs.readFileSync(file));
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const typeMap = {system: 'system', apk: 'apk', deb: 'deb', rpm: 'rpm', go: 'golang', 'go-module': 'golang', gobinary: 'golang', alpine: 'apk', debian: 'deb'};
function coordinate(type, name, version) {
  const ecosystem = typeMap[type] || type;
  // Go scanners render the same semver with v/go prefixes. Case is preserved.
  if (ecosystem === 'golang') version = String(version).replace(/^(?:go|v)(?=\d)/, '');
  return {ecosystem, name, version};
}
const key = row => JSON.stringify([row.ecosystem, row.name, row.version]);
function trivyVersion(pkg) {
  const purl = pkg.Identifier?.PURL;
  if (purl && purl.includes('@')) return decodeURIComponent(purl.slice(purl.lastIndexOf('@') + 1).split(/[?#]/)[0]);
  return (pkg.Epoch ? pkg.Epoch + ':' : '') + (pkg.Version || '') + (pkg.Release ? '-' + pkg.Release : '');
}
function record(type, name, version, ids, extra = {}) {
  const declared = [...new Set(ids.filter(id => typeof id === 'string' && id))];
  return {...coordinate(type, name, version), ids: declared, ...extra};
}
function compare(left, right, inventory) {
  const index = new Map();
  for (const row of right) {
    const list = index.get(key(row)) || [];
    list.push(row); index.set(key(row), list);
  }
  const missing = left.filter(row => !(index.get(key(row)) || []).some(other => row.ids.some(id => other.ids.includes(id))));
  return {observations: left.length, matched: left.length - missing.length,
    missing: missing.map(row => ({...row, coordinateInventoried: inventory.has(key(row))}))};
}
function unique(rows) {
  const m = new Map();
  for (const row of rows) m.set(JSON.stringify([key(row), [...row.ids].sort()]), row);
  return [...m.values()];
}
for (const project of ['traefik', 'nginx']) {
  const root = path.join(base, project);
  const files = {vv: path.join(root, vvDirectory, 'findings.json'), trivy: path.join(root, 'trivy.json'), grype: path.join(root, 'grype.json')};
  const vv = read(files.vv), trivy = read(files.trivy), grype = read(files.grype), inventory = read(path.join(root, 'inventory.json'));
  const rows = {
    vv: unique(vv.cve.map(v => record(v.dep.packageType || v.dep.ecosystem, v.dep.coord, v.dep.version,
      [v.id, ...(v.aliases || []), ...(v.upstream || [])], {primaryId: v.id, upstream: v.upstream || [], severity: v.severity}))),
    trivy: unique((trivy.Results || []).flatMap(r => (r.Vulnerabilities || []).map(v => record(r.Type, v.PkgName, v.InstalledVersion,
      [v.VulnerabilityID, ...(v.VendorIDs || [])], {primaryId: v.VulnerabilityID, severity: v.Severity, fixedVersion: v.FixedVersion || null, source: v.DataSource?.ID})))),
    grype: unique(grype.matches.map(m => record(m.artifact.type, m.artifact.name, m.artifact.version,
      [m.vulnerability.id, ...(m.relatedVulnerabilities || []).map(v => v.id)], {primaryId: m.vulnerability.id,
        severity: m.vulnerability.severity, fixedVersion: m.vulnerability.fix?.versions || [], source: m.vulnerability.namespace}))),
  };
  const inventories = {
    vv: inventory.targets.flatMap(t => t.deps.filter(d => d.ecosystem !== 'binary').map(d => coordinate(d.packageType || ({dpkg: 'deb', apk: 'apk', rpm: 'rpm'}[d.manager]) || d.ecosystem, d.namespace && d.ecosystem !== 'system' ? d.namespace + '/' + d.name : d.name, d.version))),
    trivy: (trivy.Results || []).flatMap(r => (r.Packages || []).map(p => coordinate(r.Type, p.Name, trivyVersion(p)))),
    grype: read(path.join(root, 'grype.cdx.json')).components.filter(c => c.type === 'library' && c.purl).map(c => {
      const type = /^pkg:([^/]+)/.exec(c.purl)?.[1];
      return coordinate(type, c.group && type === 'golang' ? c.group + '/' + c.name : c.name, c.version);
    }),
  };
  const inventorySets = Object.fromEntries(Object.entries(inventories).map(([tool, values]) => [tool, new Set(values.map(key))]));
  const pairwise = {};
  for (const comparator of ['trivy', 'grype']) {
    pairwise[comparator + 'AgainstVv'] = compare(rows[comparator], rows.vv, inventorySets.vv);
    pairwise['vvAgainst' + comparator[0].toUpperCase() + comparator.slice(1)] = compare(rows.vv, rows[comparator], inventorySets[comparator]);
  }
  // A single DLA may explicitly refer to many CVEs. Keep observation comparisons
  // above, and expose a separate CVE tuple metric rather than equating all IDs.
  const cveTuples = Object.fromEntries(Object.entries(rows).map(([tool, values]) => [tool,
    [...new Set(values.flatMap(r => r.ids.filter(id => /^CVE-\d{4}-\d+$/.test(id)).map(id => JSON.stringify([r.ecosystem, r.name, r.version, id]))))].sort()]));
  const cveComparison = {};
  for (const comparator of ['trivy', 'grype']) {
    const a = new Set(cveTuples.vv), b = new Set(cveTuples[comparator]);
    cveComparison[comparator] = {vv: a.size, comparator: b.size, common: [...a].filter(k => b.has(k)).length,
      comparatorOnly: [...b].filter(k => !a.has(k)).map(JSON.parse), vvOnly: [...a].filter(k => !b.has(k)).map(JSON.parse)};
  }
  const result = {project, generatedAt: new Date().toISOString(), acquisition: read(path.join(root, 'acquisition.json')),
    reportHashes: Object.fromEntries(Object.entries(files).map(([tool, file]) => [tool, digest(file)])),
    rawFindings: {vv: vv.cve.length, trivy: (trivy.Results || []).reduce((n,r) => n + (r.Vulnerabilities || []).length, 0), grype: grype.matches.length},
    inventoryCounts: Object.fromEntries(Object.entries(inventorySets).map(([tool, set]) => [tool, set.size])),
    inventoryDifferences: Object.fromEntries(['trivy','grype'].map(tool => [tool, {onlyComparator: [...inventorySets[tool]].filter(k => !inventorySets.vv.has(k)).map(JSON.parse), onlyVv: [...inventorySets.vv].filter(k => !inventorySets[tool].has(k)).map(JSON.parse)}])),
    pairwise, cveComparison, warnings: vv.warnings, rows};
  fs.writeFileSync(path.join(output, project + '-comparison.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({project, counts: result.rawFindings, inventory: result.inventoryCounts,
    pairwise: Object.fromEntries(Object.entries(pairwise).map(([name, value]) => [name, {observations:value.observations, matched:value.matched, missing:value.missing.length, absentCoordinates:value.missing.filter(r=>!r.coordinateInventoried).length}])),
    cve: Object.fromEntries(Object.entries(cveComparison).map(([name,value]) => [name,{vv:value.vv,comparator:value.comparator,common:value.common,comparatorOnly:value.comparatorOnly.length,vvOnly:value.vvOnly.length}]))}));
}
