'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {isSystemProjectPath} = require('./component-scope');
const {imageProduct} = require('./product-catalog');

async function inventoryApplications(root, target, descriptors, skipInventoryDir) {
  const groups = new Map();
  for (const relative of descriptors) {
    const basename = path.posix.basename(relative);
    if (basename !== 'composer.lock' && basename !== 'composer.json') continue;
    const file = path.join(root, relative);
    const stat = fs.lstatSync(file,{throwIfNoEntry:false});
    if (!stat?.isFile() || stat.size > 64 * 1024 ** 2) continue;
    const dir = path.dirname(file);
    if (!groups.has(dir)) groups.set(dir, {dir});
    groups.get(dir)[basename === 'composer.lock' ? 'composerLock' : 'composerJson'] = file;
  }
  const composer = await require('../codecs/composer.codec').collect(root, {manifestGroups:groups.values()});
  const composerRelations = new Map();
  for (const pkg of composer.deps.values()) {
    for (const occurrence of pkg.occurrences || []) {
      const file = path.relative(root,occurrence.manifestPath).split(path.sep).join('/');
      composerRelations.set(JSON.stringify([file,pkg.namespace,pkg.name,occurrence.version]),occurrence.managerRelation);
    }
  }
  const result = await require('../applications/plugins/runner').runApplicationPlugins(root, {
    plugins:require('../applications/plugins').allApplicationPlugins(), scanContext:'installation',
    selection:'auto', offline:true, inventoryOnly:true, artifactTargetId:target.id,
    resolvedDeps:composer.deps, activeCodecIds:[...new Set(['composer',...target.deps.map(dep=>dep.ecosystem)])],
    skipInventoryDir:dir => skipInventoryDir?.(dir) || !isSystemProjectPath(path.relative(root,dir)),
  });
  const applications = result.applications;
  const projects = new Map();
  for (const descriptor of descriptors) {
    const dir = path.posix.dirname(descriptor);
    if (!projects.has(dir)) projects.set(dir, []);
    projects.get(dir).push(descriptor);
  }
  const projectPackages = new Map(target.deps.filter(d => d.imageSource?.category === 'project' &&
    d.provenance !== 'lockfile').map(d => [d.artifactPath, d]));
  const knownRoots = new Set(applications.map(app=>app.root));
  const layout = require('../applications/layout').extensionLayout(applications,result.inventory);
  for (const [dir, files] of projects) {
    // The CLI's bundled extensions belong to the installation that loads them.
    const parent = path.posix.dirname(path.posix.dirname(dir));
    if (path.posix.basename(path.posix.dirname(dir)) === 'extensions' &&
        projectPackages.get(path.posix.join(parent,'package.json'))?.name === 'ghost-cli') continue;
    if (knownRoots.has(dir) || layout.owner(dir,true)) continue;
    const id = target.id + ':project:' + dir;
    const evidence = files.map(file => ({path:file}));
    const pkg = files.map(file => projectPackages.get(file)).find(Boolean);
    const name = pkg ? [pkg.namespace,pkg.name].filter(Boolean).join('/') : path.posix.basename(dir);
    applications.push({id, type:'project', root:dir, scanContext:'installation', evidence});
    result.inventory.push({id:id + ':project', applicationId:id, kind:'project', path:dir, name,
      version:pkg?.version || null, versionStatus:pkg?.version ? 'observed' : 'unknown', evidence});
  }
  // Transfer the same occurrence-to-module proofs as a project scan. Qualify the
  // dependency by target and retain only paths relative to the collected root.
  const occurrenceKey = (file,coord,version) => JSON.stringify([file,coord,version]);
  const locks = new Map(target.deps.filter(d=>d.ecosystem==='composer' && d.provenance==='lockfile')
    .map(d=>[occurrenceKey(d.artifactPath,'composer:'+d.namespace+'/'+d.name,d.version),d]));
  const relations = [];
  for (const r of require('../applications/inventory').buildApplicationRelations(root,result.applications,result.inventory,composer.deps)) {
    const manifestPath = path.relative(root,r.manifestPath).split(path.sep).join('/');
    const dep = locks.get(occurrenceKey(manifestPath,r.depCoordKey,r.version));
    if (dep) relations.push({...r,manifestPath,depCoordKey:dep.coordKey});
  }
  target.metadata.systemApplications = {applications, inventory:result.inventory, relations,
    ...(result.embeddedApplications ? {embeddedApplications:result.embeddedApplications} : {})};
  target.coverage.push(...result.coverage.map(c=>({...c,artifactTargetId:target.id,collector:'system-applications'})));
  for (const diagnostic of result.diagnostics.filter(d=>d.code==='CMS_PLUGIN_FAILED')) {
    target.warnings.push({type:'dependency-coverage',capability:'inventory',message:`Application inventory incomplete (${diagnostic.applicationId || diagnostic.pluginId})`});
    target.coverage.push({capability:'inventory',collector:'system-applications',execution:'partial',result:'indeterminate',artifactTargetId:target.id});
  }
  const roots = new Map();
  for (const app of applications) {
    if (!roots.has(app.root)) roots.set(app.root, []);
    roots.get(app.root).push(app.id);
  }
  for (const dep of target.deps) {
    const relative = String(dep.artifactPath || '').replace(/^\/+/, '');
    let dir = path.posix.dirname(relative);
    while (dir !== '.' && !roots.has(dir)) dir = path.posix.dirname(dir);
    const owners = roots.get(dir);
    if (owners && dep.ecosystem !== 'system' && !['system','global'].includes(dep.imageSource?.category)) dep.systemApplicationIds = owners;
    if (dep.ecosystem === 'composer' && dep.provenance === 'lockfile') {
      dep.managerRelation = composerRelations.get(JSON.stringify([relative,dep.namespace,dep.name,dep.version])) || 'unknown';
    }
    const installedLibrary = !isSystemProjectPath(relative) || /\.so(?:\.\d+)*$/.test(relative) || !!dep.binaryMetadata?.soname;
    if (installedLibrary) { dep.imageRole = 'transitive'; dep.scope = 'transitive'; }
    const project = dep.imageSource?.category === 'project' && dep.provenance !== 'lockfile';
    dep.systemSection = installedLibrary ? 'dependency' : imageProduct(dep) ? 'runtime' : project ? 'project' : 'dependency';
    require('../applications/layout').applyExtensionScope(dep,layout);
  }
}
module.exports = {inventoryApplications};
