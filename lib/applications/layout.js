'use strict';

const nativePath = require('node:path');
const path = nativePath.posix;
const extensionKinds = new Set(['module','plugin','theme','bundle','component','profile','extension','mu-plugin','drop-in','template','package']);
const isExtension = component => extensionKinds.has(component.kind);
const within = (file,dir) => dir === '.' || file === dir || file.startsWith(dir+'/');

// Recognise the CMS's extension directories even when a particular extension
// has no readable version marker. A directory name alone is no catalogue identity.
const directories = {
  ghost: /^content\/themes(?:\/[^/]+)?(?:\/|$)/,
  prestashop: /^(?:(?:admin[^/]*\/)?themes|modules)(?:\/[^/]+)?(?:\/|$)/,
  wordpress: /^(?:plugins|mu-plugins|themes)(?:\/[^/]+)?(?:\/|$)/,
  drupal: /^(?:(?:core|sites\/[^/]+)\/)?(?:modules|themes|profiles)(?:\/(?:contrib|custom))?(?:\/[^/]+)?(?:\/|$)/,
  joomla: /^(?:administrator\/)?(?:plugins(?:\/[^/]+)?|templates|modules|components)(?:\/[^/]+)?(?:\/|$)/,
  typo3: /^(?:typo3conf\/ext|typo3\/sysext)(?:\/[^/]+)?(?:\/|$)/,
  magento: /^app\/(?:code(?:\/[^/]+){0,2}|design(?:\/[^/]+){0,3})(?:\/|$)/,
  spip: /^(?:plugins|plugins-dist)(?:\/[^/]+)?(?:\/|$)/,
};

function extensionLayout(applications, inventory) {
  const apps = applications.filter(a=>a.type !== 'project').slice().sort((a,b)=>b.root.length-a.root.length);
  const byApp = new Map();
  const lockedExtensions = new Set();
  for (const c of inventory) if (isExtension(c) && c.coord) {
    for (const proof of c.evidence || []) if (proof.path && path.basename(proof.path)==='composer.lock') {
      lockedExtensions.add(JSON.stringify([proof.path,c.coord.toLowerCase(),c.versionConflict?.locked || c.version]));
    }
  }
  for (const c of inventory) if (isExtension(c) && c.path) {
    if (!byApp.has(c.applicationId)) byApp.set(c.applicationId,new Map());
    byApp.get(c.applicationId).set(c.path,c);
  }
  function lookup(app,file,directory=false) {
    if (!file || path.isAbsolute(file) || file==='..' || file.startsWith('../') || file===app.root || !within(file,app.root)) return null;
    const owners = byApp.get(app.id);
    for (let dir=file; owners && dir!==app.root && dir!=='.' && dir!=='/'; dir=path.dirname(dir)) {
      if (owners.has(dir)) return {app,component:owners.get(dir)};
    }
    const base = app.type==='wordpress' ? app.contentRoot || path.join(app.root,'wp-content') : app.documentRoot || app.root;
    const rel = path.relative(base,directory ? file : path.dirname(file));
    const expression = Object.hasOwn(directories,app.type) ? directories[app.type] : null;
    const match = expression?.exec(rel);
    if (!match) {
      const site = path.relative(app.documentRoot || app.root,file);
      if ((app.type==='wordpress' && /^(?:wp-includes|wp-admin)(?:\/|$)/.test(site)) ||
          (app.type==='drupal' && /^core(?:\/|$)/.test(site))) return {app,core:true};
      return null;
    }
    // Keep the path in the proof even if the plugin could not identify the module.
    return {app,path:path.join(base,match[0].replace(/\/$/,''))};
  }
  function owner(file,directory=false) {
    for (const app of apps) {
      const match = lookup(app,file,directory);
      if (match) return match;
    }
    return null;
  }
  function lockedExtension(dep) {
    return dep.ecosystem==='composer' && dep.provenance==='lockfile' &&
      lockedExtensions.has(JSON.stringify([dep.artifactPath,[dep.namespace,dep.name].filter(Boolean).join('/').toLowerCase(),dep.version]));
  }
  return {lookup,owner,lockedExtension};
}

// Application-level ownership is separate from the package manager's directness
// within the module's own manifest. Preserve both for private-module remediation.
function attributeLayoutFindings(matches, applications, inventory, srcRoot) {
  if (!applications.length) return;
  const layout = extensionLayout(applications,inventory);
  const modules = new Set(inventory.filter(isExtension).map(c=>c.id));
  const roots = new Map(applications.map(app=>[app.root,app]));
  for (const m of matches) {
    const dep = m.dep;
    if (!dep || dep.ecosystem==='system' || dep.systemSection==='runtime' ||
        ['system','global'].includes(dep.imageSource?.category) || (!srcRoot && !dep.artifactTargetId)) continue;
    if (srcRoot && dep.artifactTargetId) continue;
    const files = dep.artifactPath ? [dep.artifactPath] : dep.manifestPaths || [];
    const paths = files.map(file=>srcRoot && nativePath.isAbsolute(file)
      ? nativePath.relative(srcRoot,file).split(nativePath.sep).join('/') : file);
    if (!paths.length || paths.some(f=>!f || f==='..' || f.startsWith('../'))) continue;
    const owner = layout.owner(paths[0]);
    if (owner && paths.every(f=>{
      const o=layout.lookup(owner.app,f);
      return o && (o.component?.id || o.path)===(owner.component?.id || owner.path);
    })) {
      if ((owner.core && dep.provenance==='application') || m.ownerComponentIds?.some(id=>modules.has(id))) continue;
      const self = moduleSelf(dep,owner.component);
      m.applicationIds=[owner.app.id];
      m.ownerComponentIds=owner.component ? [owner.component.id] : [];
      m.applicationRelation=self ? 'direct' : 'indirect';
      m.applicationExposures=[{applicationId:owner.app.id,ownerComponentIds:m.ownerComponentIds,applicationRelation:m.applicationRelation}];
      m.attributionStatus=owner.component || owner.core ? 'confirmed' : 'unknown';
    } else if (!m.applicationIds?.length && paths.every(f=>path.dirname(f)===path.dirname(paths[0]))) {
      const app=roots.get(path.dirname(paths[0]));
      if (app) {
        m.applicationIds=[app.id];
        m.applicationRelation=managerRelation(dep);
      }
    }
  }
}

function managerRelation(dep) {
  const declared = dep.occurrences?.find(o=>o.version===dep.version && dep.manifestPaths?.includes(o.manifestPath))?.managerRelation || dep.managerRelation;
  if (declared==='direct') return 'direct';
  if (declared==='transitive' || declared==='indirect' || dep.scope==='transitive') return 'indirect';
  if (declared==='unknown' || (dep.ecosystem==='composer' && dep.provenance==='lockfile')) return 'unknown';
  if (dep.systemSection==='project' || ['prod','dev','compile','optional','peer','test'].includes(dep.scope)) return 'direct';
  return 'unknown';
}

function moduleSelf(dep,component) {
  return !!component?.coord && component.coord.toLowerCase()===[dep.namespace,dep.name].filter(Boolean).join('/').toLowerCase() &&
    (!component.version || component.version===dep.version);
}

function applyExtensionScope(dep,layout) {
  if (!dep.systemApplicationIds?.length || dep.systemSection==='runtime') return;
  const owner = layout.owner(dep.artifactPath);
  if (!owner && !layout.lockedExtension(dep)) return;
  if (!dep.managerRelation && dep.provenance==='lockfile') dep.managerRelation=managerRelation(dep);
  const self = !owner || moduleSelf(dep,owner.component);
  if (self && owner?.app.type==='ghost' && owner.component?.kind==='theme' && dep.provenance==='installed' &&
      dep.artifactPath===path.join(owner.component.path,'package.json')) dep.registryIdentity='cms-theme';
  dep.systemSection=self ? 'project' : 'dependency';
  dep.imageRole=self ? 'direct' : 'transitive';
}

// Advisory plugins assess one installed application at a time. Keep the
// original physical finding ID and evidence when displaying an embedded app.
function reparentAssessments(state, embedded) {
  const parents = new Map(embedded.map(entry=>[entry.app.id,entry]));
  for (const key of ['coverage','diagnostics']) for (const record of state[key] || []) {
    const owner = parents.get(record.applicationId);
    if (!owner) continue;
    record.embeddedApplicationId = record.applicationId;
    record.applicationId = owner.applicationId;
    if (record.componentId) {
      record.embeddedComponentId = record.componentId;
      record.componentId = owner.ownerComponentId;
    }
  }
  for (const m of state.findings || []) {
    if (!m.applicationIds?.some(id=>parents.has(id))) continue;
    const exposures = m.applicationIds.map(id=>{
      const owner = parents.get(id);
      if (owner) return {applicationId:owner.applicationId,ownerComponentIds:owner.ownerComponentId ? [owner.ownerComponentId] : [],
        applicationRelation:'indirect'};
      return m.applicationExposures?.find(e=>e.applicationId===id) ||
        {applicationId:id,ownerComponentIds:m.ownerComponentIds || [],applicationRelation:m.applicationRelation};
    });
    m.applicationExposures = exposures;
    m.applicationIds = [...new Set(exposures.map(e=>e.applicationId))];
    m.ownerComponentIds = [...new Set(exposures.flatMap(e=>e.ownerComponentIds))];
    m.applicationRelation = exposures.some(e=>e.applicationRelation==='direct') ? 'direct' : 'indirect';
  }
}

// Drop a descriptor- or framework-derived instance inside an extension. All
// other proven applications (including independent nested sites) keep their IDs.
function reconcileApplications(state, deps = []) {
  const layout = extensionLayout(state.applications,state.inventory);
  const replaced = new Map();
  for (const a of state.applications) {
    const match = layout.owner(a.root,true);
    if (match) replaced.set(a.id,match.app.id);
  }
  if (!replaced.size) return;
  function parent(id) {
    while (replaced.has(id)) id=replaced.get(id);
    return id;
  }
  const byId = new Map(state.applications.map(a=>[a.id,a]));
  const embedded = [];
  for (const app of state.applications) {
    if (!replaced.has(app.id) || !app.pluginId) continue;
    const applicationId = parent(app.id);
    const component = layout.lookup(byId.get(applicationId),app.root,true)?.component;
    embedded.push({app,applicationId,ownerComponentId:component?.id || null,
      inventory:state.inventory.filter(c=>c.applicationId===app.id)});
  }
  if (embedded.length) {
    state.embeddedApplications = [...(state.embeddedApplications || []),...embedded];
    reparentAssessments(state,embedded);
  }
  state.applications = state.applications.filter(a=>!replaced.has(a.id));
  state.inventory = state.inventory.filter(c=>!replaced.has(c.applicationId));
  for (const key of ['relations','diagnostics','coverage']) if (state[key])
    state[key]=state[key].filter(c=>!replaced.has(c.applicationId));
  if (state.findings) state.findings=state.findings.filter(m=>!m.applicationIds?.length || m.applicationIds.some(id=>!replaced.has(id)));
  for (const dep of deps) if (dep.systemApplicationIds?.some(id=>replaced.has(id)))
    dep.systemApplicationIds=[...new Set(dep.systemApplicationIds.map(parent))];
  return replaced;
}

module.exports={reparentAssessments,isExtension,extensionLayout,reconcileApplications,attributeLayoutFindings,managerRelation,moduleSelf,applyExtensionScope};
