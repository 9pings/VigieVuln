'use strict';

// A saved inventory is validated before this transformation. Filtering an old
// snapshot cannot reconstruct descriptors that its collectors never observed.
const { IMAGE_COMPONENT_SCOPE, isSystemProjectPath, isNpmPackageDescriptor, imageComponentRole, imageComponentSource } = require('./component-scope');
const SCOPE_REASON = 'image-inventory-scope-outdated';
const SCOPE_MESSAGE = 'The saved image inventory predates the current component scope or contains package metadata fragments. Reacquire the image to establish its current inventory.';

function pathsOf(value) {
  return [value?.artifactPath, value?.manifestPath, value?.installEvidence?.path,
    ...(Array.isArray(value?.manifestPaths) ? value.manifestPaths : [])]
    .filter(p => typeof p === 'string');
}
function isFragmentPath(path) {
  return /(?:^|[\\/])package\.json$/i.test(path) && !isNpmPackageDescriptor(path);
}
function isNpmFragment(dep) {
  return dep?.ecosystem === 'npm' && dep?.installEvidence?.source === 'npm'
    && pathsOf(dep).some(isFragmentPath);
}
function applyComponentScope(target, { checkPolicy = true } = {}) {
  const result = structuredClone(target);
  // Publisher SBOM contents are explicit evidence, not filesystem descriptors.
  if (result.kind === 'sbom') return result;
  const systemApps = result.metadata?.systemApplications;
  if (systemApps) {
    // Older collectors used the same result for completed enumeration and failed
    // reads. Only a completed inventory with an explicit count can be normalized.
    const enumerators = new Set(['dpkg','apk','rpm','installed-applications','native-binaries','project-lockfiles']);
    for (const check of result.coverage || []) {
      if (check.capability==='inventory' && check.execution==='completed' && check.result==='indeterminate' &&
          !check.reason && Number.isSafeInteger(check.count) && check.count>=0 && enumerators.has(check.collector))
        check.result='inventoried';
    }
    // Legacy collections could promote example manifests bundled in a gem to
    // projects. The installed gemspec is the evidence for its installed version.
    const storeProjects=new Set(systemApps.applications.filter(a=>a.type==='project' && !isSystemProjectPath(a.root)).map(a=>a.id));
    if(storeProjects.size){
      for(const field of ['applications','inventory','relations','diagnostics','coverage']){
        if(systemApps[field])systemApps[field]=systemApps[field].filter(item=>!storeProjects.has(field==='applications'?item.id:item.applicationId));
      }
      result.coverage=(result.coverage || []).filter(item=>!storeProjects.has(item.applicationId));
      for(const dep of result.deps || []){
        if(dep.systemApplicationIds?.some(id=>storeProjects.has(id))){
          dep.systemApplicationIds=dep.systemApplicationIds.filter(id=>!storeProjects.has(id));
          if(!dep.systemApplicationIds.length){dep.systemSection='dependency';dep.imageRole='transitive';dep.scope='transitive';}
        }
      }
      if(result.metadata.projectDescriptors)result.metadata.projectDescriptors=result.metadata.projectDescriptors.filter(isSystemProjectPath);
    }
    const replaced = require('../applications/layout').reconcileApplications(systemApps,result.deps || []);
    if (replaced) {
      require('../applications/layout').reparentAssessments(result,systemApps.embeddedApplications || []);
      result.coverage=(result.coverage || []).filter(c=>!replaced.has(c.applicationId));
    }
  }
  const layout = systemApps && require('../applications/layout').extensionLayout(systemApps.applications,systemApps.inventory);
  const relations = new Map();
  for (const item of systemApps?.inventory || []) {
    if (!['direct','transitive','indirect'].includes(item.managerRelation) || !item.coord) continue;
    for (const proof of item.evidence || []) relations.set(JSON.stringify([proof.path,item.coord,item.version]),item.managerRelation);
  }
  let filtered = false;
  result.deps = (result.deps || []).filter(dep => {
    if(systemApps && dep.provenance==='lockfile' && dep.artifactPath && !isSystemProjectPath(dep.artifactPath))return false;
    if (isNpmFragment(dep)) { filtered = true; return false; }
    if (!result.metadata?.systemApplications || !dep.systemSection) dep.imageRole = imageComponentRole(dep);
    dep.imageSource = imageComponentSource(dep);
    if (systemApps && dep.systemApplicationIds?.length && dep.provenance === 'lockfile') {
      const coord = [dep.namespace, dep.name].filter(Boolean).join('/');
      const npmDirect = !dep.managerRelation && dep.ecosystem === 'npm' &&
        ['prod','dev','optional','peer'].includes(dep.scope);
      const relation = dep.managerRelation === 'unknown' || !dep.managerRelation
        ? relations.get(JSON.stringify([dep.artifactPath,coord,dep.version])) : dep.managerRelation;
      if (relation) dep.managerRelation=relation;
      if (npmDirect || relation === 'direct') { dep.systemSection = 'project'; dep.imageRole = 'direct'; }
      if (relation === 'transitive' || relation === 'indirect') dep.imageRole = 'transitive';
    }
    if (layout) require('../applications/layout').applyExtensionScope(dep,layout);
    if (dep.provenance !== 'lockfile') dep.scope = dep.imageRole === 'transitive' ? 'transitive' : 'runtime';
    return true;
  });
  result.warnings = (result.warnings || []).filter(w => {
    if (w?.reason === 'installed-metadata-error' && pathsOf(w).some(isFragmentPath)) { filtered = true; return false; }
    return true;
  });
  result.coverage = result.coverage || [];
  result.componentCount = result.deps.length;
  if (checkPolicy && (result.metadata?.componentScope !== IMAGE_COMPONENT_SCOPE || filtered)) {
    const existing = result.coverage.find(c => c.collector === 'installed-applications');
    if (existing) {
      if (!['failed', 'partial'].includes(existing.execution)) existing.execution = 'partial';
      existing.result = 'indeterminate';
      existing.reason = SCOPE_MESSAGE;
    } else result.coverage.push({artifactTargetId:result.id,capability:'inventory',collector:'installed-applications',execution:'partial',result:'indeterminate',reason:SCOPE_MESSAGE});
    if (!result.warnings.some(w => w?.reason === SCOPE_REASON))
      result.warnings.push({type:'dependency-coverage',capability:'inventory',reason:SCOPE_REASON,message:SCOPE_MESSAGE});
  }
  return result;
}
module.exports = { applyComponentScope, SCOPE_REASON, SCOPE_MESSAGE };
