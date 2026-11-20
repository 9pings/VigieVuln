'use strict';

// A saved inventory is validated before this transformation. Filtering an old
// snapshot cannot reconstruct descriptors that its collectors never observed.
const { IMAGE_COMPONENT_SCOPE, isNpmPackageDescriptor, imageComponentRole, imageComponentSource } = require('./component-scope');
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
  let filtered = false;
  result.deps = (result.deps || []).filter(dep => {
    if (isNpmFragment(dep)) { filtered = true; return false; }
    dep.imageRole = imageComponentRole(dep);
    dep.imageSource = imageComponentSource(dep);
    dep.scope = dep.imageRole === 'transitive' ? 'transitive' : 'runtime';
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
