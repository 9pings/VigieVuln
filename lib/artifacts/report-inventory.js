'use strict';

// Presentation only. Acquisition snapshots retain the full inventory for
// advisory matching and offline replay.
const componentIdentity = dep => JSON.stringify([
 dep.packageType || dep.ecosystem || '', dep.namespace || '',
 dep.name || dep.artifactId || dep.coord || '', dep.version || '', dep.architecture || '',
 ...(dep.binaryEvidence?.product ? [dep.artifactPath || dep.binaryEvidence.binaryPath,dep.binaryEvidence.resourceOffset ?? null] : []),
]);
const needsAdvisory = dep => dep.ecosystem === 'system' || dep.ecosystem === 'binary' ||
 dep.provenance === 'binary' || dep.provenance === 'embedded' || dep.osPackageOwners?.length > 0;
function reportedComponents(artifact, matches = []) {
 const affected = new Set(matches.filter(match =>
  (match.dep?.artifactTargetId || match.artifactTargetId) === artifact.id &&
  !match.cpeFiltered && (match.cve?.id || match.advisoryId)
 ).map(match => componentIdentity(match.dep || {})));
 return (artifact.components || []).filter(dep => {
  if(require('./product-catalog').imageProduct(dep))return true;
  if(affected.has(componentIdentity(dep)))return true;
  if(dep.imageRole==='transitive')return false;
  return !needsAdvisory(dep);
 });
}
function reportArtifacts(artifacts, matches) {
 return artifacts.map(artifact => {
  if (!Array.isArray(artifact.components)) return artifact;
  const components = reportedComponents(artifact, matches);
  return {...artifact, componentCount:artifact.componentCount ?? artifact.components.length, components,
   componentDetailsFiltered:!!artifact.componentDetailsFiltered || components.length !== artifact.components.length};
 });
}
module.exports = {componentIdentity, reportedComponents, reportArtifacts};
