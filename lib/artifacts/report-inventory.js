'use strict';

// Presentation only. Acquisition snapshots retain the full inventory for
// advisory matching and offline replay.
const componentIdentity = dep => JSON.stringify([
 dep.packageType || dep.ecosystem || '', dep.namespace || '',
 dep.name || dep.artifactId || dep.coord || '', dep.version || '', dep.architecture || '',
 ...(dep.binaryEvidence?.product ? [dep.artifactPath || dep.binaryEvidence.binaryPath,dep.binaryEvidence.resourceOffset ?? null] : []),
]);
const occurrence = dep => JSON.stringify([dep.coordKey || componentIdentity(dep),dep.artifactPath || dep.manifestPaths?.[0] || '']);
const needsAdvisory = dep => dep.ecosystem === 'system' || dep.ecosystem === 'binary' ||
 dep.provenance === 'binary' || dep.provenance === 'embedded' || dep.osPackageOwners?.length > 0;
function reportedComponents(artifact, matches = []) {
 if (artifact.metadata?.systemApplications) {
  const affected = new Set(matches.filter(m=>m.dep?.artifactTargetId===artifact.id &&
   !m.suppressed && !m.cpeFiltered && (m.cve?.id || m.advisoryId)).map(m=>occurrence(m.dep)));
  return (artifact.components || []).filter(dep=>dep.systemSection==='runtime' || affected.has(occurrence(dep)));
 }
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
  // A distribution comparison needs the package database path and package identity.
  // The full installed file list can be megabytes and repeats for each advisory.
  const advisoryObservations = artifact.advisoryObservations?.map(item => {
   if (!item.dep?.ownedPaths) return item;
   const {ownedPaths,...dep} = item.dep;
   return {...item,dep};
  });
  return {...artifact, ...(advisoryObservations ? {advisoryObservations} : {}), componentCount:artifact.componentCount ?? artifact.components.length, components,
   componentDetailsFiltered:!!artifact.componentDetailsFiltered || components.length !== artifact.components.length};
 });
}
module.exports = {componentIdentity, occurrence, reportedComponents, reportArtifacts};
