'use strict';

const path = require('node:path').posix;
const {isExtension} = require('../applications/layout');
const {makeDepRecord} = require('../inventory/dep-record');
const {getResource} = require('../providers');
const {compareWordPressVersions} = require('../providers/wordfence/v3');
const {packagistToFindings,composerV2ToPackageObject} = require('../codecs/composer/registry');

const stable = /^v?\d+(?:\.\d+)*$/i;
const coordinate = /^[a-z0-9][a-z0-9_.-]*\/[a-z0-9][a-z0-9_.-]*$/i;
const proofKey = (name,file) => JSON.stringify([name.toLowerCase(),file]);

function moduleLocation(component,descriptors) {
  const evidence = (component.evidence || []).filter(e=>e.path);
  const versionProof = evidence.find(e=>/version/i.test(e.field || '')) || evidence.find(e=>!e.field);
  // Prefer a manifest at this installation root. A module's own composer.lock
  // usually pins its dependencies. Use a lockfile only if the CMS plugin linked
  // a package entry in it to this component.
  const ownManifests = component.path ? ['composer.json','package.json'].map(name=>path.join(component.path,name)) : [];
  const descriptorPath = ownManifests.find(file=>descriptors.has(file) || evidence.some(e=>e.path===file))
    || evidence.find(e=>['composer.json','package.json','composer.lock','package-lock.json'].includes(path.basename(e.path)))?.path;
  return {descriptorPath,versionEvidencePath:versionProof?.path};
}

// An installed extension is a direct component of its CMS. Keep the observed
// version and file even when a different version is recorded in composer.lock.
function moduleChecks(target) {
  const {applications,inventory} = target.metadata.systemApplications;
  const apps = new Map(applications.map(a=>[a.id,a]));
  const components = inventory.filter(isExtension);
  const descriptors = new Set(target.metadata.projectDescriptors || []);
  const composer = new Map(), catalogues = [], proofs = new Map(), checked = new Set();
  for (const c of components) {
    const app = apps.get(c.applicationId);
    if (!app || c.visibility==='private' || !c.version) continue;
    const slug = ['verified','user-declared'].includes(c.catalogueStatus) ? c.slug : c.releaseSlug;
    const wp = app.type==='wordpress' && ['plugin','theme'].includes(c.kind) && /^[a-z0-9][a-z0-9._-]{0,199}$/.test(slug || '');
    const ghost = app.type==='ghost' && c.kind==='theme' && c.visibility==='public' &&
      ['TryGhost/Casper','TryGhost/Source'].includes(c.releaseRepository) && stable.test(c.version);
    if (!ghost && !wp && (!coordinate.test(c.coord || '') || !stable.test(c.version))) continue;
    const [namespace,name] = ghost ? ['theme',c.name] : wp ? [c.kind,slug] : c.coord.toLowerCase().split('/');
    const {descriptorPath,versionEvidencePath} = moduleLocation(c,descriptors);
    const file = descriptorPath || c.path || versionEvidencePath;
    const dep = makeDepRecord({ecosystem:ghost ? 'ghost' : wp ? 'wordpress' : 'composer',namespace,name,version:c.version,
      manifestPath:descriptorPath || versionEvidencePath,provenance:'application',scope:'prod'});
    dep.versionPaths = versionEvidencePath ? {[c.version]:[versionEvidencePath]} : {};
    Object.assign(dep,{artifactTargetId:target.id,artifactPath:file,coordKey:c.id,systemApplicationIds:[app.id],
      systemSection:'project',cmsComponent:{kind:c.kind,name:c.name || name,path:c.path,applicationRoot:app.root,
        ...(descriptorPath && {descriptorPath}),...(versionEvidencePath && {versionEvidencePath})}});
    if (ghost) { catalogues.push({provider:'github',type:'theme-release',params:{repo:c.releaseRepository},dep}); continue; }
    if (wp) { catalogues.push({provider:'wordpress',params:{kind:c.kind,slug},dep}); continue; }
    if (namespace==='magento') continue; // The public Packagist catalogue does not distribute these packages.
    for (const proof of c.evidence || []) if (proof.path) proofs.set(proofKey(c.coord,proof.path),c.id);
    if (namespace==='drupal' && app.type==='drupal') catalogues.push({provider:'drupal',params:{name:c.coord},dep});
    else composer.set(c.id,dep);
  }
  return {components:components.filter(c=>composer.has(c.id) || catalogues.some(entry=>entry.dep.coordKey===c.id)),composer,catalogues,checked,
    replaces(dep, composerOnly = false) {
      if (dep.cmsComponent || dep.ecosystem!=='composer') return false;
      const id = proofs.get(proofKey(dep.namespace+'/'+dep.name,dep.artifactPath));
      return id !== undefined && (!composerOnly || composer.has(id));
    }};
}

async function checkModuleCatalogues(checks, opts) {
  const releases = new Map(), updates = [];
  if (!checks.catalogues.length) return updates;
  const cacheDir = opts.cacheDir || require('../cache/directory').getCacheDir();
  const store = require('../images/network').imageResourceStore(cacheDir,opts);
  for (const {provider,type='extension',params,dep} of checks.catalogues) {
    const key = JSON.stringify([provider,params]);
    if (!releases.has(key)) {
      let record;
      try {
        const response = await getResource(provider,type,params,{store,offline:opts.offline,fetcher:opts.fetcher});
        if (response.ok) record = await response.json();
      } catch { /* An unavailable catalogue is recorded in coverage. */ }
      releases.set(key,record);
    }
    const record = releases.get(key);
    if (!record) continue;
    let latest;
    if (provider==='github') {
      if (record.draft!==false || record.prerelease!==false || !stable.test(record.tag_name || '') ||
          record.html_url!=='https://github.com/'+params.repo+'/releases/tag/'+record.tag_name) continue;
      const version = record.tag_name.replace(/^v/i,'');
      if (compareWordPressVersions(dep.version,version)<0) latest=version;
    } else if (provider==='wordpress') {
      if (record.slug!==params.slug || !stable.test(record.version || '')) continue;
      const comparison = compareWordPressVersions(dep.version,record.version);
      if (comparison===null) continue;
      if (comparison<0) latest=record.version;
    } else {
      const pkg = composerV2ToPackageObject(record,params.name);
      if (!Object.keys(pkg.versions).some(v=>stable.test(v))) continue;
      latest=packagistToFindings(pkg,dep).outdated?.latest;
    }
    checks.checked.add(dep.coordKey);
    if (latest) updates.push({dep,latest,releaseDate:null,source:provider});
  }
  return updates;
}
module.exports={moduleChecks,checkModuleCatalogues};
