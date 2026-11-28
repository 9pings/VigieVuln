'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { makeDepRecord } = require('../inventory/dep-record');
const {IMAGE_COMPONENT_SCOPE,imageComponentRole,imageComponentSource} = require('./component-scope');
const { openArtifact } = require('./index');
const { collectInstalledApplications } = require('./applications');
const { collectSystemInventory } = require('../system-inventory/collect');

const SNAPSHOT_SCHEMA = 'vigievuln-artifact-inventory/1';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function normalizeWarnings(values = [], capability = 'inventory') {
  return values.map(value => typeof value === 'string'
    ? { type: capability === 'inventory' ? 'dependency-coverage' : 'source-unavailable', capability, message: value }
    : { capability, ...value });
}
function coverageRecords(values = [], targetId, capability) {
  return values.map((value, index) => {
    const execution = value.execution || ({ complete: 'completed', completed: 'completed', unsupported: 'partial',
      incomplete: 'partial', unknown: 'partial', missing: 'not-run', failed: 'failed', absent: 'not-applicable' })[value.status] || 'partial';
    return { ...value, artifactTargetId: targetId, capability: value.capability || capability,
      collector: value.collector || value.source || `${capability}-${index}`, execution,
      result: value.result || (execution === 'not-applicable' ? 'not-applicable' :
        execution === 'completed' && capability === 'inventory' ? 'inventoried' : 'indeterminate') };
  });
}
function portable(value, root, replacement = '') {
  // For a live filesystem root, absolute evidence paths already refer to the
  // target. Replacing "//" would corrupt URLs in package metadata.
  if (root === path.parse(root).root) return value;
  if (typeof value === 'string') return value.split(root + path.sep).join(replacement).split(root.replace(/\\/g, '/') + '/').join(replacement);
  if (Array.isArray(value)) return value.map(v => portable(v, root, replacement));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, portable(v, root, replacement)]));
  return value;
}
function qualify(dep, targetId) {
  const out = { ...dep, artifactTargetId: targetId };
  out.artifactPath = dep.manifestPaths?.[0] || dep.manifestPath || dep.installEvidence?.path || null;
  out.coordKey = `artifact:${targetId}:${dep.coordKey || [dep.manager, dep.name, dep.version, out.artifactPath].join(':')}`;
  return out;
}
const PACKAGE_TYPES = { dpkg: 'deb', deb: 'deb', apk: 'apk', rpm: 'rpm' };
function systemDep(pkg, targetId, distribution) {
  const dep = makeDepRecord({ ecosystem: 'system', namespace: distribution?.id || '', name: pkg.name,
    version: pkg.version, manifestPath: pkg.manifestPath, provenance: pkg.provenance || 'installed', scope: 'runtime' });
  dep.coordKey = [pkg.manager || '', pkg.name || '', pkg.version || '', pkg.architecture || '', pkg.manifestPath || ''].map(value => encodeURIComponent(String(value))).join(':');
  return qualify({ ...dep, manager: pkg.manager, packageType: pkg.packageType || PACKAGE_TYPES[pkg.manager] || null,
    architecture: pkg.architecture, sourceName: pkg.sourceName, sourceVersion: pkg.sourceVersion,
    distribution, systemEvidence: pkg.evidence || null, packageMetadata:pkg.packageMetadata || null, packageOrigin:pkg.packageOrigin || null }, targetId);
}

async function inventoryTarget(target, options = {}) {
  const system = await collectSystemInventory(target.root, options);
  const applications = await collectInstalledApplications(target.root, options);
  const imageJs = options.imageRetire ? await require('./retire').collectImageJs(target.root,options,system.packages.flatMap(p=>p.ownedPaths || [])) : null;
  const binaries = await require('../codecs/binary.codec').collect(target.root, { ...options, defaultExcludes: false, imageProducts:true, srcRoot: target.root });
  for (const dep of binaries.deps.values()) {
    const product=require('./product-catalog').binaryProduct(dep.name);
    if (!['tcl','java'].includes(product?.id) || dep.binaryMetadata?.format!=='elf') continue;
    const location=path.relative(target.root,dep.manifestPaths[0]);
    try {
      const evidence=require('./install-version').installedVersion(target.root,location,dep.binaryMetadata,product);
      if (evidence) (dep.binaryMetadata.products ||= []).push(evidence);
    } catch { dep.binaryMetadata.productReadError=true; }
  }
  const order = (a, b) => JSON.stringify([a.ecosystem, a.manager, a.namespace, a.name, a.version, a.architecture, a.manifestPath, a.manifestPaths]).localeCompare(JSON.stringify([b.ecosystem, b.manager, b.namespace, b.name, b.version, b.architecture, b.manifestPath, b.manifestPaths]));
  const packages = portable(system.packages, target.root).map(p => ({ ...p, ...(p.ownedPaths ? { ownedPaths: [...p.ownedPaths].sort() } : {}) })).sort(order);
  const appDeps = portable([...applications.deps.values(), ...binaries.deps.values(), ...(imageJs?.deps || [])], target.root).sort(order);
  const id = target.kind === 'rootfs' && target.metadata.format === 'directory'
    ? `rootfs-inventory:sha256:${sha(JSON.stringify({ systemSource:options.systemSource, distribution: system.distribution, packages, deps: appDeps }))}` : target.id;
  const owners = new Map();
  const pathKey = value => path.posix.normalize('/' + String(value || '').replace(/\\/g, '/').replace(/^\/+/, ''));
  for (const pkg of packages) for (const ownedPath of pkg.ownedPaths || []) {
    const keys = new Set([pathKey(ownedPath)]);
    // Resolve directory aliases such as merged-/usr, never follow the file's own
    // symlink: ownership of a link does not confer ownership of its destination.
    try {
      const root = fs.realpathSync(target.root), parent = fs.realpathSync(path.dirname(path.join(root, ownedPath.replace(/^\/+/, ''))));
      if (parent === root || parent.startsWith(root.endsWith(path.sep) ? root : root + path.sep)) keys.add(pathKey(path.relative(root, path.join(parent, path.basename(ownedPath)))));
    } catch { /* Removed/unavailable owned paths do not create invented evidence. */ }
    for (const key of keys) {
      const list = owners.get(key) || [];
      list.push({ name: pkg.name, version: pkg.version, manager: pkg.manager, ...(pkg.architecture && {architecture:pkg.architecture}), evidencePath: pkg.manifestPath });
      owners.set(key, list);
    }
  }
  const deps = [...packages.map(p => systemDep(p, id, system.distribution)), ...appDeps.map(d => {
    const evidence = d.binaryEvidence?.binaryPath || d.installEvidence?.path || d.manifestPaths?.[0];
    // A shared aggregate manifest does not prove that every package it names is OS-owned.
    const aggregate = d.provenance === 'lockfile' || ['composer', 'composer-php', 'nuget'].includes(d.installEvidence?.source);
    const owned = evidence && !aggregate ? owners.get(pathKey(evidence)) : null;
    return qualify(owned?.length ? { ...d, osPackageOwners: owned } : d, id);
  })];
  require('./image-products').applyProductVersions(deps);
  for(const dep of deps){dep.imageRole=imageComponentRole(dep);dep.imageSource=imageComponentSource(dep);if(dep.provenance!=='lockfile')dep.scope=dep.imageRole==='transitive'?'transitive':'runtime';}
  const warnings = portable(normalizeWarnings([...(system.warnings || []), ...applications.warnings, ...binaries.warnings, ...(imageJs?.warnings || []),
    ...(target.metadata.warnings || [])]), target.root);
  const coverage = coverageRecords(system.coverage, id, 'inventory');
  const productErrors=deps.filter(d=>d.binaryMetadata?.productReadError || d.binaryMetadata?.partial);
  if(productErrors.length) {
    coverage.push({artifactTargetId:id,capability:'inventory',collector:'image-product-metadata',execution:'partial',result:'indeterminate',count:productErrors.length});
    warnings.push({capability:'inventory',type:'dependency-coverage',reason:'image-product-metadata-incomplete',message:'Product metadata could not be fully read in '+productErrors.length+' executable(s).'});
  }
  if(imageJs)coverage.push({...imageJs.coverage,artifactTargetId:id});
  coverage.push({ artifactTargetId: id, capability: 'inventory', collector: 'installed-applications',
    execution: applications.coverage.complete ? 'completed' : 'partial', result: applications.coverage.complete ? 'inventoried' : 'indeterminate', count: applications.deps.size });
  coverage.push({ artifactTargetId: id, capability: 'inventory', collector: 'native-binaries',
    execution: binaries.warnings.length ? 'partial' : 'completed', result: binaries.warnings.length ? 'indeterminate' : 'inventoried', count: [...binaries.deps.values()].filter(d => d.ecosystem === 'binary').length });
  if (target.metadata.warnings?.length) coverage.push({ artifactTargetId: id, capability: 'inventory', collector: 'artifact-reader', execution: 'partial', result: 'indeterminate' });
  const originalSource = target.metadata.source || target.root;
  const source = options.source || path.basename(originalSource) || originalSource;
  const acquisition = options.registry ? { kind: 'registry', reference: source } : {
    kind: target.metadata.diskFormat ? 'vm-disk' : target.metadata.format === 'directory' ? 'rootfs-directory' : target.metadata.format === 'oci-layout' && target.metadata.source && fs.statSync(target.metadata.source).isDirectory() ? 'oci-layout' : 'archive', source,
  };
  return { id, kind: target.kind, metadata: { ...target.metadata, componentScope:IMAGE_COMPONENT_SCOPE, source, acquisition, definitions: [], definitionDiscovery: {status:'not-supplied'} },
    evidence: 'content-inventory', inventoryAt: new Date().toISOString(), distribution: system.distribution,
    packages, deps, coverage, warnings: require('./access-warnings').foldAccessWarnings(warnings), componentCount: deps.length };
}

function sbomTarget(input, options = {}) {
  const parsed = require('./sbom').readSbom(input, options);
  const id = 'sbom-inventory:sha256:' + sha(JSON.stringify(typeof input === 'string' ? JSON.parse(fs.readFileSync(input, 'utf8')) : input));
  // A root component's name is not an os-release identity.
  const mismatch = options.distribution && parsed.distribution && (options.distribution.id !== parsed.distribution.id || options.distribution.versionId !== parsed.distribution.versionId);
  if (mismatch) parsed.warnings.push({ type: 'dependency-coverage', reason: 'sbom-distribution-conflict', message: 'Requested distribution conflicts with publisher SBOM distribution evidence.' });
  const distribution = parsed.warnings.some(w => w.reason === 'sbom-distribution-conflict') ? null : (options.distribution || parsed.distribution || null);
  const packages = parsed.systemPackages;
  const deps = [...packages.map(p => systemDep(p, id, distribution)), ...[...parsed.deps.values()].map(d => qualify(d, id))];
  return { id, kind: 'sbom', metadata: { ...parsed.metadata, source: typeof input === 'string' ? path.basename(input) : options.source,
    digest: options.expectedDigest || parsed.metadata.subjectDigests?.[0] || null, platform: options.platform || parsed.metadata.platform,
    acquisition: options.registry ? { kind: 'registry', reference: options.registryReference || options.source } : { kind: 'sbom', source: typeof input === 'string' ? path.basename(input) : options.source || null }, definitions: [], definitionDiscovery: {status:'not-supplied'} },
    evidence: 'sbom', inventoryAt: new Date().toISOString(), distribution, packages, deps,
    warnings: parsed.warnings, coverage: [{ artifactTargetId: id, capability: 'inventory', collector: 'sbom',
      execution: 'partial', result: 'indeterminate', reason: 'Publisher inventory; component completeness and signature not verified.' }], componentCount: deps.length };
}

function createSnapshot(targets) {
  const content = { schema: SNAPSHOT_SCHEMA, generatedAt: new Date().toISOString(), targets };
  return { ...content, integrity: { algorithm: 'sha256', digest: sha(JSON.stringify(content)) } };
}
function validateSnapshot(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw Error('invalid artifact inventory schema or integrity');
  const { integrity, ...content } = doc;
  if (content.schema !== SNAPSHOT_SCHEMA || !Array.isArray(content.targets) || !content.targets.length || integrity?.algorithm !== 'sha256' || integrity.digest !== sha(JSON.stringify(content))) throw Error('invalid artifact inventory schema or integrity');
  const targetIds = new Set(), componentIds = new Set();
  for (const target of content.targets) {
    if (!target || typeof target.id !== 'string' || !target.id || targetIds.has(target.id) || !target.metadata || !Array.isArray(target.deps) || !Array.isArray(target.packages) || !Array.isArray(target.coverage) || !Array.isArray(target.warnings)) throw Error('invalid or duplicate artifact inventory target');
    targetIds.add(target.id);
    const apps = target.metadata.systemApplications;
    if (apps !== undefined) {
      if (!Array.isArray(apps?.applications) || !Array.isArray(apps.inventory)) throw Error('invalid system application inventory');
      const ids = new Set();
      function checkApp(app) {
        if (typeof app?.id !== 'string' || !app.id.startsWith(target.id + ':') || ids.has(app.id) ||
          typeof app.root !== 'string' || !app.root || /[\\\x00]/.test(app.root) || app.root.startsWith('/') || app.root.split('/').includes('..'))
          throw Error('invalid system application or root');
        ids.add(app.id);
      }
      for (const app of apps.applications) checkApp(app);
      const parents = new Set(ids);
      if (apps.embeddedApplications !== undefined) {
        if (!Array.isArray(apps.embeddedApplications)) throw Error('invalid embedded applications');
        for (const entry of apps.embeddedApplications) {
          checkApp(entry?.app);
          if (!parents.has(entry.applicationId) || !Array.isArray(entry.inventory) ||
            entry.inventory.some(c=>c?.applicationId!==entry.app.id)) throw Error('invalid embedded application owner');
        }
      }
      if (apps.inventory.some(item => !parents.has(item?.applicationId))) throw Error('invalid system application component owner');
    }
    for (const dep of target.deps) {
      if (typeof dep?.coordKey !== 'string' || !dep.coordKey || componentIds.has(dep.coordKey) || dep.artifactTargetId !== target.id || typeof dep.ecosystem !== 'string' || typeof dep.name !== 'string') throw Error('invalid or duplicate artifact inventory component');
      componentIds.add(dep.coordKey);
    }
    for (const record of target.coverage) if (record.artifactTargetId && record.artifactTargetId !== target.id) throw Error('artifact inventory coverage target mismatch');
  }
  return content.targets;
}
function readSnapshot(file, options = {}) {
  if (fs.statSync(file).size > (options.maxSnapshotBytes ?? 128 * 1024 * 1024)) throw Error('artifact inventory exceeds configured size limit');
  return validateSnapshot(JSON.parse(fs.readFileSync(file, 'utf8'))).map(t => ({ ...require('./inventory-scope').applyComponentScope(t), evidence: 'cached-inventory', originalEvidence: t.originalEvidence || t.evidence }));
}
async function writeSnapshot(file, targets, {compact = false, validate = false} = {}) {
  const absolute = path.resolve(file);
  const snapshot = createSnapshot(targets);
  if (validate) validateSnapshot(snapshot);
  await fs.promises.mkdir(path.dirname(absolute), { recursive: true });
  const temp = absolute + '.' + crypto.randomUUID() + '.tmp';
  try { await fs.promises.writeFile(temp, JSON.stringify(snapshot, null, compact ? undefined : 2) + '\n', { mode: 0o600 }); await fs.promises.rename(temp, absolute); }
  finally { await fs.promises.rm(temp, { force: true }); }
}

async function acquireInventories(input, options = {}) {
  if(options.localDockerReference){
    const local=await require('../images/local-docker').openImage(input,options.dockerSocket);
    if(local){
      try{
        const targets=await acquireInventories(local.path,{...options,localDockerReference:null,source:input});
        for(const target of targets){target.metadata.localDocker=local.metadata;target.metadata.acquisition={...target.metadata.acquisition,reference:input,kind:'docker'};}
        return targets;
      }finally{await local.cleanup();}
    }
    // Never silently: a mistyped path, or a locally built image while the Docker Engine is
    // unreachable, would otherwise become a lookup of that name on a public registry.
    if(!options.offline){
      let where=input;try{const ref=require('../images/registry').parseReference(input);where=`${ref.registry}/${ref.repository}`;}catch{}
      options.onSourceWarning?.(`${input} is not a local path and was not found in the local Docker Engine; acquiring it from ${where}.`);
    }
    return acquireInventories(input,{...options,localDockerReference:null,registry:true});
  }
  if (options.inventory) return readSnapshot(input, options);
  if (options.sbom) return [sbomTarget(input, options)];
  const cache = options.registry ? require('../cache/repository').createCacheRepository(options.cacheDir) : null;
  const legacyCacheKey = sha(JSON.stringify([input, options.platform || null, !!options.preferSbom,...(options.system ? [true] : [])]));
  const ref = options.registry ? require('../images/registry').parseReference(input) : null;
  const cacheKey = ref ? sha(JSON.stringify([`${ref.registry}/${ref.repository}@${ref.reference}`, options.platform || null, !!options.preferSbom,...(options.system ? [true] : [])])) : legacyCacheKey;
  if (options.registry && options.offline) {
    const saved = cache.get('image-inventory', cacheKey) || cache.get('image-inventory', legacyCacheKey);
    if (!saved?.value || saved.value.schema !== SNAPSHOT_SCHEMA) throw Error('image inventory is not cached; import an inventory/archive or prepare this reference online');
    const targets = validateSnapshot(saved.value).map(require('./inventory-scope').applyComponentScope);
    return targets.map(target => ({ ...target, evidence: 'cached-inventory', originalEvidence: target.originalEvidence || target.evidence,
      warnings: [...target.warnings, { type: 'cached-image-resolution', severity:'info', capability: 'sources', message: 'Using the prepared image digest and inventory offline; the registry tag is not re-resolved in this mode.' }] }));
  }
  const persist = targets => {
    targets = targets.map(require('./inventory-scope').applyComponentScope);
    validateSnapshot(createSnapshot(targets));
    if (cache) cache.put('image-inventory', cacheKey, createSnapshot(targets));
    return targets;
  };
  if (cache && !options.imageRetire && !options.forceUpdate && !require('../cache/policy').shouldForceUpdate()) {
    let targets;
    try {
      const saved = cache.get('image-inventory', cacheKey) || cache.get('image-inventory', legacyCacheKey);
      if (saved?.value) targets = validateSnapshot(saved.value);
    } catch { /* Invalid snapshots must be rebuilt from verified content online. */ }
    const digest = targets?.[0]?.metadata?.acquisition?.indexDigest;
    // Publisher SBOMs can be updated independently of the image digest.
    const scoped = targets?.map(require('./inventory-scope').applyComponentScope);
    // Older APK inventories discarded the maintainer needed to identify vendor NGINX.
    const vendorMetadataComplete=scoped?.every(t=>(t.packages||[]).every(p=>p.manager!=='apk'||p.sourceName!=='nginx'||p.packageMetadata));
    if (digest && vendorMetadataComplete && scoped.every(t => t.evidence === 'content-inventory' && t.metadata?.componentScope === require('./component-scope').IMAGE_COMPONENT_SCOPE && !t.warnings.some(w => w.reason === require('./inventory-scope').SCOPE_REASON) && t.metadata?.acquisition?.indexDigest === digest)) {
      const current = ref.reference.includes(':') ? ref.reference : await require('../images/registry').fetchRegistryDigest(input,
        {...options, fetcher:options.registryFetcher || options.fetcher, limits:options.registryLimits});
      if (current === digest) return scoped.map(target => ({...target, evidence:'cached-inventory', originalEvidence:target.originalEvidence || target.evidence}));
    }
  }
  let registry = null, opened = null, sbomAttempt = null;
  try {
    if (options.registry) {
      if (options.preferSbom && !options.imageRetire) {
        try {
          const discovered = await require('../images/registry').fetchRegistrySboms(input, { ...options, fetcher: options.registryFetcher || options.fetcher, limits: options.registryLimits });
          // Never drop image platforms when only a subset has publisher metadata.
          const subjects = new Set(discovered.documents.map(d => d.expectedDigest));
          if (discovered.documents.length && subjects.size >= (discovered.metadata.platforms?.length || 1)) {
            const targets = discovered.documents.map(item => sbomTarget(item.document, { ...options, expectedDigest: item.expectedDigest,
              ...(item.source?.binding?.kind === 'oci-subject' ? { boundSubjectDigest: item.expectedDigest,
                boundSubjectEvidence: { type: 'oci-manifest-subject', manifestDigest: item.source.manifestDigest } } : {}),
              platform: item.platform, registryReference: input, source: `${input}@${item.expectedDigest}` }));
            // Prefer metadata only when every component can actually be assessed.
            // Signature verification remains explicitly outside this evidence.
            const unusable = targets.some(t => t.warnings.some(w => w.reason !== 'sbom-unverified'));
            if (!unusable) {
              for (const target of targets) { target.metadata.registryEvidence = discovered.metadata; target.metadata.acquisition.resolvedDigest = target.metadata.digest; target.metadata.acquisition.indexDigest = discovered.metadata.digest; }
              return persist(targets);
            }
            sbomAttempt = { status: 'fallback', reason: 'Publisher inventory lacks component identity, distribution, or source-package evidence.' };
          } else sbomAttempt = { status: 'fallback', reason: 'Publisher inventory is not available for every selected image platform.' };
        } catch (error) {
          sbomAttempt = { status: 'fallback', reason: 'Publisher inventory could not be validated; full image content was requested.' };
        }
      }
      registry = await require('../images/registry').fetchRegistryImage(input, { ...options, fetcher: options.registryFetcher || options.fetcher, limits: options.registryLimits });
    }
    const source=registry?.path || input;
    const disk=require('./disk');
    opened=options.system && !registry && fs.statSync(source).isFile() && disk.isDisk(source) ? await disk.openDisk(source,options)
      : await openArtifact(source, { ...options, limits: options.artifactLimits });
    const targets = [];
    for (const target of opened.targets) {
      if (options.platform) {
        const platform = target.metadata.platform;
        if (!platform || [platform.os, platform.architecture, platform.variant].filter(Boolean).join('/') !== options.platform && [platform.os, platform.architecture].join('/') !== options.platform) continue;
      }
      const collect=options.system?require('../cli-collect').collectSystemTarget:inventoryTarget;
      const inventory = await collect(target, { ...options, source: registry ? input : options.source });
      if (registry) { inventory.metadata.registryEvidence = registry.metadata; inventory.metadata.acquisition.resolvedDigest = inventory.metadata.digest || null; inventory.metadata.acquisition.indexDigest = registry.metadata.digest; }
      if (sbomAttempt) inventory.metadata.publisherInventory = sbomAttempt;
      targets.push(inventory);
    }
    if (!targets.length) throw Error('no artifact matches the requested platform');
    return persist(targets);
  } finally { if (opened) await opened.cleanup(); if (registry) await registry.cleanup(); }
}

async function assessInventories(targets, options = {}) {
  const { assessSystemInventory, syncSystemAdvisories } = require('../system-inventory');
    options.onArtifactProgress?.({stage:'Component identities'});
  targets=targets.map(target=>require('./inventory-scope').applyComponentScope(target,{checkPolicy:false}));
  // The RPM database lists each imported signing key as a "gpg-pubkey" entry (version = key
  // id). It is not software: no advisory can exist for it, and none is expected.
  for(const target of targets){
    const keys=target.packages.filter(p=>p.manager==='rpm' && p.name==='gpg-pubkey');
    if(!keys.length)continue;
    target.packages=target.packages.filter(p=>!keys.includes(p));
    target.metadata={...target.metadata,rpmSigningKeys:keys.map(p=>({id:p.version,release:p.release??null}))};
  }
  for(const target of targets){
    for(const pkg of target.packages){const origin=require('../system-inventory/distribution-sources').identifyPackageOrigin(pkg,options);if(origin)pkg.packageOrigin=origin;}
    for(const dep of target.deps){const origin=require('../system-inventory/distribution-sources').identifyPackageOrigin(dep,options);if(origin)dep.packageOrigin=origin;}
    const identity=await require('./go-main-identity').resolveGoMainIdentities(target,options);
    for(const dep of identity.deps){const qualified=qualify({...dep,imageRole:'direct',scope:'runtime'},target.id);if(!target.deps.some(d=>d.coordKey===qualified.coordKey))target.deps.push(qualified);}
    target.coverage.push({...identity.coverage,artifactTargetId:target.id,capability:'inventory'});
    target.warnings.push(...identity.warnings);
    // A Go binary built from a checkout names its main module "(devel)". Without verified
    // version evidence the application's own advisories cannot be assessed: say so.
    const identifiedBinaries=new Set(identity.deps.map(d=>d.binaryEvidence?.binaryPath));
    const unversioned=target.deps.filter(d=>d.ecosystem==='binary' && !identifiedBinaries.has(d.artifactPath||d.manifestPaths?.[0])).map(d=>{
      const main=(d.binaryMetadata?.go?.modules||[]).filter(m=>m.kind==='mod');
      return main.length===1 && main[0].version==='(devel)' && main[0].path ? `${main[0].path} (${d.artifactPath||d.manifestPaths?.[0]})` : null;
    }).filter(Boolean);
    if(unversioned.length)target.warnings.push({type:'dependency-coverage',severity:'info',capability:'advisories',reason:'go-main-module-unversioned',count:unversioned.length,
      items:unversioned.map(id=>({id})),message:`${unversioned.length} Go application module(s) carry no verifiable version: advisories for the application itself were not assessed; its embedded dependencies were.`});
  }
  const resolvedDeps = new Map(), cveMatches = [], warnings = [], artifacts = [], warmed = new Set();
  const nativeDeps=new Map();
  for(const target of targets)for(const dep of target.deps||[])if(dep.ecosystem!=='binary' && dep.ecosystem!=='image-product' && dep.installEvidence?.source!=='retire' && (!dep.osPackageOwners?.length || dep.binaryEvidence))nativeDeps.set(dep.coordKey,dep);
  let native={matches:[],unknown:[],coverage:{status:'not-applicable'}},nativePreparation={sources:[],coverage:[],warnings:[]};
  if(nativeDeps.size){
    const nativeOptions={...options};
    try{
    options.onArtifactProgress?.({stage:'Native advisory preparation'});
      nativePreparation=await require('../advisories/native-source-prepare').prepareNativeSources(nativeDeps,nativeOptions);
      if(nativePreparation.sources.length){
        const store=require('../advisories/store').openAdvisoryStore({cacheDir:options.cacheDir});
    options.onArtifactProgress?.({stage:'Native advisory matching'});
        try{native=require('../advisories/native').matchNativePackages(nativeDeps,store,{sources:nativePreparation.sources});}finally{store.close();}
      }
    }catch(error){nativePreparation.warnings.push(`Native advisory scan failed: ${error.message}`);native.coverage={status:'failed',reason:error.message};}
  }
  for (const original of targets) {
    const target = JSON.parse(JSON.stringify(original));
    let targetWarnings = normalizeWarnings(target.warnings);
    if (target.metadata.systemApplications && target.metadata.inspectLocalImages === false)
      targetWarnings = targetWarnings.filter(w=>w.reason!=='image-reference-parse-error');
    const reliability=require('../scan/reliability');
    const discoveryCoverage=reliability.createDiscoveryCoverage();
    const assessedPackages = new Set();
    let distributionState = options.osv===false ? 'disabled' : undefined;
    // The auditor evaluates lifecycle through system maintenance. An unsupported
    // lifecycle hook in an inventory plugin is not a second requested lookup.
    const coverage = target.metadata.systemApplications
      ? target.coverage.filter(c=>c.diagnostic!=='CMS_LIFECYCLE_NOT_QUALIFIED')
      : [...target.coverage];
    if (options.publisherAdvisories !== false && target.metadata.systemApplications?.applications.some(app => app.pluginId)) {
      const assessed = await require('../applications/plugins/runner').runApplicationPlugins(null, {
        savedInventory:target.metadata.systemApplications, scanContext:'installation', offline:!!options.offline, fetchImpl:options.fetcher,
        plugins:require('../applications/plugins').allApplicationPlugins(),
        advisoryCacheDir:path.join(options.cacheDir || require('../cache/directory').getCacheDir(),'advisory-snapshots'),
        wordfenceFeedPath:options.wordfenceFeed, drupalAdvisoriesPath:options.drupalAdvisories,
        prestashopAdvisoriesPath:options.prestashopAdvisories, typo3AdvisoriesPath:options.typo3Advisories,
        spipAdvisoriesPath:options.spipAdvisories,
      });
      for (const match of assessed.findings) {
        const dep = qualify({...match.dep,systemSection:'project',systemApplicationIds:match.applicationIds,coordKey:JSON.stringify([match.dep.coordKey,match.ownerComponentIds])},target.id);
        cveMatches.push({...match,dep});
      }
      coverage.push(...assessed.coverage.map(c=>({...c,collector:c.sourceId || 'system-applications',artifactTargetId:target.id})));
      targetWarnings.push(...require('../scan/coverage').applicationWarnings({
        diagnostics:assessed.diagnostics, inventory:target.metadata.systemApplications.inventory,
        coverage:coverage.filter(c=>c.applicationId),
      }));
    }
    options.onArtifactProgress?.({stage:'Distribution advisories'});
    const distroKey = JSON.stringify(target.distribution);
    const advisoryScope = target.packages.length && options.osv !== false ? require('../system-inventory').scope(target.distribution,options) : null;
    if (options.osv !== false && !options.offline && target.packages.length && !warmed.has(distroKey) && !require('../providers').hasHostedProxy()) {
      warmed.add(distroKey);
      try {
        const scope=require('../system-inventory').scope(target.distribution,options);
        const cached=scope && require('../cache/repository').createCacheRepository(options.cacheDir).getSnapshot('system-osv:'+scope.ecosystem);
        const age=Date.now()-(cached?.fetchedAt||0);
        if(options.refresh || !cached?.complete || cached.stale || age<0 || age>=require('../cache/policy').DEFAULT_TTL_MS)
          await syncSystemAdvisories(target.distribution, options);
      }
      catch (error) { targetWarnings.push({ type: 'source-unavailable', capability: 'sources', message: `System advisory refresh failed: ${error.message}` }); }
    }
    for (const dep of target.deps) resolvedDeps.set(dep.coordKey, dep);
    for(const source of nativePreparation.coverage){
      coverage.push(...coverageRecords([{...source,collector:`native-${source.source}`}],target.id,'sources'));
      if(source.issue && source.issue!=='refresh-failed')targetWarnings.push({type:'source-unavailable',severity:source.issue==='missing-source'?'info':undefined,capability:'sources',source:source.source,message:`${source.source}: ${source.reason}.`});
    }
    for(const warning of nativePreparation.warnings)targetWarnings.push(typeof warning==='string'?{type:'source-unavailable',capability:'sources',message:warning}:{capability:'sources',...warning});
    const nativeUnknown=native.unknown.filter(item=>!item.artifactTargetId||item.artifactTargetId===target.id);
    if(nativeUnknown.length){coverage.push({artifactTargetId:target.id,capability:'sources',collector:'native-comparisons',execution:'completed',result:'indeterminate',affectsCompleteness:false,affectsAssessment:true,count:nativeUnknown.length});targetWarnings.push({...require('../scan/diagnostics').advisoryEvidenceDiagnostic(nativeUnknown),capability:'sources'});}
    if (target.packages.length && options.osv === false) {
      coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'system-osv', execution: 'not-applicable', result: 'not-consulted', expected:false, reason: 'OSV is excluded by source configuration.' });
    } else if (target.packages.length) {
      const systemInventory = { distribution: target.distribution, packages: target.packages.filter(p=>!['third-party','ambiguous'].includes(p.packageOrigin?.status)) };
      const excluded=target.packages.length-systemInventory.packages.length;
      if(excluded){const reason='Distribution OSV ranges do not establish applicability for packages declaring another vendor.';coverage.push({artifactTargetId:target.id,capability:'advisories',collector:'system-osv-vendor-scope',execution:'partial',result:'indeterminate',count:excluded,reason});targetWarnings.push({type:'dependency-coverage',severity:'info',capability:'advisories',message:reason});}
      const hostedOnline = !options.offline && require('../providers').hasHostedProxy() && !advisoryScope?.accepts;
      let assessment;
      try {
        assessment = hostedOnline ? await require('../system-inventory').assessTargetedSystemInventory(systemInventory, options)
          : await assessSystemInventory(systemInventory, options);
        if (!hostedOnline && assessment.coverage.some(c => c.status !== 'complete')) {
          // Ask OSV for the exact installed versions when the bulk ranges cannot
          // establish them. Offline runs can replay those verified consultations.
          const targeted = advisoryScope?.accepts ? {assessedPackages:[],coverage:[]} : await require('../system-inventory').assessTargetedSystemInventory(systemInventory, options);
          if (targeted.assessedPackages?.length === systemInventory.packages.length ||
              (options.offline && assessment.coverage.some(c=>c.status==='missing') && targeted.coverage.some(c=>c.consulted>c.unknown)))
            assessment = targeted;
        }
      } catch(error) {
        assessment={matches:[],coverage:[{source:'system-osv',status:'incomplete',reason:error.message}],warnings:[`System OSV assessment failed: ${error.message}`]};
      }
      if(options.offline && assessment.coverage.some(c=>c.status==='missing'))distributionState='distribution-cache-missing';
      // A comparison that failed for one package says nothing about other packages.
      const verified = new Set(assessment.assessedPackages || []);
      const keyOf = p=>`${p.manager}:${p.name}@${p.version}`;
      const unchecked = new Set(systemInventory.packages.filter(p=>!verified.has(p)).map(keyOf));
      for(const pkg of verified)if(!unchecked.has(keyOf(pkg))){
        assessedPackages.add(keyOf(pkg));
        discoveryCoverage.consulted(systemDep(pkg,target.id,target.distribution),'osv');
      }
      coverage.push(...coverageRecords(assessment.coverage, target.id, 'advisories'));
      targetWarnings.push(...normalizeWarnings(assessment.warnings, 'advisories'));
      for (const match of assessment.matches) {
        const dep = systemDep(match.dep, target.id, target.distribution);
        const full = resolvedDeps.get(dep.coordKey) || dep;
        const cve = { ...match.cve, score: match.cve.score ?? match.cve.cvss ?? null,
          fixVersion: match.cve.fixVersion || match.fixVersion || null,
          osvRefs: match.cve.osvRefs || match.cve.references || [] };
        cveMatches.push({ ...match, dep: full, cve });
      }
    }
    options.onArtifactProgress?.({stage:'Distribution security trackers'});
    const distribution=await require('../system-inventory/distribution-sources').assessDistributionSources({distribution:target.distribution,packages:target.packages},{...options,
      onPackageConsulted:(pkg,source)=>discoveryCoverage.consulted(systemDep(pkg,target.id,target.distribution),source),confirmedMatches:[...cveMatches,...native.matches].filter(m=>m.dep?.artifactTargetId===target.id)});
    coverage.push(...coverageRecords(distribution.coverage,target.id,'advisories'));
    targetWarnings.push(...normalizeWarnings(distribution.warnings,'advisories'));
    // A known limit of the source, stated in the report rather than left to be guessed: errata
    // describe fixes. It does not apply when a source of unfixed vulnerabilities answered.
    const unfixedCovered = distribution.coverage.some(c => c.source === 'redhat-oval' && c.execution === 'completed');
    if (advisoryScope?.fixedOnly && !unfixedCovered) targetWarnings.push({type:'dependency-coverage',severity:'info',capability:'advisories',reason:'distribution-fixed-advisories-only',
      message:`${target.distribution.name || advisoryScope.base}: its packages are assessed against the distribution's published errata. A vulnerability the distribution has not fixed yet has no erratum and is not listed.`});
    for(const match of distribution.matches){const dep=systemDep(match.dep,target.id,target.distribution);cveMatches.push({...match,dep:resolvedDeps.get(dep.coordKey)||dep});}
    const imageJsAssessment=await require('./retire').assessImageJs(target,options);
    for(const item of imageJsAssessment.matches)cveMatches.push(item);
    coverage.push(imageJsAssessment.coverage);
    targetWarnings.push(...imageJsAssessment.warnings);
    options.onArtifactProgress?.({stage:'Application advisories'});
    const appDeps = new Map(target.deps.filter(d => d.registryIdentity !== 'cms-theme' && d.ecosystem !== 'system' && d.ecosystem !== 'binary' && d.ecosystem !== 'image-product' && d.installEvidence?.source !== 'retire' && (!d.osPackageOwners?.length || !!d.binaryEvidence)).map(d => [d.coordKey, d]));
    // Distribution headers/metadata identify the upstream release, but downstream
    // fixes can be backported. Keep these comparisons as evidence to investigate.
    const owned = new Map(target.metadata.systemApplications ? target.deps.filter(d =>
      d.osPackageOwners?.length && !d.binaryEvidence && d.provenance === 'installed' &&
      ['ruby','pypi','npm','composer'].includes(d.ecosystem) && d.installEvidence && d.version
    ).map(d => [d.coordKey,d]) : []);
    const osvDeps = new Map([...appDeps, ...owned]);
    if (osvDeps.size && options.osv === false) {
      coverage.push({ artifactTargetId: target.id, capability:'advisories',collector:'osv-application',execution:'not-applicable',result:'not-consulted',expected:false,reason:'OSV is excluded by source configuration.' });
    } else if (osvDeps.size) {
      const appWarnings = [];
      try {
        const matches = await require('../providers/osv/query').queryOsvForDeps(osvDeps, { ...options, allowStaleFallback: true, onConsulted:discoveryCoverage.consulted,
          onWarning: warning => appWarnings.push(typeof warning === 'string' ? { type: 'osv-coverage', message: warning } : warning) });
        const upstream = matches.filter(m=>owned.has(m.dep.coordKey));
        const findings = matches.filter(m=>!owned.has(m.dep.coordKey));
        for(const item of require('./applications').upstreamPackageObservations(
          upstream, [...cveMatches,...native.matches].filter(m=>m.dep?.artifactTargetId===target.id), distribution.observations
        ))distribution.observations.push(item);
        for(const item of findings)cveMatches.push(item);
        const incomplete=appWarnings.some(w=>!require('../scan/diagnostics').isInformational(w));
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'osv-application',
          execution: incomplete ? 'partial' : 'completed', result: findings.length ? 'affected' : incomplete || upstream.length ? 'indeterminate' : 'no-match', count: osvDeps.size });
      } catch (error) {
        appWarnings.push({ type: 'source-unavailable', message: `Application advisory scan failed: ${error.message}` });
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'osv-application', execution: 'failed', result: 'indeterminate' });
      }
      targetWarnings.push(...normalizeWarnings(appWarnings, 'advisories'));
    }
    // Gems installed by an application, not by the distribution: the Ruby advisory database
    // records advisories OSV does not carry for RubyGems (lib/providers/rubysec).
    const gems = new Map([...appDeps].filter(([, dep]) => dep.ecosystem === 'ruby'));
    if (gems.size && options.rubyAdvisories !== false) {
      try {
        const found = await require('../providers/rubysec/advisories').queryRubyAdvisories(gems, { cacheDir: options.cacheDir, offline: options.offline,
          fetcher: options.fetcher, forceUpdate: options.forceUpdate, onConsulted: discoveryCoverage.consulted, onWarning: warning => targetWarnings.push({ ...warning, capability: 'advisories' }) });
        for (const item of found) cveMatches.push(item);
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'rubysec', execution: 'completed', result: found.length ? 'affected' : 'no-match', count: gems.size });
      } catch (error) {
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'rubysec', execution: 'failed', result: 'indeterminate', reason: error.message });
        targetWarnings.push({ type: 'source-unavailable', capability: 'advisories', source: 'rubysec', message: `Ruby advisory database: ${error.message}` });
      }
    }
    options.onArtifactProgress?.({stage:'Publisher advisories'});
    const publisher=await require('./publisher-advisories').assessPublisherAdvisories(appDeps,{...options,onPackageConsulted:discoveryCoverage.consulted});
    for(const item of publisher.matches)cveMatches.push(item);
    coverage.push(...coverageRecords(publisher.coverage,target.id,'advisories'));
    targetWarnings.push(...normalizeWarnings(publisher.warnings,'advisories'));
    const products=await require('./product-advisories').assessProductAdvisories(target,options);
    for(const match of products.matches)if(!resolvedDeps.has(match.dep.coordKey))resolvedDeps.set(match.dep.coordKey,match.dep);
    for(const item of products.matches)cveMatches.push(item);
    const conditions = products.coverage.flatMap(check => (check.undecidableIds || []).map(id => ({
      id, package: check.product, version: check.version, reason: check.reason
    })));
    if (conditions.length) targetWarnings.push({
      ...require('../scan/diagnostics').advisoryEvidenceDiagnostic(conditions), capability: 'advisories'
    });
    coverage.push(...coverageRecords(products.coverage,target.id,'advisories'));
    const productInventory=require('./image-products').productCoverage(target,products.coverage,assessedPackages,[...cveMatches,...native.matches],distributionState);
    const identifiedBinaryPaths=new Set(target.deps.filter(d=>(d.ecosystem==='binary' && d.binaryEvidence?.product && d.version) || d.binaryEvidence?.source==='go-vcs-and-module-proxy').map(d=>d.binaryEvidence.binaryPath));
    const unknownBinaries = target.deps.filter(d => d.ecosystem === 'binary' && !d.osPackageOwners?.length && !identifiedBinaryPaths.has(d.artifactPath));
    if (unknownBinaries.length) {
      coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'native-binaries', execution: 'not-applicable', result: 'indeterminate', affectsCompleteness:false, count: unknownBinaries.length, reason: 'These files expose no supported package/version identity for advisory queries.' });
      targetWarnings.push({ type: 'dependency-coverage', severity:'info', capability: 'advisories', message: `${unknownBinaries.length} native binaries have no authenticated package/version identity.` });
    }
    const archiveContext=require('./applications').classifyOwnedArchiveWarnings(targetWarnings,target.packages,assessedPackages);
    if(archiveContext.informational.length){
      targetWarnings=archiveContext.warnings;
      // Reclassify the collector only when none of its original inventory
      // diagnostics remain; never hide malformed archives or unresolved files.
      if(!targetWarnings.some(w=>w.capability==='inventory' && !require('../scan/diagnostics').isInformational(w)))
        for(const check of coverage)if(check.collector==='installed-applications' && check.execution==='partial')check.execution='completed';
      targetWarnings.push(...archiveContext.informational.map(({warning,owner,path})=>({...warning,severity:'info',type:'os-owned-component',owner,
        message:`${path} is covered by its installed OS package ${owner.name}@${owner.version}; no independent Maven identity is declared.`})));
    }
    for (const check of coverage) {
      if (check.affectsCompleteness === false || ['completed', 'not-applicable'].includes(check.execution)) continue;
      if (check.collector==='native-binaries' || check.collector==='native-comparisons' || check.collector==='go-main-identity' || check.collector==='system-osv-vendor-scope' || check.issue==='missing-source') continue;
      if (targetWarnings.some(w => w.capability === check.capability && !require('../scan/diagnostics').isInformational(w))) continue;
      targetWarnings.push({ type: check.capability === 'inventory' ? 'dependency-coverage' : 'source-unavailable',
        capability: check.capability, message: `${check.collector || check.source || check.capability}: ${check.reason || check.execution}; coverage is incomplete.` });
    }
    const requiredDeps = new Map(osvDeps);
    for (const pkg of target.packages) {
      const dep=systemDep(pkg,target.id,target.distribution);
      requiredDeps.set(dep.coordKey,dep);
    }
    // Products identified by CPE are checked by the product/version adapter.
    // An excluded adapter is a real gap for a product it could check.
    for (const check of products.coverage) {
      if (check.collector === 'nvd-image-product' && check.execution === 'not-applicable') {
        targetWarnings.push(reliability.coverageWarning(`No applicability check for ${check.product}@${check.version}: ${check.reason}`));
      }
    }
    if(requiredDeps.size) {
      const store=require('../advisories/store').openAdvisoryStore({cacheDir:options.cacheDir});
      try {
        const checkedSources=nativePreparation.coverage.filter(c=>!c.issue && native.coverage?.status!=='failed').map(c=>c.source);
        const gap=discoveryCoverage.assess(requiredDeps,{store,options,nativeSources:checkedSources,reviewed:options.osv!==false});
        if(gap)targetWarnings.push(gap);
      } finally {store.close();}
    }
    for(const check of coverage.filter(reliability.incompleteCheck)){
      targetWarnings.push(reliability.coverageWarning(`${check.collector || check.sourceId}: ${check.reason || check.execution} (${check.capability}).`));
    }
    for(const warning of targetWarnings) {
      if(warning.severity!=='info' && warning.affectsCompleteness!==false && (warning.capability==='advisories' ||
         warning.code==='source-request-failed' || (warning.source && nativePreparation.sources.includes(warning.source))))warning.reliabilityFailure=true;
    }
    warnings.push(...targetWarnings.map(w => ({ artifactTargetId: target.id, ...w })));
    artifacts.push({ id: target.id, kind: target.kind, metadata: target.metadata, evidence: target.evidence,
      originalEvidence: target.originalEvidence, distribution: target.distribution, inventoryAt: target.inventoryAt,
      componentCount: target.deps.length, coverage, productInventory, advisoryObservations:distribution.observations, components: target.deps.map(d => ({ ...(d.systemSection ? {systemSection:d.systemSection,systemApplicationIds:d.systemApplicationIds || []} : {}), ecosystem: d.ecosystem, packageType: d.packageType,
        namespace: d.namespace, name: d.name, version: d.version, sourceName:d.sourceName || null, sourceVersion:d.sourceVersion || null, packageOrigin:d.packageOrigin || null, architecture: d.architecture, artifactPath: d.artifactPath,
        imageProduct:require('./image-products').describe(d), provenance: d.provenance, imageRole:d.imageRole || null, imageSource:d.imageSource || imageComponentSource(d), installEvidence:d.installEvidence, manager:d.manager, coordKey: d.coordKey, binaryEvidence:d.binaryEvidence, osPackageOwners: d.osPackageOwners || [],
        purl: require('../inventory/purl').purlFor(d) })) });
  }
  const combined=require('../findings/merge').foldAnnouncements(require('../findings/merge').mergeBySource(cveMatches,native.matches));
  const applicabilityStore=require('../advisories/store').openAdvisoryStore({cacheDir:options.cacheDir});
  try{
    const checked=require('../system-inventory/package-applicability').reconcileSystemFindings(combined,applicabilityStore);
    cveMatches.splice(0,cveMatches.length,...checked.matches);
    for(const artifact of artifacts)for(const item of checked.observations.filter(o=>o.dep.artifactTargetId===artifact.id))artifact.advisoryObservations.push(item);
  }finally{applicabilityStore.close();}
  for (const artifact of artifacts) {
    options.onArtifactProgress?.({stage:'Image updates'});
    try { artifact.imageUpdate=await require('../images/update').resolveImageUpdate(artifact.metadata,options); }
    catch (error) { artifact.imageUpdate={status:'unknown',reference:artifact.metadata?.acquisition?.reference||null,reason:`Image update lookup unavailable: ${error.message}`,verifiedFix:false}; }
    const matches = cveMatches.filter(m => m.dep?.artifactTargetId === artifact.id);
    options.onArtifactProgress?.({stage:'CVE enrichment'});
    const visibleComponents = require('./report-inventory').reportedComponents(artifact,matches);
    await require('./release-versions').attachReleaseVersions(artifact,visibleComponents,options);
    const enrichment = await require('./enrichment').enrichArtifactFindings(matches, options);
    const recordSources = new Set(['nvd', 'euvd', 'euvd-details']);
    artifact.coverage.push(...enrichment.coverage.map(c => ({ ...c, artifactTargetId: artifact.id,
      ...(recordSources.has(c.collector) ? { affectsCompleteness:false,
        diagnostics:enrichment.warnings.filter(w => w.source === c.collector) } : {}) })));
    warnings.push(...enrichment.warnings.filter(w => !recordSources.has(w.source)).map(w => ({ ...w, artifactTargetId: artifact.id })));
  }
  await require('../findings/cve-descriptions').completeCveDescriptions(cveMatches,options);
  const recordSummary = require('../findings/cve-record-coverage').summarizeCveRecords(cveMatches,
    { ...options, coverage: artifacts.flatMap(a => a.coverage) });
  if (recordSummary.warning) warnings.push(recordSummary.warning);
  require('../findings/priority').attachPriority(cveMatches);
  const diagnostics=require('../scan/diagnostics').partitionDiagnostics(warnings);
  const systemTargets = artifacts.filter(a => a.metadata.systemApplications);
  const applicationRelations = systemTargets.flatMap(a=>a.metadata.systemApplications.relations || []);
  const relationsByDep = new Map();
  for (const relation of applicationRelations) {
    if (!relationsByDep.has(relation.depCoordKey)) relationsByDep.set(relation.depCoordKey,[]);
    relationsByDep.get(relation.depCoordKey).push(relation);
  }
  for (const match of cveMatches) {
    const dep = match.dep;
    const relations = relationsByDep.get(dep?.coordKey);
    if (relations?.length) {
      const occurrence = {version:dep.version,manifestPath:dep.artifactPath,scope:dep.scope,isDev:dep.isDev};
      const [attributed] = require('../applications/inventory').expandComposerFindings(
        [{...match,dep:{...dep,occurrences:[occurrence]}}],'.',relations);
      Object.assign(match,attributed);
    }
    if (dep?.systemApplicationIds?.length) {
      if (!match.applicationIds?.length) match.applicationIds = dep.systemApplicationIds;
      if (!match.applicationRelation) match.applicationRelation = require('../applications/layout').managerRelation(dep);
    }
  }
  for (const target of systemTargets) {
    const {applications,inventory} = target.metadata.systemApplications;
    require('../applications/layout').attributeLayoutFindings(cveMatches.filter(m=>m.dep?.artifactTargetId===target.id),applications,inventory);
  }
  const systemApplications = systemTargets.length ? {
    applicationRelations,
    applications:systemTargets.flatMap(a=>a.metadata.systemApplications.applications.map(app=>({...app,artifactTargetId:a.id}))),
    coverage:systemTargets.flatMap(a=>a.coverage.filter(check=>check.applicationId)),
    applicationInventory:systemTargets.flatMap(a=>a.metadata.systemApplications.inventory.map(c=>({...c,artifactTargetId:a.id}))),
  } : {};
  return { resolvedDeps, cveMatches: require('../findings/summary').uniqueFindings(cveMatches), ...systemApplications, ...diagnostics, artifacts };
}

function incompleteCapabilities(result, required = ['inventory', 'advisories', 'sources']) {
  const gaps = [];
  for (const target of result.artifacts) {
    for (const capability of required) {
      if (capability === 'sources') {
        if (result.warnings.some(w => w.affectsCompleteness !== false && w.artifactTargetId === target.id && (/source|osv/.test(w.type) || w.reliabilityFailure))) gaps.push({ target: target.id, capability });
      } else {
        const records = target.coverage.filter(c => c.capability === capability);
        if (!records.length || records.some(c => c.affectsCompleteness !== false && !['completed', 'not-applicable'].includes(c.execution))) gaps.push({ target: target.id, capability });
      }
    }
  }
  return gaps;
}

module.exports = { acquireInventories, assessInventories, inventoryTarget, sbomTarget, readSnapshot, writeSnapshot,
  createSnapshot, validateSnapshot, incompleteCapabilities, coverageRecords, systemDep, SNAPSHOT_SCHEMA };
