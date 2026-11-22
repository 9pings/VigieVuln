'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { makeDepRecord } = require('../dep-record');
const {IMAGE_COMPONENT_SCOPE,imageComponentRole,imageComponentSource} = require('./component-scope');
const { openArtifact } = require('./index');
const { collectInstalledApplications } = require('./applications');
const { collectSystemInventory, assessSystemInventory, syncSystemAdvisories } = require('../system-inventory');

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
      result: value.result || (execution === 'not-applicable' ? 'not-applicable' : 'indeterminate') };
  });
}
function portable(value, root, replacement = '') {
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
    ? `rootfs-inventory:sha256:${sha(JSON.stringify({ distribution: system.distribution, packages, deps: appDeps }))}` : target.id;
  const owners = new Map();
  const pathKey = value => path.posix.normalize('/' + String(value || '').replace(/\\/g, '/').replace(/^\/+/, ''));
  for (const pkg of packages) for (const ownedPath of pkg.ownedPaths || []) {
    const keys = new Set([pathKey(ownedPath)]);
    // Resolve directory aliases such as merged-/usr, never follow the file's own
    // symlink: ownership of a link does not confer ownership of its destination.
    try {
      const root = fs.realpathSync(target.root), parent = fs.realpathSync(path.dirname(path.join(root, ownedPath.replace(/^\/+/, ''))));
      if (parent === root || parent.startsWith(root + path.sep)) keys.add(pathKey(path.relative(root, path.join(parent, path.basename(ownedPath)))));
    } catch { /* Removed/unavailable owned paths do not create invented evidence. */ }
    for (const key of keys) {
      const list = owners.get(key) || [];
      list.push({ name: pkg.name, version: pkg.version, manager: pkg.manager, evidencePath: pkg.manifestPath });
      owners.set(key, list);
    }
  }
  const deps = [...packages.map(p => systemDep(p, id, system.distribution)), ...appDeps.map(d => {
    const evidence = d.binaryEvidence?.binaryPath || d.installEvidence?.path || d.manifestPaths?.[0];
    // A shared aggregate manifest does not prove that every package it names is OS-owned.
    const aggregate = ['composer', 'composer-php', 'nuget'].includes(d.installEvidence?.source);
    const owned = evidence && !aggregate ? owners.get(pathKey(evidence)) : null;
    return qualify(owned?.length ? { ...d, osPackageOwners: owned } : d, id);
  })];
  require('./image-products').applyProductVersions(deps);
  for(const dep of deps){dep.imageRole=imageComponentRole(dep);dep.imageSource=imageComponentSource(dep);dep.scope=dep.imageRole==='transitive'?'transitive':'runtime';}
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
    execution: applications.warnings.length ? 'partial' : 'completed', result: 'indeterminate', count: applications.deps.size });
  coverage.push({ artifactTargetId: id, capability: 'inventory', collector: 'native-binaries',
    execution: binaries.warnings.length ? 'partial' : 'completed', result: 'indeterminate', count: [...binaries.deps.values()].filter(d => d.ecosystem === 'binary').length });
  if (target.metadata.warnings?.length) coverage.push({ artifactTargetId: id, capability: 'inventory', collector: 'artifact-reader', execution: 'partial', result: 'indeterminate' });
  const source = options.source || path.basename(target.metadata.source || target.root);
  const acquisition = options.registry ? { kind: 'registry', reference: source } : {
    kind: target.metadata.format === 'directory' ? 'rootfs-directory' : target.metadata.format === 'oci-layout' && target.metadata.source && fs.statSync(target.metadata.source).isDirectory() ? 'oci-layout' : 'archive', source,
  };
  return { id, kind: target.kind, metadata: { ...target.metadata, componentScope:IMAGE_COMPONENT_SCOPE, source, acquisition, definitions: [], definitionDiscovery: {status:'not-supplied'} },
    evidence: 'content-inventory', inventoryAt: new Date().toISOString(), distribution: system.distribution,
    packages, deps, coverage, warnings, componentCount: deps.length };
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
async function writeSnapshot(file, targets) {
  const absolute = path.resolve(file);
  await fs.promises.mkdir(path.dirname(absolute), { recursive: true });
  const temp = absolute + '.' + crypto.randomUUID() + '.tmp';
  try { await fs.promises.writeFile(temp, JSON.stringify(createSnapshot(targets), null, 2) + '\n', { mode: 0o600 }); await fs.promises.rename(temp, absolute); }
  finally { await fs.promises.rm(temp, { force: true }); }
}

async function acquireInventories(input, options = {}) {
  if (options.inventory) return readSnapshot(input, options);
  if (options.sbom) return [sbomTarget(input, options)];
  const cache = options.registry ? require('../cache-repository').createCacheRepository(options.cacheDir) : null;
  const legacyCacheKey = sha(JSON.stringify([input, options.platform || null, !!options.preferSbom]));
  const ref = options.registry ? require('../image-registry').parseReference(input) : null;
  const cacheKey = ref ? sha(JSON.stringify([`${ref.registry}/${ref.repository}@${ref.reference}`, options.platform || null, !!options.preferSbom])) : legacyCacheKey;
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
  if (cache && !options.imageRetire && !options.forceUpdate && !require('../cache-policy').shouldForceUpdate()) {
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
      const current = ref.reference.includes(':') ? ref.reference : await require('../image-registry').fetchRegistryDigest(input,
        {...options, fetcher:options.registryFetcher || options.fetcher, limits:options.registryLimits});
      if (current === digest) return scoped.map(target => ({...target, evidence:'cached-inventory', originalEvidence:target.originalEvidence || target.evidence}));
    }
  }
  let registry = null, opened = null, sbomAttempt = null;
  try {
    if (options.registry) {
      if (options.preferSbom && !options.imageRetire) {
        try {
          const discovered = await require('../image-registry').fetchRegistrySboms(input, { ...options, fetcher: options.registryFetcher || options.fetcher, limits: options.registryLimits });
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
      registry = await require('../image-registry').fetchRegistryImage(input, { ...options, fetcher: options.registryFetcher || options.fetcher, limits: options.registryLimits });
    }
    opened = await openArtifact(registry?.path || input, { ...options, limits: options.artifactLimits });
    const targets = [];
    for (const target of opened.targets) {
      if (options.platform) {
        const platform = target.metadata.platform;
        if (!platform || [platform.os, platform.architecture, platform.variant].filter(Boolean).join('/') !== options.platform && [platform.os, platform.architecture].join('/') !== options.platform) continue;
      }
      const inventory = await inventoryTarget(target, { ...options, source: registry ? input : undefined });
      if (registry) { inventory.metadata.registryEvidence = registry.metadata; inventory.metadata.acquisition.resolvedDigest = inventory.metadata.digest || null; inventory.metadata.acquisition.indexDigest = registry.metadata.digest; }
      if (sbomAttempt) inventory.metadata.publisherInventory = sbomAttempt;
      targets.push(inventory);
    }
    if (!targets.length) throw Error('no artifact matches the requested platform');
    return persist(targets);
  } finally { if (opened) await opened.cleanup(); if (registry) await registry.cleanup(); }
}

async function assessInventories(targets, options = {}) {
    options.onArtifactProgress?.({stage:'Component identities'});
  targets=targets.map(target=>require('./inventory-scope').applyComponentScope(target,{checkPolicy:false}));
  for(const target of targets){
    for(const pkg of target.packages){const origin=require('../system-inventory/distribution-sources').identifyPackageOrigin(pkg,options);if(origin)pkg.packageOrigin=origin;}
    for(const dep of target.deps){const origin=require('../system-inventory/distribution-sources').identifyPackageOrigin(dep,options);if(origin)dep.packageOrigin=origin;}
    const identity=await require('./go-main-identity').resolveGoMainIdentities(target,options);
    for(const dep of identity.deps){const qualified=qualify({...dep,imageRole:'direct',scope:'runtime'},target.id);if(!target.deps.some(d=>d.coordKey===qualified.coordKey))target.deps.push(qualified);}
    target.coverage.push({...identity.coverage,artifactTargetId:target.id,capability:'inventory'});
    target.warnings.push(...identity.warnings);
  }
  const resolvedDeps = new Map(), cveMatches = [], warnings = [], artifacts = [], warmed = new Set();
  const nativeDeps=new Map();
  for(const target of targets)for(const dep of target.deps||[])if(dep.ecosystem!=='binary' && dep.ecosystem!=='image-product' && dep.installEvidence?.source!=='retire' && (!dep.osPackageOwners?.length || dep.binaryEvidence))nativeDeps.set(dep.coordKey,dep);
  let native={matches:[],unknown:[],coverage:{status:'not-applicable'}},nativePreparation={sources:[],coverage:[],warnings:[]};
  if(nativeDeps.size){
    const nativeOptions={...options};
    try{
    options.onArtifactProgress?.({stage:'Native advisory preparation'});
      nativePreparation=await require('../native-source-prepare').prepareNativeSources(nativeDeps,nativeOptions);
      if(nativePreparation.sources.length){
        const store=require('../advisory-store').openAdvisoryStore({cacheDir:options.cacheDir});
    options.onArtifactProgress?.({stage:'Native advisory matching'});
        try{native=require('../native-advisories').matchNativePackages(nativeDeps,store,{sources:nativePreparation.sources});}finally{store.close();}
      }
    }catch(error){nativePreparation.warnings.push(`Native advisory scan failed: ${error.message}`);native.coverage={status:'incomplete',reason:error.message};}
  }
  for (const original of targets) {
    const target = JSON.parse(JSON.stringify(original));
    let targetWarnings = normalizeWarnings(target.warnings);
    const assessedPackages = new Set();
    const coverage = [...target.coverage];
    options.onArtifactProgress?.({stage:'Distribution advisories'});
    const distroKey = JSON.stringify(target.distribution);
    if (options.osv !== false && !options.offline && target.packages.length && !warmed.has(distroKey) && !require('../providers').hasHostedProxy()) {
      warmed.add(distroKey);
      try {
        const scope=require('../system-inventory').scope(target.distribution,options);
        const cached=scope && require('../cache-repository').createCacheRepository(options.cacheDir).getSnapshot('system-osv:'+scope.ecosystem);
        const age=Date.now()-(cached?.fetchedAt||0);
        if(options.refresh || !cached?.complete || cached.stale || age<0 || age>=require('../cache-policy').DEFAULT_TTL_MS)
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
    if(nativeUnknown.length){coverage.push({artifactTargetId:target.id,capability:'sources',collector:'native-comparisons',execution:'completed',result:'indeterminate',affectsCompleteness:false,affectsAssessment:true,count:nativeUnknown.length});targetWarnings.push({...require('../diagnostics').advisoryEvidenceDiagnostic(nativeUnknown),capability:'sources'});}
    if (target.packages.length && options.osv === false) {
      coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'system-osv', execution: 'not-applicable', result: 'not-consulted', expected:false, reason: 'OSV is excluded by source configuration.' });
    } else if (target.packages.length) {
      const systemInventory = { distribution: target.distribution, packages: target.packages.filter(p=>!['third-party','ambiguous'].includes(p.packageOrigin?.status)) };
      const excluded=target.packages.length-systemInventory.packages.length;
      if(excluded){const reason='Distribution OSV ranges do not establish applicability for packages declaring another vendor.';coverage.push({artifactTargetId:target.id,capability:'advisories',collector:'system-osv-vendor-scope',execution:'partial',result:'indeterminate',count:excluded,reason});targetWarnings.push({type:'dependency-coverage',severity:'info',capability:'advisories',message:reason});}
      const hostedOnline = !options.offline && require('../providers').hasHostedProxy();
      let assessment;
      try {
        assessment = hostedOnline ? await require('../system-inventory').assessTargetedSystemInventory(systemInventory, options)
          : await assessSystemInventory(systemInventory, options);
        if (options.offline && assessment.coverage.some(c => c.status === 'missing')) {
          const targeted = await require('../system-inventory').assessTargetedSystemInventory(systemInventory, options);
          if (targeted.coverage.some(c => c.consulted > c.unknown)) assessment = targeted;
        }
      } catch(error) {
        assessment={matches:[],coverage:[{source:'system-osv',status:'incomplete',reason:error.message}],warnings:[`System OSV assessment failed: ${error.message}`]};
      }
      if (assessment.coverage.length && assessment.coverage.every(c=>c.status==='complete')) for(const pkg of systemInventory.packages) assessedPackages.add(`${pkg.manager}:${pkg.name}@${pkg.version}`);
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
    const distribution=await require('../system-inventory/distribution-sources').assessDistributionSources({distribution:target.distribution,packages:target.packages},{...options,confirmedMatches:[...cveMatches,...native.matches].filter(m=>m.dep?.artifactTargetId===target.id)});
    coverage.push(...coverageRecords(distribution.coverage,target.id,'advisories'));
    targetWarnings.push(...normalizeWarnings(distribution.warnings,'advisories'));
    for(const match of distribution.matches){const dep=systemDep(match.dep,target.id,target.distribution);cveMatches.push({...match,dep:resolvedDeps.get(dep.coordKey)||dep});}
    const imageJsAssessment=await require('./retire').assessImageJs(target,options);
    cveMatches.push(...imageJsAssessment.matches);
    coverage.push(imageJsAssessment.coverage);
    targetWarnings.push(...imageJsAssessment.warnings);
    options.onArtifactProgress?.({stage:'Application advisories'});
    const appDeps = new Map(target.deps.filter(d => d.ecosystem !== 'system' && d.ecosystem !== 'binary' && d.ecosystem !== 'image-product' && d.installEvidence?.source !== 'retire' && (!d.osPackageOwners?.length || !!d.binaryEvidence)).map(d => [d.coordKey, d]));
    if (appDeps.size && options.osv === false) {
      coverage.push({ artifactTargetId: target.id, capability:'advisories',collector:'osv-application',execution:'not-applicable',result:'not-consulted',expected:false,reason:'OSV is excluded by source configuration.' });
    } else if (appDeps.size) {
      const appWarnings = [];
      try {
        const matches = await require('../osv').queryOsvForDeps(appDeps, { ...options, allowStaleFallback: true,
          onWarning: warning => appWarnings.push(typeof warning === 'string' ? { type: 'osv-coverage', message: warning } : warning) });
        cveMatches.push(...matches);
        const incomplete=appWarnings.some(w=>!require('../diagnostics').isInformational(w));
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'osv-application',
          execution: incomplete ? 'partial' : 'completed', result: matches.length ? 'affected' : incomplete ? 'indeterminate' : 'no-match', count: appDeps.size });
      } catch (error) {
        appWarnings.push({ type: 'source-unavailable', message: `Application advisory scan failed: ${error.message}` });
        coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'osv-application', execution: 'failed', result: 'indeterminate' });
      }
      targetWarnings.push(...normalizeWarnings(appWarnings, 'advisories'));
    }
    options.onArtifactProgress?.({stage:'Publisher advisories'});
    const publisher=await require('./publisher-advisories').assessPublisherAdvisories(appDeps,options);
    cveMatches.push(...publisher.matches);
    coverage.push(...coverageRecords(publisher.coverage,target.id,'advisories'));
    targetWarnings.push(...normalizeWarnings(publisher.warnings,'advisories'));
    const products=await require('./product-advisories').assessProductAdvisories(target,options);
    cveMatches.push(...products.matches);
    coverage.push(...coverageRecords(products.coverage,target.id,'advisories'));
    const productInventory=require('./image-products').productCoverage(target,products.coverage,assessedPackages,[...cveMatches,...native.matches]);
    const identifiedBinaryPaths=new Set(target.deps.filter(d=>(d.ecosystem==='binary' && d.binaryEvidence?.product && d.version) || d.binaryEvidence?.source==='go-vcs-and-module-proxy').map(d=>d.binaryEvidence.binaryPath));
    const unknownBinaries = target.deps.filter(d => d.ecosystem === 'binary' && !d.osPackageOwners?.length && !identifiedBinaryPaths.has(d.artifactPath));
    if (unknownBinaries.length) {
      coverage.push({ artifactTargetId: target.id, capability: 'advisories', collector: 'native-binaries', execution: 'partial', result: 'indeterminate', count: unknownBinaries.length, reason: 'Native binary identities cannot all be established from embedded metadata.' });
      targetWarnings.push({ type: 'dependency-coverage', severity:'info', capability: 'advisories', message: `${unknownBinaries.length} native binaries have no authenticated package/version identity.` });
    }
    const archiveContext=require('./applications').classifyOwnedArchiveWarnings(targetWarnings,target.packages,assessedPackages);
    if(archiveContext.informational.length){
      targetWarnings=archiveContext.warnings;
      // Reclassify the collector only when none of its original inventory
      // diagnostics remain; never hide malformed archives or unresolved files.
      if(!targetWarnings.some(w=>w.capability==='inventory' && !require('../diagnostics').isInformational(w)))
        for(const check of coverage)if(check.collector==='installed-applications' && check.execution==='partial')check.execution='completed';
      targetWarnings.push(...archiveContext.informational.map(({warning,owner,path})=>({...warning,severity:'info',type:'os-owned-component',owner,
        message:`${path} is covered by its installed OS package ${owner.name}@${owner.version}; no independent Maven identity is declared.`})));
    }
    for (const check of coverage) {
      if (check.affectsCompleteness === false || ['completed', 'not-applicable'].includes(check.execution)) continue;
      if (check.collector==='native-binaries' || check.collector==='native-comparisons' || check.collector==='go-main-identity' || check.collector==='system-osv-vendor-scope' || check.issue==='missing-source') continue;
      if (targetWarnings.some(w => w.capability === check.capability && !require('../diagnostics').isInformational(w))) continue;
      targetWarnings.push({ type: check.capability === 'inventory' ? 'dependency-coverage' : 'source-unavailable',
        capability: check.capability, message: `${check.collector || check.source || check.capability}: ${check.reason || check.execution}; coverage is incomplete.` });
    }
    warnings.push(...targetWarnings.map(w => ({ artifactTargetId: target.id, ...w })));
    artifacts.push({ id: target.id, kind: target.kind, metadata: target.metadata, evidence: target.evidence,
      originalEvidence: target.originalEvidence, distribution: target.distribution, inventoryAt: target.inventoryAt,
      componentCount: target.deps.length, coverage, productInventory, advisoryObservations:distribution.observations, components: target.deps.map(d => ({ ecosystem: d.ecosystem, packageType: d.packageType,
        namespace: d.namespace, name: d.name, version: d.version, sourceName:d.sourceName || null, sourceVersion:d.sourceVersion || null, packageOrigin:d.packageOrigin || null, architecture: d.architecture, artifactPath: d.artifactPath,
        imageProduct:require('./image-products').describe(d), provenance: d.provenance, imageRole:d.imageRole || null, imageSource:d.imageSource || imageComponentSource(d), installEvidence:d.installEvidence, manager:d.manager, coordKey: d.coordKey, binaryEvidence:d.binaryEvidence, osPackageOwners: d.osPackageOwners || [],
        purl: require('../purl').purlFor(d) })) });
  }
  const combined=require('../merge-sources').mergeBySource(cveMatches,native.matches);
  cveMatches.splice(0,cveMatches.length,...combined);
  for (const artifact of artifacts) {
    options.onArtifactProgress?.({stage:'Image updates'});
    try { artifact.imageUpdate=await require('../image-update').resolveImageUpdate(artifact.metadata,options); }
    catch (error) { artifact.imageUpdate={status:'unknown',reference:artifact.metadata?.acquisition?.reference||null,reason:`Image update lookup unavailable: ${error.message}`,verifiedFix:false}; }
    const matches = cveMatches.filter(m => m.dep?.artifactTargetId === artifact.id);
    options.onArtifactProgress?.({stage:'CVE enrichment'});
    const enrichment = await require('./enrichment').enrichArtifactFindings(matches, options);
    const recordSources = new Set(['nvd', 'euvd', 'euvd-details']);
    artifact.coverage.push(...enrichment.coverage.map(c => ({ ...c, artifactTargetId: artifact.id,
      ...(recordSources.has(c.collector) ? { affectsCompleteness:false,
        diagnostics:enrichment.warnings.filter(w => w.source === c.collector) } : {}) })));
    warnings.push(...enrichment.warnings.filter(w => !recordSources.has(w.source)).map(w => ({ ...w, artifactTargetId: artifact.id })));
  }
  const recordSummary = require('../cve-record-coverage').summarizeCveRecords(cveMatches,
    { ...options, coverage: artifacts.flatMap(a => a.coverage) });
  if (recordSummary.warning) warnings.push(recordSummary.warning);
  require('../priority').attachPriority(cveMatches);
  const diagnostics=require('../diagnostics').partitionDiagnostics(warnings);
  return { resolvedDeps, cveMatches: require('../finding-summary').uniqueFindings(cveMatches), ...diagnostics, artifacts };
}

function incompleteCapabilities(result, required = ['inventory', 'advisories', 'sources']) {
  const gaps = [];
  for (const target of result.artifacts) {
    for (const capability of required) {
      if (capability === 'sources') {
        if (result.warnings.some(w => w.affectsCompleteness !== false && w.artifactTargetId === target.id && /source|osv/.test(w.type))) gaps.push({ target: target.id, capability });
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
