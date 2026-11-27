'use strict';

const {makeDepRecord} = require('../dep-record');
const {getCodec} = require('../codecs');
const {findEolProduct, getEolCycles, findCycleForVersion, checkEolDeps} = require('../outdated');

// Only product identities established by a versioned fingerprint enter upstream
// lifecycle checks. Distribution packages can receive downstream backports.
const runtimeSlugs = new Map(Object.entries({
  php:'php', python:'python', node:'nodejs', ruby:'ruby', nginx:'nginx', mariadb:'mariadb',
  postgresql:'postgresql', apache:'apache-http-server', dotnet:'dotnet', go:'go',
}));
const distributions = new Set(['debian','ubuntu','alpine','fedora','rocky-linux','almalinux','rhel']);
const cmsSlugs = new Set(['wordpress','drupal','typo3','prestashop']);

async function assessSystemMaintenance(targets, opts = {}) {
  const eolResults = [], obsoleteResults = [], updates = [], licensed = [], warnings = [];
  const cycles = new Map();
  for (const target of targets) {
    const deps = new Map(), products = new Map();
    const addProduct = (dep,slug,label,via) => {
      products.set(dep,{product:slug,label,via,viaKey:dep.manifestPaths?.[0]});
    };
    const {applications,inventory} = target.metadata.systemApplications;
    for (const dep of target.deps) {
      if (!dep.version) continue;
      if (dep.registryIdentity!=='cms-theme' && dep.systemApplicationIds?.length && getCodec(dep.ecosystem)?.checkRegistry &&
          !['binary','image-product','system'].includes(dep.ecosystem)) {
        const d = dep.imageRole === 'transitive' ? {...dep,scope:'transitive'} : dep;
        deps.set(d.coordKey,d);
        const product = findEolProduct(d);
        if (product) products.set(d,product);
      }
      const slug = runtimeSlugs.get(dep.binaryEvidence?.product);
      if (slug && dep.systemSection === 'runtime' && !dep.osPackageOwners?.length)
        addProduct(dep,slug,dep.name,'binary-version');
    }
    const distro = target.distribution;
    if (distributions.has(distro?.id) && distro.versionId) {
      const dep = makeDepRecord({ecosystem:'system',name:distro.id,version:distro.versionId,manifestPath:'etc/os-release'});
      addProduct({...dep,artifactTargetId:target.id},distro.id,distro.name || distro.id,'os-release');
    }
    const byApp = new Map(applications.map(a=>[a.id,a]));
    for (const c of inventory) {
      const app = byApp.get(c.applicationId);
      if (c.kind !== 'core' || !c.version || !cmsSlugs.has(app?.type)) continue;
      const dep = makeDepRecord({ecosystem:'application',name:app.type,version:c.version,manifestPath:c.evidence?.[0]?.path || app.root});
      addProduct({...dep,artifactTargetId:target.id},app.type,c.name,'cms-version');
    }

    if (opts.eol !== false) {
      const missing = new Set();
      for (const [dep,p] of products) {
        if (!cycles.has(p.product)) cycles.set(p.product,await getEolCycles(p.product,opts));
        if (!findCycleForVersion(cycles.get(p.product),dep.version)) missing.add(p.product+' '+dep.version);
      }
      const hits = await checkEolDeps([...products.keys()],{...opts,cycles:Object.fromEntries(cycles),productFor:dep=>products.get(dep)});
      eolResults.push(...hits);
      target.coverage.push({artifactTargetId:target.id,collector:'endoflife.date',capability:'maintenance',
        execution:missing.size ? 'partial' : products.size ? 'completed' : 'not-applicable',result:'consulted',
        ...(missing.size ? {reason:'Lifecycle data unavailable for '+[...missing].join(', ')} : {})});
    }
    const checks = opts.allLibs !== false && require('./system-module-updates').moduleChecks(target);
    if (checks) {
      for (const [id,dep] of deps) if (checks.replaces(dep,true)) deps.delete(id);
      for (const [id,dep] of checks.composer) deps.set(id,dep);
    }
    for (const id of new Set([...deps.values()].map(d=>d.ecosystem))) {
      const packages = new Map([...deps].filter(([,d])=>d.ecosystem===id));
      try {
        const data = await getCodec(id).checkRegistry(packages,{...opts,systemMaintenance:true,allLibs:opts.allLibs !== false,
          onVersionChecked:dep=>{ if (checks && dep.cmsComponent) checks.checked.add(dep.coordKey); }});
        obsoleteResults.push(...data.deprecated || []);
        updates.push(...(data.outdated || []).filter(o=>!checks || !checks.replaces(o.dep)));
        licensed.push(...data.licensed || []);
        if (opts.licenses && id==='maven') licensed.push(...require('../maven-license').collectMavenLicenses(packages));
      } catch (error) {
        warnings.push({type:'source-unavailable',artifactTargetId:target.id,message:id+' maintenance: '+error.message});
      }
    }
    if (checks && checks.components.length) {
      updates.push(...await require('./system-module-updates').checkModuleCatalogues(checks,opts));
      const expected = checks.components.length, executed = checks.checked.size;
      target.coverage.push({artifactTargetId:target.id,collector:'cms-extension-versions',capability:'maintenance',
        execution:executed===expected ? 'completed' : 'partial',result:executed===expected ? 'consulted' : 'indeterminate',
        expected,executed,reason:`${executed}/${expected} installed extensions have a comparable catalogue version.`});
    }

  }
  const superseded = new Set([...eolResults,...obsoleteResults].map(r=>r.dep.coordKey));
  return {eolResults,obsoleteResults,outdatedResults:updates.filter(r=>r.dep.scope!=='transitive' && !superseded.has(r.dep.coordKey)),
    licenseResults:opts.licenses ? require('../license-policy').assessLicenses(licensed) : null,warnings};
}

module.exports = {assessSystemMaintenance};
