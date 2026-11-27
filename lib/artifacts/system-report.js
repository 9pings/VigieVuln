'use strict';

const {occurrence} = require('./report-inventory');

const path = require('node:path');
const {targetPath} = require('./report-path');
const {linkedCves,renderLatestVersions,renderSeverityCounts,productCheckLabel, renderImageCves, renderReferences, renderAdvisoryObservations} = require('./report');
const {projectImageCves} = require('./cve-view');

function byKey(items, keyOf) {
  const groups = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

function auditTargetName(target) {
  const meta = target.metadata || {};
  const acquisition = meta.acquisition || {};
  if (acquisition.reference) return acquisition.reference;
  if (meta.localDocker) {
    return meta.localDocker.tags?.find(tag => tag !== '<none>:<none>') ||
      meta.localDocker.repoDigests?.[0] || meta.localDocker.id || target.id;
  }
  const source = acquisition.source || meta.source;
  if (source) {
    const normalized = String(source).replaceAll('\\', '/');
    return path.posix.basename(normalized) || normalized;
  }
  return meta.tags?.find(tag => tag !== '<none>:<none>') || target.id;
}

function targetName(target) {
  const meta = target.metadata || {};
  const source = meta.source || meta.acquisition?.source || '';
  const file = path.posix.basename(source.replaceAll('\\','/'));
  const products = (target.productInventory?.entries || []).filter(e=>e.version && e.versionSource==='embedded-version-banner');
  const service = products.find(e=>e.category==='service') || products.find(e=>e.id==='php') || products[0];
  const cores = (meta.systemApplications?.inventory || []).filter(c=>c.kind==='core' && c.name);
  const cms = [...new Set(cores.map(c=>[c.name,c.version].filter(Boolean).join(' ')))].join(', ');
  const system = [cms || (service && service.label+' '+service.version),target.distribution?.name].filter(Boolean).join(' · ');
  const name = meta.tags?.[0] || meta.acquisition?.reference || meta.hostname || file || system || target.id;
  return [name,meta.partition].filter(Boolean).join(' · ');
}

function buildSystemSections({projectInfo, matches, locale, systemIds, warnings, applicationRelations}, helpers) {
  const {esc, minorSection, renderCveTable, renderInstanceFindings} = helpers;
  const t = (en,fr) => locale === 'fr' ? fr : en;
  const systems = projectInfo.artifacts.filter(a => systemIds.has(a.id));
  const images = projectInfo.artifacts.filter(a => !systemIds.has(a.id));
  const imageInfo = {...projectInfo,artifacts:images};
  const active = matches.filter(m => !m.suppressed && !m.cpeFiltered);
  const byTarget = byKey(active, m=>m.dep?.artifactTargetId);
  const code = value => '<code>'+esc(value || '—')+'</code>';
  const table = (headers, rows) => rows.length ? '<table><thead><tr>'+headers.map(h=>'<th>'+esc(h)+'</th>').join('')+
    '</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(cell=>'<td>'+cell+'</td>').join('')+'</tr>').join('')+'</tbody></table>' : '';
  const advisories = items => new Set(items.map(m=>m.cve?.id).filter(Boolean)).size;
  const componentName = c => c.coord || [c.namespace,c.name].filter(Boolean).join('/') || c.artifactId;
  const evidence = c => [...new Set([c.artifactPath,...(c.evidence || []).map(e=>e.path),c.path].filter(Boolean))];
  const matchTable = (items,systemRelation) => items.length ? renderCveTable(items,{systemRelation}) : '';
  const projects = [], hosts = [], checks = [], overview = [], projectNav = [];
  const chartMatches = new Map(), chartApps = [], hostFindings = [];
  const direct = 'direct', transitive = 'transitive', unknown = 'unknown';
  const relationLabels = {
    direct:t('Direct dependencies','Dépendances directes'),
    transitive:t('Transitive dependencies','Dépendances transitives'),
    unknown:t('Undetermined relationship','Relation indéterminée'),
  };

  for (const target of systems) {
    const name = targetName(target), meta = target.metadata;
    const {applications,inventory} = meta.systemApplications;
    chartApps.push(...applications.map(app=>({...app,root:targetPath(app.root)})));
    const itemsByApp = byKey(inventory,c=>c.applicationId);
    const appsById = new Map(applications.map(a=>[a.id,a]));
    const components = target.components || [];
    const componentByKey = new Map(components.map(c=>[occurrence(c),c]));
    const findings = byTarget.get(target.id) || [];
    const byComponent = byKey(findings,m=>occurrence(m.dep));
    const runtime = {components:components.filter(c=>c.systemSection==='runtime'),findings:[]}, hostDeps = [];
    const appBuckets = new Map(applications.map(a=>[a.id,{
      direct:[],transitive:[],unknown:[],
    }]));

    // Ownership is scoped to the inventoried target. An installed system package
    // can share a path prefix with a project whose document root is the scan root.
    function place(item,component,owners,relation) {
      if (component.systemSection === 'runtime') { runtime.findings.push(item); return; }
      const isHost = component.ecosystem === 'system' || ['global','system'].includes(component.imageSource?.category);
      const apps = isHost ? [] : [...new Set(owners || [])].filter(id=>appBuckets.has(id));
      if (!apps.length) { hostDeps.push(item); return; }
      for (const id of apps) appBuckets.get(id)[relation].push(item);
    }
    function relationOf(c,match) {
      if (match?.applicationRelation === unknown) return unknown;
      if (match?.applicationRelation === 'indirect') return transitive;
      if (match?.applicationRelation === 'direct' || c.systemSection === 'project' || c.provenance === 'application') return direct;
      if (c.imageRole === 'transitive' || c.scope === transitive) return transitive;
      return unknown;
    }
    for (const m of findings) {
      const c = componentByKey.get(occurrence(m.dep)) || m.dep;
      place(m,c,m.applicationIds?.length ? m.applicationIds : c.systemApplicationIds,relationOf(c,m));
    }

    const productKey = (name,file,offset) => JSON.stringify([name,targetPath(file),offset ?? null]);
    const productChecks = new Map((target.productInventory?.entries || []).map(e=>[productKey(e.name,e.path,e.resourceOffset),e]));
    const ownerKey = p => JSON.stringify([p.manager,p.name,p.version]);
    const installedPackages = byKey(components.filter(c=>c.ecosystem==='system'),ownerKey);
    const packageMatches = byKey(findings.filter(m=>m.dep.ecosystem==='system'),m=>ownerKey(m.dep));
    function matchesForOwner(owner) {
      const key = ownerKey(owner);
      const candidates = packageMatches.get(key) || [];
      if (owner.architecture) return candidates.filter(m=>m.dep.architecture===owner.architecture);
      // Older inventories kept no architecture on the file-to-package link.
      return installedPackages.get(key)?.length===1 ? candidates : [];
    }
    const inventoryTable = (items,showRuntimeCheck=false) => table([t('Component','Composant'),'Version',...(showRuntimeCheck ? [t('Latest version','Dernière version')] : []),t('Evidence path','Chemin de preuve'),t('Advisories','Avis')],
      items.map(c=>{
        const associated = byComponent.get(occurrence(c)) || [];
        const owned = showRuntimeCheck ? (c.osPackageOwners || []).flatMap(matchesForOwner) : [];
        const related = [...associated,...owned];
        const check = showRuntimeCheck && productChecks.get(productKey(c.name,c.artifactPath,c.binaryEvidence?.resourceOffset));
        const state = check && check.advisoryCheck!=='affected' ? check.advisoryCheck : 'indeterminate';
        let assessment;
        if(showRuntimeCheck && related.length){
          const severities = {critical:0,high:0,medium:0,low:0,unknown:0};
          const bands = Object.keys(severities);
          const ranks = new Map();
          for(const m of projectImageCves(related)){
            if(m.suppressed)continue;
            const index = bands.indexOf(String(m.cve.severity || '').toLowerCase());
            const rank = index<0 ? bands.length-1 : index;
            ranks.set(m.cve.id,Math.min(rank,ranks.get(m.cve.id) ?? rank));
          }
          for(const rank of ranks.values())severities[bands[rank]]++;
          const unlinked = new Set(related.filter(m=>m.dep.ecosystem==='system' && !linkedCves(m.cve).length).map(m=>m.cve.id));
          assessment = [ranks.size ? renderSeverityCounts(severities,locale) : '',unlinked.size ? esc(unlinked.size+' '+t('advisories without a CVE','avis sans CVE liée')) : ''].filter(Boolean).join(' · ');
        }else{
          assessment = esc(showRuntimeCheck ? productCheckLabel(state,locale) : [...new Set(associated.map(m=>m.cve.id))].join(', ') || '—');
        }
        return [(c.imageProduct?.label ? esc(c.imageProduct.label)+'<br>' : '')+code(componentName(c)),esc(c.version || '—'),
          ...(showRuntimeCheck ? [renderLatestVersions(c.releaseVersions,locale)] : []),evidence(c).map(targetPath).map(code).join('<br>'),assessment];
      }));
    const sub = content => systems.length > 1 ? minorSection(esc(name),content) : content;

    for (const app of applications) {
      const items = itemsByApp.get(app.id) || [];
      const identity = items.find(c=>['core','framework','project'].includes(c.kind));
      const label = identity?.name || (app.type==='project' ? identity?.coord || path.posix.basename(app.root) : app.type);
      const role = app.deploymentRole === 'installation-template' ? t('Installation template','Gabarit d’installation') : null;
      const title = [label,identity?.version,role,targetPath(app.root)].filter(Boolean).join(' · ');
      const anchor = 'system-app-'+projectNav.length;
      const number = '1.'+(projectNav.length+2);
      const buckets = appBuckets.get(app.id);
      const assigned = Object.values(buckets).flat();
      // Existing project charts use artifactTargetId to select their container lane.
      // Give them a presentation-only project view while preserving physical IDs in the report.
      for (const [relation,bucket] of Object.entries(buckets)) for (const m of bucket) {
        if (!chartMatches.has(m)) chartMatches.set(m,{...m,reportAnchor:anchor,applicationRelation:relation===transitive ? 'indirect' : relation,
          applicationIds:[], dep:{...m.dep,artifactTargetId:null,scope:relation===direct ? (m.dep.isDev ? 'dev' : 'prod') : relation===transitive ? transitive : m.dep.scope}});
        chartMatches.get(m).applicationIds.push(app.id);
      }
      const heading = title+' ('+advisories(assigned)+' '+t('distinct advisories','avis distincts')+')';
      const componentInventory = [direct,transitive,unknown].map(rel=>{
        const affected = [...new Map(buckets[rel].map(m=>[occurrence(m.dep),m.dep])).values()];
        if (!affected.length) return '';
        return minorSection(esc(relationLabels[rel])+' ('+affected.length+')',inventoryTable(affected),{level:4,collapsed:true});
      }).join('') || '<p>'+t('No affected component identified.','Aucun composant affecté identifié.')+'</p>';
      projectNav.push({id:anchor,label:title});
      const checks = (target.coverage || []).filter(check=>check.applicationId===app.id);
      const notices = (warnings || []).filter(w=>w.applicationId===app.id);
      const pairs = assigned.map(m=>{
        const rel = relationOf(componentByKey.get(occurrence(m.dep)) || m.dep,m);
        return {m:{...m,applicationIds:m.applicationIds?.length ? m.applicationIds : [app.id],
          applicationRelation:m.applicationRelation || (rel===transitive ? 'indirect' : rel)},dev:!!m.dep.isDev};
      });
      const rendered = renderInstanceFindings({...app,artifactTargetId:target.id},items,checks,pairs,applicationRelations,notices);
      projects.push(minorSection(number+' '+esc(heading),rendered+
        minorSection(t('Component inventory','Inventaire des composants'),componentInventory,{collapsed:true}),{id:anchor}));
    }

    const metadata = [[t('Target','Cible'),name],[t('Distribution','Distribution'),target.distribution?.name || target.distribution?.id],
      [t('Image format','Format d’image'),meta.diskFormat || (meta.format !== 'directory' ? meta.format : null)],
      [t('Partition','Partition'),meta.partition],[t('Image tags','Tags d’image'),meta.tags?.join(', ')],
      [t('Platform','Plateforme'),typeof meta.platform === 'string' ? meta.platform : [meta.platform?.os,meta.platform?.architecture,meta.platform?.variant].filter(Boolean).join('/')],
      [t('Manifest digest','Empreinte du manifeste'),meta.digest],[t('Configuration digest','Empreinte de configuration'),meta.configDigest],
      [t('Layers','Couches'),meta.layers?.length]].filter(([,value])=>value);
    const intro = table([t('Host information','Informations sur l’hôte'),t('Value','Valeur')],metadata.map(([k,v])=>[esc(k),code(v)]));
    const hostGroup = (title,body) => minorSection(esc(title),body,{level:4});
    hostFindings.push(...runtime.findings,...hostDeps);
    hosts.push(sub(intro+hostGroup(t('Interpreters, applications and services','Interpréteurs, applications et services'),
      inventoryTable(runtime.components,true)+matchTable(runtime.findings,direct) || '<p>'+t('None identified.','Aucun identifié.')+'</p>')+
      hostGroup(t('System dependencies (transitive)','Dépendances du système (transitives)'),matchTable(hostDeps,transitive) ||
      '<p>'+t('No vulnerability identified in host dependencies.','Aucune vulnérabilité identifiée dans les dépendances du système.')+'</p>')));
    const coverage = target.coverage || [];
    const gaps = coverage.filter(c=>c.affectsCompleteness !== false && ['partial','not-run','failed'].includes(c.execution));
    overview.push([esc(name),esc(target.distribution?.name || target.distribution?.id || '—'),String(applications.length),
      String(advisories(findings)),String(gaps.length)]);
    const hostCoverage = coverage.filter(c=>!appsById.has(c.applicationId));
    checks.push(sub(table([t('Source','Source'),t('Check','Contrôle'),t('Project','Projet'),t('Execution','Exécution'),t('Result','Résultat')],hostCoverage.map(c=>[
      esc(c.sourceId || c.collector || c.source),esc(c.capability),appsById.has(c.applicationId) ? code(targetPath(appsById.get(c.applicationId).root)) : '—',esc(c.execution),esc(c.reason || c.diagnostic || c.result),
    ]))+renderAdvisoryObservations(target,locale)));
  }

  const hostTitle = t('Host system','Système hôte');
  const cveSections = [minorSection('1.1 '+hostTitle,hosts.join(''),{id:'chhost'}),...projects];
  projectNav.unshift({id:'chhost',label:hostTitle});
  const imageMatches = active.filter(m=>!systemIds.has(m.dep?.artifactTargetId));
  // Earlier inventories recorded successful additional targets and failures,
  // but did not persist the option when discovery returned no references.
  const inspectImages = images.length || systems.some(a=>a.metadata.inspectLocalImages || a.coverage?.some(c=>c.collector==='local-images'));
  if (inspectImages) {
    const imageBody = images.length ? renderReferences(imageInfo,images,locale)+
      '<div id="chimages-cves">'+renderImageCves(imageInfo,imageMatches,locale,{renderCveTable,minorSection,merged:true})+'</div>' :
      renderReferences(imageInfo,[],locale)+'<p>'+t('No additional image was inventoried.','Aucune image supplémentaire inventoriée.')+'</p>';
    cveSections.push(minorSection('1.'+(projectNav.length+1)+' Images',imageBody,{id:'chimages'}));
    projectNav.push({id:'chimages',label:'Images'});
  }
  return {
    cveSections:{html:cveSections.join(''),toc:projectNav}, images, inspectImages:!!inspectImages,
    targetNames:systems.map(targetName).join(', '),
    projectMatches:[...chartMatches.values()], chartApps, hostFindings, checks:minorSection(t('Host coverage checks','Contrôles de couverture du système hôte'),checks.join(''),{collapsed:true}),
    overview:table([t('Target','Cible'),t('Operating system','Système'),t('Projects and instances','Projets et instances'),
      t('Distinct host and project advisories','Avis distincts sur l’hôte et ses projets'),t('Incomplete checks','Contrôles incomplets')],overview),
  };
}

module.exports = {auditTargetName,targetName,buildSystemSections};
