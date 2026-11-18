'use strict';
const crypto = require('node:crypto');
const {renderTime}=require('../report-time');
const { projectImageCves } = require('./cve-view');
const esc = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const tr = locale => (en, fr) => locale === 'fr' ? fr : en;
const artifactAnchor = id => 'image-' + crypto.createHash('sha256').update(String(id)).digest('hex').slice(0, 12);
const title = a => a?.imageUpdate?.reference || a?.metadata?.reference || a?.metadata?.acquisition?.reference || a?.metadata?.source || a?.id || '';
const location = r => `${r?.path || ''}${r?.line != null ? ':' + r.line : ''}`;
const platform = value => typeof value === 'string' ? value : [value?.os, value?.architecture, value?.variant].filter(Boolean).join('/');
function artifactTitle(artifact, artifacts = []) {
 const label=title(artifact);
 // Always expose content identity, including archive names reused across scans.
 const meta=artifact.metadata||{}, p=platform(meta.platform), digest=meta.digest||meta.acquisition?.resolvedDigest||meta.configDigest||'';
 const short=digest ? String(digest).slice(0,19) : String(artifact.id||'').slice(-12);
 return [p,short].filter(Boolean).join(' · ')+' — '+label;
}
const visible = matches => (matches || []).filter(m => !m.suppressed && !m.cpeFiltered);
const linkedCves = cve => [...new Set([cve?.id,...(cve?.aliases||[]),...(cve?.upstream||[])].filter(id=>typeof id==='string' && /^CVE-\d{4}-\d{4,}$/i.test(id)).map(id=>id.toUpperCase()))];
// Native sources retain their own public record route; a GCVE is not an OSV advisory.
const advisoryUrl = id => `https://www.vigievuln.fr/${/^CVE-\d{4}-\d{4,}$/i.test(id)?'cve':/^GCVE-[0-9]+-/i.test(id)?'advisory/gcve':'advisory/osv'}/${encodeURIComponent(id)}`;
const safeUrl = value => typeof value==='string' && /^https?:\/\/[^\s<>"']+$/i.test(value) ? value : null;
function artifactGroups(projectInfo = {}, matches = []) {
 const groups = new Map();
 for (const artifact of projectInfo.artifacts || []) if (artifact?.id && !groups.has(artifact.id)) groups.set(artifact.id, {artifact, matches: []});
 for (const match of matches || []) {
  const id = match?.dep?.artifactTargetId || match?.artifactTargetId;
  if (!id) continue;
  if (!groups.has(id)) groups.set(id, {artifact: {id, metadata: {}, coverage: [], components: []}, matches: []});
  groups.get(id).matches.push(match);
 }
 return [...groups.values()];
}
function definitionText(artifact, locale) {
 const t=tr(locale),definitions=artifact.metadata?.definitions || [],discovery=artifact.metadata?.definitionDiscovery || {};
 if (definitions.length) return definitions.map(d => `<code>${esc(location(d))}</code>${d.role ? ` (${esc(d.role)})` : ''}${d.declared ? ` — <code>${esc(d.declared)}</code>` : ''}${d.binding==='registry-reference-resolution' ? ` — ${esc(t('registry reference resolved to the scanned digest','référence de registre résolue vers l’empreinte analysée'))}` : ''}`).join('<br>');
 if (discovery.status === 'not-supplied' || !discovery.status) return esc(t('Source definitions not provided.', 'Définitions source non fournies.'));
 if (discovery.status === 'no-match' || discovery.status === 'none' || discovery.status === 'completed') return esc(t('No source definition was matched to this image.', 'Aucune définition source associée à cette image.'));
 return esc(t('Source definition match is unavailable.', 'Association aux définitions source indisponible.'));
}
function renderImageSummary(a, locale) {
 const t=tr(locale),meta=a.metadata||{},acq=meta.acquisition||{};
 const cached=a.evidence==='cached-inventory',origin=cached?a.originalEvidence:a.evidence;
 const collectors=(a.coverage||[]).filter(c=>c.capability==='inventory' && ['completed','complete'].includes(c.execution||c.status)).map(c=>c.collector).filter(Boolean);
 const details=[...new Set(collectors)].map(c=>({apk:'APK',dpkg:'dpkg',rpm:'RPM','installed-applications':t('installed application metadata','métadonnées des applications installées'),'native-binaries':t('native binary metadata','métadonnées des binaires natifs')}[c]||c));
 const evidence=origin==='sbom'?t('SBOM inventory; signature not verified','Inventaire issu du SBOM ; signature non vérifiée'):origin==='content-inventory'?t('Inventory extracted from image filesystem','Inventaire extrait du système de fichiers de l’image')+(details.length?` (${details.join(', ')})`:''):t('Inventory origin unavailable','Origine de l’inventaire indisponible');
 const evidenceText=cached?evidence+' — '+(origin==='content-inventory'?t('saved inventory reused without rereading the image','inventaire enregistré réutilisé sans relire l’image'):t('saved inventory reused','inventaire enregistré réutilisé')):evidence;
 const rows=[
  [acq.kind?t('Acquisition','Acquisition'):t('Original format','Format d’origine'),`${esc(acq.kind||meta.format||a.kind||'—')} · <code>${esc(acq.reference||acq.source||meta.reference||meta.source||'—')}</code>`],
  ...(meta.registryReference?.reference && a.imageUpdate?.reference===meta.registryReference.reference ? [[t('Associated registry reference','Référence de registre associée'),`<code>${esc(a.imageUpdate.reference)}</code> — ${t('linked by platform manifest digest','liée par l’empreinte du manifeste de plateforme')}${meta.registryReference.verifiedAt?` · ${renderTime(meta.registryReference.verifiedAt,locale)}`:''}`]] : []),
  [t('Current manifest digest','Empreinte du manifeste actuel'),`<code>${esc(meta.digest||acq.resolvedDigest||meta.resolvedDigest||'—')}</code>`],
  ...(meta.configDigest?[[t('Configuration digest','Empreinte de configuration'),`<code>${esc(meta.configDigest)}</code>`]]:[]),
  [t('Platform','Plateforme'),esc(platform(meta.platform)||'—')],
  [t('Distribution','Distribution'),esc([a.distribution?.id,a.distribution?.versionId].filter(Boolean).join(' ')||'—')],
  [t('Evidence','Preuve'),esc(evidenceText)],
  [t('Inventory date','Date de l’inventaire'),renderTime(a.inventoryAt||'—',locale)],
  ...(a.imageUpdate ? [[t('Image update','Mise à jour de l’image'),require('./remediation-report').renderImageUpdateSummary(a,locale)]] : []),
  [t('Source definitions','Définitions source'),definitionText(a,locale)]
 ];
 return `<table class="image-summary"><tbody>${rows.map(([label,value])=>`<tr><th scope="row">${label}</th><td>${value}</td></tr>`).join('')}</tbody></table>`;
}
const {componentIdentity,reportedComponents} = require('./report-inventory');
function renderAdvisoryObservations(artifact,locale){
 const t=tr(locale),groups=new Map();
 for(const item of artifact.advisoryObservations||[]){
  const id=item.id||item.cveId,name=item.sourceName||item.dep?.sourceName||item.dep?.name,version=item.sourceVersion||item.dep?.sourceVersion||item.dep?.version;
  const key=JSON.stringify([item.source||'',id,name,version,item.status]);
  if(!groups.has(key))groups.set(key,{...item,id,name,version,packages:new Set()});
  const group=groups.get(key);if(item.evidence?.conflictingFinding)group.evidence={...group.evidence,conflictingFinding:true};for(const pkg of item.packages||[item.dep?.name])if(pkg)group.packages.add(pkg);
 }
 if(!groups.size)return '';
 const rows=[...groups.values()].map(item=>{
  const url=safeUrl(item.sourceUrl||item.evidence?.advisoryURL)||(/^CVE-\d{4}-\d{4,}$/.test(item.id||'')?`https://www.vigievuln.fr/cve/${encodeURIComponent(item.id)}`:null);
  const status=item.status==='possible'?t('Possibly affected','Potentiellement affecté'):item.status==='not-affected'?t('Not affected according to source','Non affecté selon la source'):item.status==='fixed'?t('Fixed according to source','Corrigé selon la source'):t('Not established','Non établi');
  const evidence=item.evidence||{},comparison=evidence.comparison;
  const reason=item.source==='freexian-tracker' && evidence.releaseStatus ? t('The tracker release status applies to a different archive source version; applicability to the installed version is undetermined.','Le statut du suivi concerne une autre version source de l’archive ; son applicabilité à la version installée reste indéterminée.') : evidence.versionRange ? t('Upstream version range cannot be evaluated.','La plage de versions amont ne peut pas être évaluée.') : evidence.statuses ? t('No usable tracker package/version verdict.','Le suivi ne fournit pas de verdict exploitable pour ce paquet et cette version.') : evidence.origin ? t('Package vendor provenance does not establish Debian origin.','La provenance du paquet ne permet pas d’établir une origine Debian.') : item.reason==='release status lacks an installed-version bound'?t('No version bound for this release.','Pas de borne de version pour cette distribution.'):item.reason==='package has explicitly different vendor provenance'?t('Package supplied by another vendor.','Paquet fourni par un autre éditeur.'):item.reason==='unrecognized or conflicting release status'?t('Unrecognised or conflicting distribution status.','Statut de distribution non reconnu ou contradictoire.'):item.reason||'';
  const states=(item.states||[]).map(s=>`${s.repo}: ${s.fixed?t('fixed','corrigé'):t('possibly vulnerable','potentiellement vulnérable')}`).join('; ');
  let detail=esc(states||reason||t('The source does not establish the status of this exact version.','La source ne permet pas de conclure pour cette version exacte.'));
  if(comparison && evidence.releaseApplicability==='unknown'){
   const rule=comparison.operator==='<'?`${esc(comparison.installedVersion)} &lt; ${esc(comparison.threshold)}`:t('No fixed version in the current source package rule.','Aucune version corrective dans la règle actuelle du paquet source.');
   const context=(evidence.contextReleases||[]).map(c=>`${esc((c.releases||[]).join(', '))}: ${esc(c.note||'')}`).join('<br>');
   detail=`${t('Current source package rule','Règle actuelle du paquet source')} : <code>${rule}</code><br>${evidence.reconciliation?t('This rule alone does not establish applicability to the unsupported release.','Cette règle seule ne détermine pas l’applicabilité à la distribution hors support.'):t('Applicability to this unsupported distribution is not established.','Applicabilité à cette distribution hors support non établie.')}${context?`<br><small>${t('Other releases marked not affected','Autres distributions déclarées non affectées')} : ${context}</small>`:''}`;
  }
  if(evidence.reconciliation?.assessments?.length){const notes=evidence.reconciliation.assessments.map(a=>{const proof=a.evidence?.releaseEvidence,link=safeUrl(proof?.sourceURL||a.evidence?.sourceURL);const label=esc(a.source||'');const ref=link?`<a href="${esc(link)}">${label}</a>`:label;const row=proof?.row;return row?`${ref} — ${esc(row.release)}: ${esc(row.fixedVersion)}`:ref;}).join(', ');detail+=`<br><small>${t('Release assessment','Évaluation de la distribution')} : ${notes}</small>`;}
  if(evidence.conflictingFinding)detail+=`<br><strong>${t('Another source reports this package as affected; the finding remains visible.','Une autre source signale ce paquet comme affecté ; le résultat reste visible.')}</strong>`;
  return `<tr><td>${url?`<a href="${esc(url)}">${esc(item.id)}</a>`:esc(item.id)}</td><td><code>${esc(item.name)}@${esc(item.version)}</code><br><small>${esc([...item.packages].join(', '))}</small></td><td>${status}</td><td>${detail}${item.observedAt?`<br>${renderTime(item.observedAt,locale)}`:''}</td></tr>`;
 }).join('');
 return `<details class="report-subsection"><summary><h4>${t('Additional advisory evidence','Vérifications complémentaires')} (${groups.size})</h4></summary><p>${t('These source observations are excluded from confirmed finding counts and remediation claims; check their individual evidence and any conflicting findings.','Ces observations des sources sont exclues des compteurs de vulnérabilités et des conclusions de correction ; consultez leurs preuves et les éventuels résultats contradictoires.')}</p><table><thead><tr><th>CVE</th><th>${t('Source package / installed packages','Paquet source / paquets installés')}</th><th>${t('Status','Statut')}</th><th>${t('Evidence','Preuve')}</th></tr></thead><tbody>${rows}</tbody></table></details>`;
}
function renderSeverityCounts(severity, locale) {
 const t=tr(locale),labels={critical:t('Critical','Critiques'),high:t('High','Élevées'),medium:t('Medium','Moyennes'),low:t('Low','Faibles'),unknown:t('Unknown','Inconnues')};
 return Object.entries(severity).filter(([,count])=>count>0).map(([band,count])=>`<span class="image-severity ${band}">${labels[band]} <strong>${count}</strong></span>`).join(' ') || '—';
}
function renderImageCves(projectInfo = {}, matches = [], locale = 'en', helpers = {}) {
 const t=tr(locale),render=helpers.renderCveTable,minor=helpers.minorSection,groups=artifactGroups(projectInfo,matches),artifacts=groups.map(g=>g.artifact);
 const explanation=`<p>${t('The CVE section shows linked CVE identifiers per image. Distribution advisories without linked CVEs remain in the image inventory section.','La section CVE présente les identifiants CVE liés à chaque image. Les avis de distribution sans CVE liée restent dans la section d’inventaire de l’image.')}</p>`;
 const noFindings=t('No findings recorded; consult scan coverage before drawing conclusions.', 'Aucun résultat enregistré ; consultez la couverture de l’analyse avant de conclure.');
 if(!groups.length)return explanation+`<p>${noFindings} ${t('Reference-only images have not been scanned.','Les images uniquement déclarées n’ont pas été analysées.')}</p>`;
 return explanation+groups.map(({artifact,matches:rows})=>{
  const anchor=artifactAnchor(artifact.id),heading=`${esc(artifactTitle(artifact,artifacts))} (${rows.length})`;
  const detail=rows.length && typeof render==='function' ? render(rows,{image:artifact}) : `<p>${noFindings}</p>`;
  const content=`${renderImageSummary(artifact,locale)}<p class="image-section-nav"><a class="report-section-link" href="#${anchor}">${t('Image inventory and coverage','Inventaire et couverture de l’image')}<span aria-hidden="true">→</span></a></p>${detail}`;
  return typeof minor==='function' ? minor(heading,content,{id:anchor+'-cves'}) : `<details class="report-subsection" open id="${anchor}-cves"><summary><h3>${heading}</h3></summary><div>${content}</div></details>`;
 }).join('');
}
function stats(group) {
 const matches=visible(group.matches),components=new Set(),advisories=new Set(),cves=new Set(),severity={critical:0,high:0,medium:0,low:0,unknown:0},updates=new Map();
 for(const m of matches) {
  const dep=m.dep||{},key=dep.coordKey || [dep.ecosystem,dep.namespace,dep.name,dep.version,dep.architecture,dep.manifestPaths?.[0]].join(':');
  components.add(key);advisories.add(m.advisoryId || m.cve?.id || '');
  for(const id of linkedCves(m.cve))cves.add(id);

  const fix=m.cve?.fixVersion || m.fixVersion;if(fix){const k=`${key}\0${fix}`, item=updates.get(k)||{dep,fix,advisories:new Set()};const advisory=m.advisoryId||m.cve?.id;if(advisory)item.advisories.add(advisory);updates.set(k,item);}
 }
 const cveRows=projectImageCves(matches);
 for(const m of cveRows){const band=String(m.cve?.severity||'unknown').toLowerCase();severity[Object.hasOwn(severity,band)?band:'unknown']++;}
 advisories.delete('');return {cveFindings:cveRows.length,findings:matches.length,components:components.size,advisories:advisories.size,cves:cves.size,severity,updates:[...updates.values()]};
}
function renderReferences(projectInfo, artifacts, locale) {
 const t=tr(locale),all=projectInfo.imageReferences?.length ? projectInfo.imageReferences : artifacts.flatMap(a=>a.metadata?.declarations || []),groups=new Map();
 for(const r of all){
  const label=r.reference||r.declared||'',key=JSON.stringify([label,r.platform||null]);
  if(!groups.has(key))groups.set(key,{label,platform:platform(r.platform),refs:[]});groups.get(key).refs.push(r);
 }
 if(!groups.size)return '';
 const rows=[...groups.values()].map(group=>{
  const locations=[...new Set(group.refs.map(location).filter(Boolean))],roles=[...new Set(group.refs.map(r=>r.role).filter(Boolean))],details=[];
  for(const r of group.refs){
   const ids=[...new Set([...(r.boundArtifactIds||[]),...(r.imageScan?.artifactIds||[])])].filter(id=>artifacts.some(a=>a.id===id));
   const status=r.imageScan?.status||r.scanStatus,reason=r.imageScan?.reasonCode||r.blockReason||r.classification;
   let value;
   if(status==='assessment-failed')value=esc(t('Inventory acquired; advisory assessment failed','Inventaire obtenu ; analyse des avis échouée'))+(r.imageScan?.message?`: ${esc(r.imageScan.message)}`:'');
   else if(ids.length){const text=status==='scanned'?t('Scanned image inventory','Inventaire de l’image analysée'):t('Image inventory acquired','Inventaire de l’image obtenu');value=ids.map(id=>`<a href="#${artifactAnchor(id)}">${esc(text)}</a>`).join(', ');}
   else if(status==='failed')value=esc(t('Image acquisition failed','Récupération de l’image échouée'))+(r.imageScan?.message||r.scanReason?`: ${esc(r.imageScan?.message||r.scanReason)}`:'');
   else if(reason==='local-build'||r.localBuild)value=esc(t('Local build; image cannot be acquired from a registry from this declaration.','Construction locale ; cette déclaration ne permet pas de récupérer l’image depuis un registre.'));
   else if(reason==='unresolved'||reason==='unresolved-variables'||r.unresolved?.length)value=esc(t('Unresolved variable','Variable non résolue'))+(r.unresolved?.length?`: ${esc(r.unresolved.join(', '))}`:'');
   else if(status==='not-scannable'||r.scanEligible===false)value=esc(t('Image cannot be scanned from this declaration','Cette déclaration ne permet pas d’analyser l’image'))+(reason?`: ${esc(reason)}`:'');
   else value=esc(t('Image scan status unavailable.','État de l’analyse de l’image indisponible.'));
   if(!details.includes(value))details.push(value);
  }
  return `<tr><td>${locations.length?locations.map(x=>`<code>${esc(x)}</code>`).join('<br>'):'—'}</td><td><code>${esc(group.label)}</code></td><td>${esc(group.platform||'—')}</td><td>${esc(roles.join(', ')||'—')}</td><td>${details.join('<br>')}</td></tr>`;
 }).join('');
 return `<details class="report-subsection" open><summary><h3>${t('Declared image references','Références d’images déclarées')}</h3></summary><table><thead><tr><th>${t('File','Fichier')}</th><th>${t('Declaration','Déclaration')}</th><th>${t('Platform','Plateforme')}</th><th>${t('Role','Rôle')}</th><th>${t('Status','État')}</th></tr></thead><tbody>${rows}</tbody></table></details>`;
}
function renderArtifactEvidence(projectInfo = {}, locale = 'en', matches = []) {
 const t=tr(locale),groups=artifactGroups(projectInfo,matches),artifacts=groups.map(g=>g.artifact);
 if(!groups.length && !(projectInfo.imageReferences||[]).length)return '';
 const referenceNotice=projectInfo.provenance?.mode==='offline' && projectInfo.imageReferences?.length ? `<p>${t('Air-gap mode: Dockerfiles remain in the isolated environment and are not transferred; images they define cannot therefore be built during online preparation.','Mode air gap : les Dockerfiles restent dans l’environnement isolé et ne sont pas transférés ; les images qu’ils définissent ne peuvent donc pas être construites pendant la préparation en ligne.')}</p>`:'';
 const overviewRows=groups.map(group=>{const a=group.artifact,s=stats(group),sev=Object.entries(s.severity).filter(([,v])=>v>0).map(([k,v])=>`${esc(k)}: ${v}`).join(' · ');return `<tr><td><a href="#${artifactAnchor(a.id)}">${esc(artifactTitle(a,artifacts))}</a></td><td>${Number(a.componentCount??a.components?.length??0)}</td><td>${s.components}</td><td>${s.findings}</td><td>${s.cveFindings}</td><td>${s.advisories}</td><td>${s.cves}</td><td>${sev}</td><td>${s.updates.length}</td></tr>`;}).join('');
 const overview=overviewRows?`<table><thead><tr><th>${t('Image','Image')}</th><th>${t('Components','Composants')}</th><th>${t('Affected packages','Paquets affectés')}</th><th>${t('Raw findings','Résultats bruts')}</th><th>${t('CVE rows','Lignes CVE')}</th><th>${t('Advisories','Avis')}</th><th>${t('Unique CVEs','CVE distinctes')}</th><th>${t('CVE row severities','Sévérités des lignes CVE')}</th><th>${t('Update candidates','Corrections proposées')}</th></tr></thead><tbody>${overviewRows}</tbody></table>`:'';
 const cards=groups.map(group=>{
  const a=group.artifact,meta=a.metadata||{},acq=meta.acquisition||{},s=stats(group),anchor=artifactAnchor(a.id);
  const definitions=(meta.definitions||[]).filter(d=>d.path && (['manifest-digest','index-digest','registry-reference-resolution'].includes(d.binding) || d.match==='exact-digest'));
  const sourceAction=definitions.length ? t('If applicable, update these verified source declarations:', 'Si nécessaire, mettez à jour ces déclarations source vérifiées :')+' '+definitions.map(d=>`<code>${esc(location(d))}</code>`).join(', ') : t('No matching source declaration is available; identify the build or deployment definition before changing it.', 'Aucune déclaration source associée n’est disponible ; identifiez la définition de build ou de déploiement avant de la modifier.');
  const imageAction=visible(group.matches).length ? `<p><strong>${t('Recommended image action','Action recommandée sur l’image')}:</strong> ${t('For a publisher-provided image, obtain and deploy a corrected image from its publisher. If you build the image, rebuild it from a corrected base and packages, republish it and deploy the replacement.','Pour une image fournie par un éditeur, procurez-vous et déployez une image corrigée auprès de cet éditeur. Si vous construisez l’image, reconstruisez-la à partir d’une base et de paquets corrigés, publiez-la de nouveau et déployez son remplacement.')} ${sourceAction} ${t('Scan the replacement image to verify the fixes and its coverage.','Analysez l’image de remplacement pour vérifier les corrections et la couverture.')} ${['available','current'].includes(a.imageUpdate?.status)?'':t('No replacement tag or digest has been verified from this evidence.','Aucun tag ni empreinte de remplacement n’a été vérifié à partir de ces éléments.')}</p>` : `<p><strong>${t('Recommended image action','Action recommandée sur l’image')}:</strong> ${t('No correction is proposed from the recorded findings; consult scan coverage before deciding the image is safe.','Aucune correction n’est proposée à partir des résultats enregistrés ; consultez la couverture avant de considérer l’image comme sûre.')}</p>`;
  const rows=(a.coverage||[]).map(c=>`<tr><td>${esc(c.capability||'')}</td><td>${esc(c.collector||c.source||'')}</td><td>${esc(c.execution||c.status||'unknown')}</td><td>${esc(c.reason||c.message||c.result||'')}</td></tr>`).join('');
  const updateIndex=new Map();
  for(const update of s.updates){const key=componentIdentity(update.dep),list=updateIndex.get(key)||[];list.push(update);updateIndex.set(key,list);}
  const findingIndex=new Map();
  for(const match of visible(group.matches)){const key=componentIdentity(match.dep||{}),list=findingIndex.get(key)||[];list.push(match);findingIndex.set(key,list);}
  const affectedKeys=new Set(findingIndex.keys());
  const inventory=reportedComponents(a,group.matches),inventoryKeys=new Set(inventory.map(componentIdentity));
  // Older or partial inventories can omit a component that is still supported
  // by a finding. Keep its correction, and identify the source of this row.
  for(const [key,findings] of findingIndex)if(!inventoryKeys.has(key)){inventory.push({...findings[0].dep,_fromFinding:true});inventoryKeys.add(key);}
  inventory.sort((left,right)=>Number(affectedKeys.has(componentIdentity(right)))-Number(affectedKeys.has(componentIdentity(left))));
  const componentRows=items=>items.map(c=>{
   const key=componentIdentity(c),updates=updateIndex.get(key)||[],findings=findingIndex.get(key)||[];
   const fixes=[...new Set(updates.map(u=>u.fix))];
   const advisories=[...new Set(findings.flatMap(m=>[m.advisoryId||m.cve?.id,...linkedCves(m.cve)]).filter(Boolean))];
   const links=advisories.map(id=>/^CVE-\d{4}-\d{4,}$/i.test(id)
    ? `<a href="#${anchor}-cves">${esc(id)}</a>`
    : `<a href="${advisoryUrl(id)}">${esc(id)}</a>`).join(', ');
   return `<tr><td><code>${esc(c.namespace?c.namespace+'/'+c.name:c.name||c.artifactId||c.coord||'')}</code><br>${esc(c.packageType||c.ecosystem||'')}${c._fromFinding?`<br><small>${t('From finding; not present in inventory','Issu d’un résultat ; absent de l’inventaire')}</small>`:''}</td><td>${esc(c.version||'—')}</td><td>${fixes.map(esc).join('<br>')||'—'}</td><td>${links||'—'}</td><td>${esc(c.architecture||'—')}</td><td>${esc(c.artifactPath||'—')}</td><td>${esc((c.osPackageOwners||[]).map(o=>`${o.name}@${o.version}`).join(', ')||'—')}</td></tr>`;
  }).join('');
  const table=items=>items.length?`<table class="image-inventory"><thead><tr><th>${t('Component','Composant')}</th><th>${t('Installed','Installé')}</th><th>${t('Candidate corrections','Corrections proposées')}</th><th>${t('Advisories','Avis')}</th><th>Arch</th><th>${t('Location','Emplacement')}</th><th>${t('OS package owner','Paquet système propriétaire')}</th></tr></thead><tbody>${componentRows(items)}</tbody></table>`:`<p>${t('No components observed.','Aucun composant observé.')}</p>`;
  const direct=inventory.filter(c=>c.imageRole==='direct'),subdeps=inventory.filter(c=>c.imageRole==='transitive'),unclassified=inventory.filter(c=>!['direct','transitive'].includes(c.imageRole));
  const componentSections=`<h5>${t('Direct image components','Composants directs de l’image')} (${direct.length})</h5>${table(direct)}`+
   `<h5>${t('Image sub-dependencies','Sous-dépendances de l’image')} (${subdeps.length})</h5>${table(subdeps)}`+
   (unclassified.length?`<h5>${t('Unclassified image components','Composants de l’image non classés')} (${unclassified.length})</h5>${table(unclassified)}`:'');
  const totals=[[t('Components','Composants'),Number(a.componentCount ?? a.components?.length ?? 0)],[t('Affected packages','Paquets affectés'),s.components],[t('Advisories','Avis'),s.advisories],[t('Unique CVEs','CVE distinctes'),s.cves]];
  const totalsTable=`<table class="image-totals"><thead><tr>${totals.map(([label])=>`<th scope="col">${label}</th>`).join('')}</tr></thead><tbody><tr>${totals.map(([,value])=>`<td class="image-total-value">${value}</td>`).join('')}</tr><tr><td colspan="4"><span class="image-severity-label">${t('CVE row severities','Sévérités des lignes CVE')}</span>${renderSeverityCounts(s.severity,locale)}</td></tr></tbody>${group.matches.length?`<tfoot><tr><td colspan="4"><a class="report-section-link" href="#${anchor}-cves">${t('View vulnerability details','Voir les vulnérabilités')}<span aria-hidden="true">→</span></a></td></tr></tfoot>`:''}</table>`;
  const noCve=visible(group.matches).filter(m=>m.dep?.ecosystem==='system' && !linkedCves(m.cve).length);
  const noCveRows=noCve.map(m=>{
   const dep=m.dep||{},c=m.cve||{},id=m.advisoryId||c.id||'—',url=safeUrl(c.advisorySource)||safeUrl(c.gcveSource)||safeUrl((c.osvRefs||[]).find(r=>safeUrl(r?.url))?.url);
   const name=dep.namespace?`${dep.namespace}/${dep.name||dep.artifactId||''}`:dep.name||dep.artifactId||'—';
   return `<tr><td><a href="${advisoryUrl(id)}"><code>${esc(id)}</code></a>${url?`<br><a href="${esc(url)}">${t("Original source","Source originale")}</a>`:""}</td><td>${esc(c.summary||c.description||'—')}</td><td>${renderTime(c.published||'—',locale)}</td><td><code>${esc(name)}</code> ${esc(dep.version||'')}</td><td>${esc(c.fixVersion||m.fixVersion||'—')}</td></tr>`;
  }).join('');
  const nonCveAdvisories=noCveRows?`<details open><summary>${t('Distribution advisories without linked CVEs','Avis de distribution sans CVE liée')} (${noCve.length})</summary><p>${t('No linked CVE or CVE severity is supplied for these advisory records. They may include security or maintenance updates.','Aucune CVE liée ni sévérité CVE n’est fournie pour ces avis. Ils peuvent concerner la sécurité ou la maintenance.')}</p><table><thead><tr><th>${t('Advisory','Avis')}</th><th>${t('Summary','Résumé')}</th><th>${t('Published','Publié')}</th><th>${t('Package','Paquet')}</th><th>${t('Candidate','Version proposée')}</th></tr></thead><tbody>${noCveRows}</tbody></table></details>`:'';
  return `<details class="report-subsection" open id="${anchor}"><summary><h3>${esc(artifactTitle(a,artifacts))}</h3></summary><div>`+
   renderImageSummary(a,locale)+
   totalsTable+
   imageAction+
   (rows?`<details open><summary>${t('Coverage checks','Contrôles de couverture')}</summary><table><thead><tr><th>${t('Capability','Capacité')}</th><th>${t('Source','Source')}</th><th>${t('Execution','Exécution')}</th><th>${t('Result / limitation','Résultat / limite')}</th></tr></thead><tbody>${rows}</tbody></table></details>`:`<p>${t('Coverage information unavailable.','Informations de couverture indisponibles.')}</p>`)+
   renderAdvisoryObservations(a,locale)+nonCveAdvisories+`<details class="report-subsection"><summary><h4>${t('Component inventory and candidate corrections','Inventaire des composants et corrections proposées')} (${inventory.length})</h4></summary><p>${t('Libraries are listed with or without findings; system packages and native binaries are detailed when associated with an advisory. Roles describe the image inventory, not project dependency scope.','Les bibliothèques sont listées avec ou sans résultat ; les paquets système et binaires natifs sont détaillés lorsqu’un avis leur est associé. Les rôles décrivent l’inventaire de l’image et non la portée des dépendances du projet.')}</p><p>${t('Candidate versions come from individual advisories. Verify them in the replacement image; they do not establish that a particular image tag or digest is corrected.','Les versions proposées proviennent d’avis individuels. Vérifiez-les dans l’image de remplacement ; elles ne prouvent pas qu’un tag ou une empreinte d’image est corrigé.')}</p>${componentSections}</details></div></details>`;
 }).join('');
 return referenceNotice+overview+(groups.length?`<p>${t('A raw finding is an advisory affecting a component. An advisory can link several CVEs; the CVE section groups linked CVE identifiers while advisories without linked CVEs remain below.','Un résultat brut correspond à un avis affectant un composant. Un avis peut être lié à plusieurs CVE ; la section CVE regroupe les identifiants liés et les avis sans CVE liée restent ci-dessous.')}</p>`:'')+cards+renderReferences(projectInfo,artifacts,locale);
}
module.exports={artifactAnchor,artifactTitle,artifactGroups,renderImageCves,renderArtifactEvidence};
