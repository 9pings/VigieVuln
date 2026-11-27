'use strict';
// NVD context concerns the identified CVE, not the distribution's own
// affected-version decision. All values are untrusted report evidence.
const esc=value=>String(value ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const {renderTime}=require('../report-time');
const CVE=/^CVE-\d{4}-\d{4,}$/i;
const LINKED_CVE_PREVIEW_LIMIT=6;
const words={
 en:{linked:'Linked CVEs',identity:'Same vulnerability',upstream:'Upstream CVE',unspecified:'Unspecified',associated:'associated CVE',
  distribution:'Distribution advisories',candidate:'Advisory-specific candidate',original:'Original source',evidence:'Linked CVE evidence',explanation:'CVE metrics provide context; the original advisory remains the source of the affected-version verdict.',
  cve:'CVE',relationship:'Relationship',severity:'Severity',score:'CVSS',vector:'Vector',cwe:'CWE',published:'Published',modified:'Modified',description:'Description',references:'References',unknown:'Not available'},
 fr:{linked:'CVE liées',identity:'Même vulnérabilité',upstream:'CVE en amont',unspecified:'Non précisée',associated:'CVE associée',
  distribution:'Avis de distribution',candidate:'Version candidate propre à cet avis',original:'Source originale',evidence:'Données des CVE liées',explanation:'Les métriques des CVE apportent du contexte ; l’avis d’origine reste la source du verdict sur les versions affectées.',
  cve:'CVE',relationship:'Relation',severity:'Sévérité',score:'CVSS',vector:'Vecteur',cwe:'CWE',published:'Publication',modified:'Modification',description:'Description',references:'Références',unknown:'Non disponible'},
};
function dict(locale){return String(locale||'en').toLowerCase().startsWith('fr')?words.fr:words.en;}
function cveLink(id){if(!CVE.test(String(id||'')))return '';const name=String(id).toUpperCase();return `<a href="https://www.vigievuln.fr/cve/${esc(name)}" target="_blank" rel="noopener noreferrer">${esc(name)}</a>`;}
function safeLink(value){try{const url=new URL(typeof value==='string'?value:value?.url);if(!['http:','https:'].includes(url.protocol)||url.username||url.password)return '';const href=url.href;return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(href)}</a>`;}catch{return '';}}
function number(value){return typeof value==='number' && Number.isFinite(value) && value>=0 && value<=10 ? String(value) : '';}
function records(cve){return Array.isArray(cve?.nvdEvidence?.records)?cve.nvdEvidence.records.filter(r=>r && CVE.test(String(r.id||''))):[];}
function renderLinkedCves(cve,locale){
 const t=dict(locale),own=String(cve?.id||'').toUpperCase(),items=new Map();
 for(const id of cve?.upstream||[])if(CVE.test(String(id))&&String(id).toUpperCase()!==own)items.set(String(id).toUpperCase(),null);
 for(const entry of cve?.cveEvidence || [])if(entry.cveProjectMetric && items.has(entry.id))items.set(entry.id,entry.cveProjectMetric);
 for(const record of records(cve)){const id=String(record.id).toUpperCase();if(id!==own)items.set(id,record);}
 if(!items.size)return '';
 const remaining=items.size-LINKED_CVE_PREVIEW_LIMIT;
 const preview=[...items].slice(0,LINKED_CVE_PREVIEW_LIMIT).map(([id,record])=>{
  const severity=typeof record?.severity==='string' && record.severity.toUpperCase()!=='UNKNOWN'?record.severity:null,score=number(record?.score);
  return cveLink(id)+(severity||score?` <small>(${esc([severity,score].filter(Boolean).join(' · '))})</small>`:'');
 }).join(', ');
 return `<div class="linked-cves"><span>${esc(t.linked)}:</span> ${preview}${remaining>0 ? ` … (+${remaining})` : ''}</div>`;
}
function renderRiskAttribution(cve,locale){
 const t=dict(locale),risk=cve?.riskEvidence;if(!risk || !['nvd','euvd','cveproject'].includes(risk.source) || !['identity','upstream'].includes(risk.relationship) || !CVE.test(String(risk.id||'')))return '';
 const kind=risk.relationship==='upstream'?t.associated:t.identity;
 return `<span class="risk-attribution">${risk.source==='euvd'?'ENISA EUVD':risk.source==='cveproject'?'CVEProject':'NVD'} · ${cveLink(risk.id)} (${esc(kind)})</span>`;
}
function renderRiskEvidence(cve,locale,options={}){
 const t=dict(locale),items=records(cve);if(!items.length)return '';
 const value=v=>v===null||v===undefined||v===''?esc(t.unknown):esc(v);
 const field=(label,content)=>`<div><label>${esc(label)}</label><span>${content}</span></div>`;
 const body=items.map(record=>{
  const relationship=record.relationship==='upstream'?t.upstream:record.relationship==='identity'?t.identity:t.unspecified;
  const sev=record.severity && String(record.severity).toUpperCase()!=='UNKNOWN'?record.severity:null;
  const score=number(record.score),vector=[record.cvssVersion,record.cvssVector].filter(Boolean).join(' · ');
  const cwes=Array.isArray(record.cwes)?record.cwes.filter(x=>typeof x==='string').join(', '):'';
  const refs=Array.isArray(record.references)?record.references.map(safeLink).filter(Boolean):[];
  const id=String(record.id).toUpperCase(),nvd=`<a href="https://nvd.nist.gov/vuln/detail/${esc(id)}" target="_blank" rel="noopener noreferrer">NVD</a>`;
  const own=options.omitRepeated && id===String(cve.id||'').toUpperCase();
  const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const sameSet=(a,b)=>Array.isArray(a)&&Array.isArray(b)&&equal([...new Set(a)].sort(),[...new Set(b)].sort());
  const shown=[];
  if(!own || (sev && sev!==cve.severity))shown.push(field(t.severity,value(sev)));
  if(!own || (record.score!=null && record.score!==cve.score))shown.push(field(t.score,value(score)));
  if(!own || (record.cvssVector && (record.cvssVector!==cve.cvssVector || record.cvssVersion!==cve.cvssVersion)))shown.push(field(t.vector,value(vector)));
  if(!own || (record.cwes?.length && !sameSet(record.cwes,cve.cwes)))shown.push(field(t.cwe,value(cwes)));
  for(const key of ['published','modified'])if(!own || (record[key] && record[key]!==cve[key]))shown.push(field(t[key],record[key]?renderTime(record[key],locale):esc(t.unknown)));
  const mainRefs=new Set([...(cve.nvdRefs||[]),...(cve.osvRefs||[])].map(safeLink));
  const uniqueRefs=[...new Set(refs)].filter(ref=>!own || !mainRefs.has(ref));
  const references=uniqueRefs.length?`<div class="panel-title">${esc(t.references)}</div><ul class="ref-list">${uniqueRefs.map(ref=>`<li>${ref}</li>`).join('')}</ul>`:'';
  if(own && !shown.length && !references)return '';
  shown.push(field('Source',nvd));
  return `<div class="panel-block"><h4>${cveLink(id)}${own?'':` · ${esc(relationship)}`}</h4><div class="kv">${shown.join('')}</div>${references}</div>`;
 }).join('');
 if(!body)return '';
 return `<section class="linked-cve-evidence"><h4>${esc(t.evidence)}</h4><p>${esc(t.explanation)}</p>${body}</section>`;
}
function renderEuvdEvidence(cve,locale,options={}){
 const t=dict(locale),detail=require('../euvd').normalizeEuvdDetailDates(cve?.euvdDetails);
 if(!detail || !/^EUVD-\d{4}-\d{1,12}$/.test(String(detail.id||'')))return '';
 const field=(label,content)=>`<div><label>${esc(label)}</label><span>${content}</span></div>`;
 const source=`<a href="https://euvd.enisa.europa.eu/vulnerability/${esc(detail.id)}" target="_blank" rel="noopener noreferrer">${esc(detail.id)}</a>`;
 const omit=!!options.omitRepeated,shown=[];
 if(detail.severity && (!omit || detail.severity!==cve.severity))shown.push(field(t.severity,esc(detail.severity)));
 if(detail.score!=null && (!omit || detail.score!==cve.score))shown.push(field(t.score,esc(number(detail.score)||t.unknown)));
 if(detail.cvssVector && (!omit || detail.cvssVector!==cve.cvssVector || detail.cvssVersion!==cve.cvssVersion))shown.push(field(t.vector,esc([detail.cvssVersion,detail.cvssVector].filter(Boolean).join(' '))));
 for(const key of ['published','modified'])if(detail[key] && (!omit || detail[key]!==cve[key]))shown.push(field(t[key],renderTime(detail[key],locale)));
 const mainRefs=new Set([...(cve.nvdRefs||[]),...(cve.osvRefs||[])].map(safeLink));
 const refs=Array.isArray(detail.references)?[...new Set(detail.references.map(safeLink).filter(Boolean))].filter(ref=>!omit || !mainRefs.has(ref)):[];
 return `<section class="linked-cve-evidence panel-block"><h4>ENISA EUVD · ${source}</h4><p>${esc(t.explanation)}</p>${shown.length?`<div class="kv">${shown.join('')}</div>`:''}${refs.length?`<div class="panel-title">${esc(t.references)}</div><ul class="ref-list">${refs.map(ref=>`<li>${ref}</li>`).join('')}</ul>`:''}</section>`;
}

function renderDistributionAdvisories(cve,locale){
 const t=dict(locale),advisories=Array.isArray(cve?.distributionAdvisories)?cve.distributionAdvisories:[];
 if(!advisories.length)return '';
 const body=advisories.map(item=>{
  const id=String(item?.id||'');if(!id)return '';
  const link=/^[A-Za-z0-9._:+-]{1,256}$/.test(id)?`<a href="https://www.vigievuln.fr/advisory/osv/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>`:esc(id);
  const origin=safeLink(item.sourceURL),relationship=item.relationship==='upstream'?t.upstream:item.relationship==='identity'?t.identity:t.unspecified;
  return `<div class="panel-block"><h4>${link}</h4><div class="kv"><div><label>${esc(t.relationship)}</label><span>${esc(relationship)}</span></div><div><label>${esc(t.candidate)}</label><span>${esc(item.fixVersion || t.unknown)}</span></div></div>${origin?`<div>${esc(t.original)}: ${origin}</div>`:''}</div>`;
 }).join('');
 return body?`<section class="distribution-advisories"><h4>${esc(t.distribution)}</h4>${body}</section>`:'';
}

function renderHistoricalEvidence(cve,locale){
 const proofs=require('../applicability-evidence').applicabilityEvidence(cve).filter(p=>p.kind==='historical');
 return proofs.map(({evidence:e})=>{
  const fr=String(locale).startsWith('fr'),d=e.distribution||{},commit=String(e.commit||'');
  const field=(label,value)=>`<div><label>${esc(label)}</label><span>${value}</span></div>`;
  const fields=[field('Distribution',esc([d.id,d.versionId,d.codename].filter(Boolean).join(' · ')))];
  if(e.scope==='release-specific-ela'){
   fields.push(field(fr?'Avis':'Advisory',safeLink(e.sourceURL)),field(fr?'Publication':'Published',renderTime(e.publishedAt,locale)),field(fr?'Version corrective':'Fixed version',esc(e.fixVersion||'—')));
   return `<section class="panel-block"><h4>${esc(e.advisoryId||'ELA')} · Freexian</h4><div class="kv">${fields.join('')}</div><p>${fr?'Comparaison au seuil correctif publié pour le paquet source de cette distribution ; aucune borne d’introduction n’est déclarée. Le correctif est publié dans le dépôt Extended LTS : vérifiez sa disponibilité pour l’image ou migrez vers une distribution maintenue.':'Comparison with the published fixed threshold for this release’s source package; no introduction bound is declared. The fix is published in the Extended LTS repository: check its availability for the image or migrate to a supported distribution.'}</p></section>`;
  }
  const source=/^[a-f0-9]{40}$/.test(commit)?`<a href="https://salsa.debian.org/security-tracker-team/security-tracker/-/tree/${commit}">${esc(commit.slice(0,12))}</a>`:esc(commit||'—');
  fields.push(field(fr?'Date limite des données':'Evidence cutoff',renderTime(e.cutoff,locale)),field(fr?'Révision de la source':'Source revision',source));
  const inherited=e.scope==='inherited-source-note';
  if(e.comparisonThreshold)fields.push(field(fr?'Seuil de comparaison':'Comparison threshold',esc(e.comparisonThreshold)));
  if(e.trackerUrgency)fields.push(field(fr?'Urgence selon Debian':'Debian urgency',esc(e.trackerUrgency)));
  const annotations=(e.annotations||[]).map(x=>[x.kind,x.note].filter(Boolean).join(' — '));
  if(annotations.length)fields.push(field(fr?'Décision de maintenance':'Maintenance decision',esc(annotations.join('; '))));
  const explanation=inherited?(fr?'La règle générale du paquet source est appliquée selon la priorité des règles du tracker Debian. Son seuil de comparaison ne constitue pas une proposition de mise à jour pour cette release.':'The source package’s general rule is applied with Debian tracker precedence. Its comparison threshold is not an update recommendation for this release.'):(fr?'La version source inventoriée est évaluée avec la règle propre à cette distribution.':'The inventoried source version is evaluated against the rule specific to this distribution.');
  return `<section class="panel-block"><h4>${fr?'Preuve de portée historique':'Historical applicability evidence'}</h4><div class="kv">${fields.join('')}</div><p>${explanation} ${fr?'Ce snapshot historique ne couvre pas les vulnérabilités publiées après sa date limite.':'This historical snapshot does not cover vulnerabilities published after its cutoff.'}</p>${e.originStatus==='distribution-context'?`<p class="muted">${fr?'Origine déduite du contexte de distribution et de l’identité déclarée par le paquet ; contenu du paquet non authentifié.':'Origin follows the distribution context and declared package identity; package contents are not authenticated.'}</p>`:''}</section>`;
 }).join('');
}
function renderVendorEvidence(cve,locale){
 return require('../applicability-evidence').applicabilityEvidence(cve).filter(p=>p.kind==='vendor').map(({evidence:e})=>{
 const fr=String(locale).startsWith('fr');
 const fields=[[fr?'Version amont':'Upstream version',esc(e.upstreamVersion||'—')],[fr?'Versions affectées':'Affected versions',esc(e.versionRange||'—')],[fr?'Origine déclarée':'Declared origin',esc(e.packageOrigin?.declared||'—')],['Source',safeLink(e.advisoryURL||e.sourceURL)],[fr?'Consultation':'Consulted',renderTime(e.observedAt,locale)]];
 return `<section class="panel-block"><h4>${fr?'Avis du fournisseur':'Vendor advisory'}</h4><div class="kv">${fields.map(([label,value])=>`<div><label>${label}</label><span>${value}</span></div>`).join('')}</div><p class="muted">${fr?'Correspondance de version fondée sur l’origine déclarée du paquet. L’applicabilité à la configuration effective et la signature du paquet ne sont pas vérifiées.':'Version match based on the declared package origin. Applicability to the runtime configuration and package signature are not verified.'}</p></section>`;
 }).join('');
}
module.exports={renderLinkedCves,renderRiskEvidence,renderRiskAttribution,renderEuvdEvidence,renderDistributionAdvisories,renderHistoricalEvidence,renderVendorEvidence};
