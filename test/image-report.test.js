'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {generateHtmlReport,generateWordReport}=require('../lib/cve-report');
const {makeDepRecord}=require('../lib/dep-record');
const {artifactAnchor}=require('../lib/artifacts/report');
function fixture(){
 const imageId='oci:sha256:'+'a'.repeat(64),otherId='oci:sha256:'+'b'.repeat(64);
 const image={id:imageId,kind:'oci',metadata:{source:'registry.example/app:v1',resolvedDigest:'sha256:'+'a'.repeat(64),platform:{os:'linux',architecture:'amd64'},definitions:[{path:'deploy/compose.yml',line:17,declared:'registry.example/app@sha256:'+'a'.repeat(64),role:'deployment',match:'exact-digest'}]},distribution:{id:'alpine',versionId:'3.19'},componentCount:1,coverage:[]};
 const other={id:otherId,kind:'oci',metadata:{source:'other-image.tar',resolvedDigest:'sha256:'+'b'.repeat(64)},distribution:{id:'debian',versionId:'12'},componentCount:1,coverage:[]};
 const dep=(name,id,file)=>{const d=makeDepRecord({ecosystem:'system',namespace:'alpine',name,version:'1.0-r0',manifestPath:file,provenance:'installed'});return Object.assign(d,{coordKey:`artifact:${id}:${name}`,artifactTargetId:id,artifactPath:file,packageType:'apk'});};
 const a=dep('shared-package',imageId,'/lib/apk/db/installed'),b=dep('shared-package',otherId,'/var/lib/dpkg/status');
 const m=makeDepRecord({ecosystem:'maven',namespace:'org.example',name:'maven-only',version:'1.0',manifestPath:'/project/pom.xml'});
 const cve=(dep,id)=>({dep,cve:{id,severity:'HIGH',score:7.5,description:`description ${id}`,fixVersion:'2.0-r0',fixScope:'advisory',packageFixVerified:false},source:'osv'});
 return {ids:[imageId,otherId],payload:{cveMatches:[cve(a,'CVE-2099-1001'),cve(b,'CVE-2099-1001'),cve(m,'CVE-2099-2001')],resolvedDeps:new Map([[a.coordKey,a],[b.coordKey,b],[m.coordKey,m]]),projectInfo:{name:'mixed',src:'/project',generatedAt:'2026-11-05',artifacts:[image,other]}}};
}
function detailsById(html,id){const anchor=html.indexOf(`id="${id}"`);assert(anchor>=0,`${id} exists`);const start=html.lastIndexOf('<details',anchor);assert(start>=0);const re=/<details\b[^>]*>|<\/details>/g;re.lastIndex=start;let depth=0,m;while((m=re.exec(html))){depth+=m[0].startsWith('</')?-1:1;if(depth===0)return html.slice(start,re.lastIndex);}assert.fail(`unclosed ${id}`);}
test('image CVEs group installation sources and declarations lead the image chapter',()=>{
 const {payload,ids}=fixture(),base=payload.cveMatches[0];
 const deps=[{ecosystem:'system',manager:'dpkg',artifactPath:'var/lib/dpkg/status'},
  {ecosystem:'npm',artifactPath:'usr/local/lib/node_modules/tool/package.json'},
  {ecosystem:'npm',artifactPath:'srv/app/package.json'},
  {ecosystem:'npm',artifactPath:'srv/app/dist/jquery.js',installEvidence:{source:'retire'}},
  {ecosystem:'npm',artifactPath:'srv/app/node_modules/child/package.json'}];
 payload.cveMatches=deps.map((d,i)=>({...base,dep:{...base.dep,...d,name:`component-${i}`,artifactId:`component-${i}`,coordKey:`component-${i}`,artifactTargetId:ids[0]}}));
 payload.projectInfo.imageReferences=[{reference:'example:latest',path:'compose.yaml',line:3,classification:'registry'}];
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),cves=detailsById(html,'chimages-cves'),inventory=detailsById(html,'chimages');
  const headings=['System packages — APT / dpkg','Global installations — npm -g','Applications with a root descriptor — /srv/app','Bundled JavaScript (RetireJS)','Other components and sub-dependencies'];
  for(let i=0;i<headings.length;i++){assert.ok(cves.includes(headings[i]),headings[i]);if(i)assert.ok(cves.indexOf(headings[i])>cves.indexOf(headings[i-1]));}
  assert.match(cves,/<code>\/srv\/app\/package\.json<\/code>/);
  assert.equal((cves.match(/class="cve-row/g)||[]).length,5);
  assert.ok(inventory.indexOf('Declared image references')<inventory.indexOf('class="image-totals"'));
  assert.ok(inventory.indexOf('Declared image references')<inventory.indexOf('<th>Components</th>'));
 }
});
test('native GCVE image advisories link to their own source and site record',()=>{
 const {payload}=fixture(),match=payload.cveMatches[0];
 match.cve={id:'GCVE-1-native/test',gcveSource:'https://example.test/feed',description:'Native advisory',severity:'HIGH',score:7.5,fixVersion:'2.0'};match.source='GCVE:GNA-1';
 payload.cveMatches=[match];
 for(const render of [generateHtmlReport,generateWordReport]){
  const chapter=detailsById(render(payload),'chimages');
  assert.match(chapter,/https:\/\/www\.vigievuln\.fr\/advisory\/gcve\/GCVE-1-native%2Ftest/);
  assert.match(chapter,/https:\/\/example\.test\/feed/);
  assert.doesNotMatch(chapter,/advisory\/osv\/GCVE/);
 }
});
test('HTML and Word order images after CVEs, group by image and retain declaration location',()=>{
 const {ids,payload}=fixture();
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),cve=html.indexOf('id="chcve"'),images=html.indexOf('id="chimages"'),deps=html.indexOf('id="chbin"');
  assert(cve>=0 && images>cve && deps>images,'image evidence follows CVEs and precedes dependencies');
  assert(html.indexOf('class="exec-summary ')>=0 && html.indexOf('class="exec-summary ')<cve,'executive summary precedes CVE section');
  const compact=detailsById(html,'chimages-cves');
  assert(html.indexOf('id="chimages-cves"')>html.indexOf('id="ch1"'),'image CVEs follow the other populated CVE subsections');
  for(const id of ids)assert.match(compact,new RegExp(artifactAnchor(id)+'-cves'));
  assert.match(compact,/CVE-2099-1001/);assert.equal((compact.match(/class="cve-row/g)||[]).length,2,'same finding in two images remains two rows');
  assert.match(html,/deploy\/compose\.yml/);assert.match(html,/compose\.yml(?:<[^>]+>)*:?\s*17|compose\.yml:17/);
  for(const id of ids)assert.match(html,new RegExp(`id="${artifactAnchor(id)}"`));
  assert.match(html,/other-image\.tar/);assert.match(html,/unavailable|not provided|not available/i);
  const maven=detailsById(html,'ch1');
  assert.match(maven,/CVE-2099-2001/);assert.doesNotMatch(maven,/CVE-2099-1001/);
  const evidence=detailsById(html,'chimages');assert.doesNotMatch(evidence,/class="cve-row/,'evidence chapter must not repeat CVE detail tables');
  assert.match(compact,/class="cve-row/,'image subsection uses the common CVE table');assert.match(compact,/2\.0-r0/,'candidate fix stays visible');
 }
});
test('image report has unique element ids and every local navigation anchor resolves',()=>{
 for (const render of [generateHtmlReport,generateWordReport]) {
  const html=render(fixture().payload);
  const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
  const dup=ids.filter((id,i)=>ids.indexOf(id)!==i);assert.deepEqual(dup,[]);
  const links=[...html.matchAll(/href="#([^"]+)"/g)].map(m=>m[1]);
  for(const id of links)assert(ids.includes(id),`anchor #${id} resolves`);
 }
});

test('reference-only images report a declaration without inventing findings or an image digest',()=>{
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render({cveMatches:[],projectInfo:{name:'reference-only',src:'/project',imageReferences:[{path:'compose.yml',line:3,declared:'example.test/app:latest',role:'deployment'}]}});
  assert.match(html,/compose\.yml/);assert.match(html,/example\.test\/app:latest/);
  assert.match(html,/Image scan status unavailable|État de l.analyse de l.image indisponible/i);
  assert.doesNotMatch(html,/class="cve-row/);
  assert.doesNotMatch(html,/sha256:[a-f0-9]{64}/);
 }
});
test('French mixed and reference-only reports preserve image grouping and honest evidence',()=>{
 const {payload}=fixture();
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render({...payload,locale:'fr'});assert(html.indexOf('id="chimages"')>html.indexOf('id="chcve"'));assert.match(html,/compose\.yml/);assert.match(html,/CVE-2099-1001/);assert.doesNotMatch(detailsById(html,'ch1'),/CVE-2099-1001/);
  const refs=render({cveMatches:[],locale:'fr',projectInfo:{name:'references',imageReferences:[{path:'compose.yml',line:3,declared:'example.test/app:latest'}]}});assert.match(refs,/État de l.analyse de l.image indisponible/i);assert.doesNotMatch(refs,/class="cve-row/);
 }
});
function cveHeading(html){const section=detailsById(html,'chcve');return (section.match(/<summary>\s*<h2>([\s\S]*?)<\/h2>/)||[])[1]?.replace(/<[^>]*>/g,'').trim()||'';}
test('CVE heading lists only nonzero finding groups for mixed and image-only reports',()=>{
 const {payload}=fixture();
 for(const render of [generateHtmlReport,generateWordReport]){
  for(const locale of ['en','fr']){
   const heading=cveHeading(render({...payload,locale}));
   assert.match(heading,/Images?:?\s*2/i);assert.doesNotMatch(heading,/(?:^|[,;(])\s*0\s*(?:direct|indirect|en direct)/i);
   assert.doesNotMatch(heading,/0\s*(?:dev|test)/i);
   const imageOnly={...payload,cveMatches:payload.cveMatches.filter(m=>m.dep.artifactTargetId),resolvedDeps:new Map([...payload.resolvedDeps].filter(([,d])=>d.artifactTargetId))};
   const imageHeading=cveHeading(render({...imageOnly,locale}));assert.match(imageHeading,/Images?:?\s*2/i);assert.doesNotMatch(imageHeading,/0\s*(?:direct|indirect|en direct)/i);
  }
 }
});
test('CVE heading distinguishes no scannable components from a scan with no findings',()=>{
 const dep=makeDepRecord({ecosystem:'npm',name:'clean-package',version:'1.2.3',manifestPath:'/project/package-lock.json'});
 for(const render of [generateHtmlReport,generateWordReport])for(const [locale,empty,clean] of [['en',/No scannable components/i,/No CVEs detected/i],['fr',/Aucun (?:composant|élément) analysable/i,/Aucune CVE détectée/i]]){
  const emptyHeading=cveHeading(render({cveMatches:[],resolvedDeps:new Map(),projectInfo:{name:'empty'},locale}));assert.match(emptyHeading,empty);assert.doesNotMatch(emptyHeading,/0\s*(?:direct|indirect|en direct)/i);
  const cleanHeading=cveHeading(render({cveMatches:[],resolvedDeps:new Map([[dep.coordKey,dep]]),projectInfo:{name:'clean'},locale}));assert.match(cleanHeading,clean);assert.doesNotMatch(cleanHeading,empty);
  const referenceHeading=cveHeading(render({cveMatches:[],resolvedDeps:new Map(),projectInfo:{name:'references',imageReferences:[{path:'compose.yml',line:3,declared:'example.test/app:latest'}]},locale}));assert.match(referenceHeading,empty);
 }
});
test('non-CVE image advisory stays in image inventory rather than the CVE section',()=>{
 const {payload}=fixture();const item=payload.cveMatches[0];item.cve={id:'DLA-2099-0001',severity:'UNKNOWN',description:'Advisory with no CVE metadata'};payload.cveMatches=[item];
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const html=render({...payload,locale});assert.doesNotMatch(detailsById(html,'chcve'),/DLA-2099-0001/);assert.match(detailsById(html,'chimages'),/DLA-2099-0001/);
 }
});
test('multi-CVE distribution advisory produces separate CVE rows with distro advisory references',()=>{
 const {payload}=fixture(),item=payload.cveMatches[0];
 item.cve={id:'DLA-2099-1234',severity:'UNKNOWN',description:'Distribution advisory',upstream:['CVE-2099-3001','CVE-2099-3002'],fixVersion:'2.0-r0',fixScope:'advisory',nvdEvidence:{records:[
  {id:'CVE-2099-3001',relationship:'upstream',severity:'HIGH',score:8.2,cvssVector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',references:[{url:'https://nvd.nist.gov/vuln/detail/CVE-2099-3001'}]},
  {id:'CVE-2099-3002',relationship:'upstream',severity:'MEDIUM',score:5.3,cvssVector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',references:[{url:'https://nvd.nist.gov/vuln/detail/CVE-2099-3002'}]}
 ]}};payload.cveMatches=[item];
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const html=render({...payload,locale}),section=detailsById(html,'chimages-cves');assert.equal((section.match(/class="cve-row/g)||[]).length,2);assert.match(section,/CVE-2099-3001/);assert.match(section,/CVE-2099-3002/);assert.match(section,/DLA-2099-1234/);assert.doesNotMatch(section,/<td class="cve">[^<]*<a[^>]*>DLA-2099-1234<\/a>/);assert.match(section,/8\.2/);assert.match(section,/5\.3/);assert.match(section,/2\.0-r0/);assert.equal(item.cve.severity,'UNKNOWN');assert.equal(item.cve.score,undefined);
 }
});
test('image summaries and the combined closed inventory retain exact component corrections',()=>{
 const {ids,payload}=fixture(),image=payload.projectInfo.artifacts[0],dep=payload.cveMatches[0].dep;
 image.components=[{...dep,architecture:'amd64'}, {...dep,name:'unaffected',architecture:'amd64'}];
 dep.architecture='amd64';
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),cves=detailsById(html,artifactAnchor(ids[0])+'-cves'),details=detailsById(html,artifactAnchor(ids[0]));
  for(const section of [cves,details]){assert.match(section,/<table class="image-summary">/);assert.match(section,/deploy\/compose\.yml:17/);assert.match(section,/linux\/amd64/);}
  assert.match(details,render===generateHtmlReport ? /<details class="report-subsection"><summary><h4>Component inventory and candidate corrections/ : /<details class="report-subsection" open><summary><h4>Component inventory and candidate corrections/);
  const shared=details.match(/<tr><td><code>alpine\/shared-package<\/code>[\s\S]*?<\/tr>/)?.[0],unaffected=details.match(/<tr><td><code>alpine\/unaffected<\/code>[\s\S]*?<\/tr>/)?.[0];
  assert.match(shared,/2\.0-r0/);assert.match(shared,/CVE-2099-1001/);assert.equal(unaffected,undefined);
  assert.doesNotMatch(details,/Package corrections to verify in the replacement image/);
 }
});
test('baseline report distinguishes findings unassessed in the current and baseline scans',()=>{
 const {payload}=fixture(),empty={added:0,removed:0,unchanged:0,unassessed:0};
 payload.diff={summary:{cve:{...empty,unassessed:2,unassessedAdded:3,addedProduction:0,addedBySeverity:{}},eol:empty,obsolete:empty,outdated:empty,licenses:empty},cve:{added:[]}};
 for(const render of [generateHtmlReport,generateWordReport]){
  const en=detailsById(render(payload),'chdiff');assert.match(en,/2 unassessed because advisory coverage is incomplete/);assert.match(en,/3 currently observed finding\(s\) cannot be classified as new because baseline advisory coverage was incomplete/);
  const fr=detailsById(render({...payload,locale:'fr'}),'chdiff');assert.match(fr,/3 résultat\(s\) observé\(s\) actuellement/);assert.match(fr,/couverture des avis de référence était incomplète/);
 }
});
test('image inventory omits system components without advisories and identifies saved evidence accurately',()=>{
 const {ids,payload}=fixture(),image=payload.projectInfo.artifacts[0],dep=payload.cveMatches[0].dep;
 image.evidence='cached-inventory';image.originalEvidence='content-inventory';image.coverage=[{capability:'inventory',collector:'apk',execution:'completed'},{capability:'inventory',collector:'native-binaries',execution:'completed'}];
 image.components=[{...dep,name:'unaffected'},dep];delete payload.cveMatches[0].cve.fixVersion;
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),details=detailsById(html,artifactAnchor(ids[0])),table=details.slice(details.indexOf('<table class="image-inventory"'));
  assert.match(table,/alpine\/shared-package/);assert.doesNotMatch(table,/alpine\/unaffected/);
  assert.match(details,/Inventory extracted from image filesystem \(APK, native binary metadata\)/);assert.match(details,/saved inventory reused without rereading the image/);
  assert.match(html,/:is\(h3,h4\)::before/);
 }
 image.originalEvidence='sbom';let html=generateHtmlReport(payload);assert.match(html,/SBOM inventory; signature not verified/);assert.doesNotMatch(html,/saved inventory reused without rereading the image/);
 image.originalEvidence=undefined;html=generateHtmlReport(payload);assert.match(html,/Inventory origin unavailable/);
});
test('image CVE renderer receives the associated image as context',()=>{
 const {payload}=fixture(),{renderImageCves}=require('../lib/artifacts/report'),seen=[];
 renderImageCves(payload.projectInfo,payload.cveMatches,'en',{renderCveTable:(rows,options)=>{seen.push({rows,options});return '';}});
 assert.equal(seen.length,2);assert.equal(seen[0].options.image,payload.projectInfo.artifacts[0]);assert.equal(seen[1].options.image,payload.projectInfo.artifacts[1]);
});
test('merged image keeps the normal CVE lists and appends the original inventory tables',()=>{
 const {parseDocument,DomUtils}=require('htmlparser2');
 const {renderImageCves,renderArtifactEvidence}=require('../lib/artifacts/report');
 const {projectImageCves}=require('../lib/artifacts/cve-view');
 const {payload}=fixture(),image=payload.projectInfo.artifacts[0],base=payload.cveMatches[0];
 const info={artifacts:[image]};
 const raw=[{...base,cve:{...base.cve,id:'DLA-1',upstream:['CVE-2099-1001','CVE-2099-1002']}},
  {...base,cve:{...base.cve,id:'DLA-2',upstream:[],fixVersion:'3.1'}}];
 const helpers={renderCveTable:rows=>rows.map(m=>m.cve.id).join(' ')};
 const normal=parseDocument(renderImageCves(info,projectImageCves(raw),'en',helpers));
 const inventory=parseDocument(renderArtifactEvidence(info,'en',raw));
 const merged=parseDocument(renderImageCves(info,raw,'en',{...helpers,merged:true}));
 const lists=doc=>DomUtils.findAll(n=>n.name==='details' && n.attribs['data-image-source'],doc.children).map(n=>DomUtils.getOuterHTML(n));
 const tables=doc=>DomUtils.findAll(n=>n.name==='table' && n.attribs.class==='image-inventory',doc.children).map(n=>DomUtils.getOuterHTML(n));
 assert.ok(lists(normal).length && tables(inventory).length);
 assert.deepEqual(lists(merged),lists(normal));
 assert.deepEqual(tables(merged),tables(inventory));
 assert.match(tables(merged).join(''),/DLA-2/);
 assert.deepEqual(tables(normal),[]);
});
test('mixed image and source reports retain source scope totals and valid executive links',()=>{
 const {payload}=fixture(),source=payload.cveMatches[2];
 source.dep.scope='vendored';source.cve.severity='CRITICAL';
 const transitive={dep:{...source.dep,coordKey:'transitive:other',artifactId:'other',name:'other',scope:'transitive'},cve:{id:'CVE-2099-2002',severity:'HIGH'},source:'osv'};
 payload.cveMatches.push(transitive);payload.resolvedDeps.set(transitive.dep.coordKey,transitive.dep);
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),summary=html.slice(html.indexOf('<div class="summary">'),html.indexOf('<div class="summary">')+3500);
  assert.match(summary,/<div class="v">2<\/div><div class="l">Source findings<\/div>/);
  assert.match(summary,/<div class="v">1<\/div><div class="l">in Direct<\/div>/);
  assert.match(summary,/<div class="v">1<\/div><div class="l">in Transitive<\/div>/);
  assert.match(html,/<a class="exec-cve-link" href="#ch1">CVE-2099-2001<\/a>/);
  assert.match(html,/id="ch1"/);
 }
});

test('French current Debian candidates are escaped and excluded from confirmed finding counts',()=>{
 const {payload}=fixture(), image=payload.projectInfo.artifacts[0];
 image.advisoryObservations=[{source:'debian-security-tracker-current-candidates',cveId:'CVE-2099-9999',status:'possible',dep:{name:'pkg<script>',sourceName:'src<img>',sourceVersion:'1<2'},evidence:{releaseApplicability:'unknown',comparison:{operator:'<',installedVersion:'1<2',threshold:'2<script>'},contextReleases:[{releases:['bookworm<script>'],note:'<img src=x onerror=alert(1)>'}]}}];
 payload.cveMatches=[];
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render({...payload,locale:'fr'}),chapter=detailsById(html,'chimages');
  assert.match(chapter,/Vérifications complémentaires/);assert.match(chapter,/Potentiellement affecté/);
  assert.match(chapter,/Règle actuelle du paquet source/);assert.match(chapter,/Applicabilité à cette distribution hors support non établie/);
  assert.match(chapter,/exclues des compteurs de vulnérabilités/);assert.match(chapter,/CVE-2099-9999/);
  assert.match(chapter,/src&lt;img&gt;/);assert.match(chapter,/bookworm&lt;script&gt;/);assert.match(chapter,/&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(chapter,/<img src=x onerror=alert\(1\)>|src<img>|bookworm<script>/);
  assert.doesNotMatch(html,/class="cve-row/,'candidate must not create a confirmed CVE row');
  const raw=require('../lib/artifacts/report').renderArtifactEvidence(payload.projectInfo,'fr',[]);
  const overview=raw.match(/<table><thead>[\s\S]*?<\/thead><tbody>([\s\S]*?)<\/tbody><\/table>/)[1];
  assert.match(overview,/<td>1<\/td><td>0<\/td><td>0<\/td><td>0<\/td><td>0<\/td><td>0<\/td>/,'candidate is excluded from affected package, finding, CVE and advisory totals');
 }
});

test('image report has a mobile viewport and localises structured observation reasons',()=>{
 const {payload}=fixture(),image=payload.projectInfo.artifacts[0];
 image.advisoryObservations=[{source:'freexian-tracker',cveId:'CVE-2099-1111',status:'possible',reason:'The tracker release status applies to a different archive source version; applicability to the installed version is undetermined.',dep:{name:'pkg'},evidence:{releaseStatus:'open'}},{cveId:'CVE-2099-2222',status:'unknown',reason:'Upstream version range cannot be evaluated.',dep:{name:'other'},evidence:{versionRange:{}}}];
 const html=generateHtmlReport({...payload,locale:'fr'});assert.match(html,/<meta name="viewport" content="width=device-width, initial-scale=1">/);assert.match(html,/Le statut du suivi concerne une autre version source/);assert.match(html,/La plage de versions amont ne peut pas être évaluée/);assert.doesNotMatch(html,/Upstream version range cannot be evaluated/);
});

test('image declarations group all locations and show actual acquisition statuses with offline context',()=>{
 const refs=[
  {path:'compose.yml',line:2,reference:'registry.example/demo:1',role:'deployment',imageScan:{status:'scanned',artifactIds:['sha256:good']}},
  {path:'ci.yml',line:7,reference:'registry.example/demo:1',role:'ci',imageScan:{status:'scanned',artifactIds:['sha256:good']}},
  {path:'missing.yml',line:3,reference:'registry.example/missing:1',imageScan:{status:'failed',message:'HTTP 404'}},
  {path:'vars.yml',line:9,declared:'${IMAGE}',classification:'unresolved',unresolved:['IMAGE'],imageScan:{status:'not-scannable',reasonCode:'unresolved'}},
  {path:'build.yml',line:4,declared:'local',classification:'local-build',imageScan:{status:'not-scannable',reasonCode:'local-build'}}
 ];
 const artifacts=[{id:'sha256:good',metadata:{source:'demo'},components:[],coverage:[]}];
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const html=render({cveMatches:[],locale,projectInfo:{name:'image-status',provenance:{mode:'offline'},imageReferences:refs,artifacts}});
  assert.match(html,/compose\.yml:2/);assert.match(html,/ci\.yml:7/);assert.equal((html.match(/registry\.example\/demo:1/g)||[]).length,1);
  assert.match(html,/#image-[a-f0-9]{12}/);assert.match(html,/HTTP 404/);assert.match(html,/IMAGE/);assert.match(html,/Dockerfiles/);
  assert.doesNotMatch(html,/Reference only; image content not verified|Référence seule ; contenu de l.image non vérifié/);
  assert.match(html,locale==='fr'?/Récupération de l’image échouée/:/Image acquisition failed/);
  assert.match(html,locale==='fr'?/Variable non résolue/:/Unresolved variable/);
  assert.match(html,locale==='fr'?/Construction locale/:/Local build/);
 }
});
test('registry-resolved source definitions appear with digest evidence and platform',()=>{
 const {payload}=fixture(),artifact=payload.projectInfo.artifacts[0];artifact.metadata.definitions=[{path:'deploy/compose.yml',line:8,declared:'registry.example/demo:1',binding:'registry-reference-resolution',role:'deployment'}];
 payload.projectInfo.imageReferences=[{reference:'registry.example/demo:1',platform:'linux/arm64',path:'deploy/compose.yml',line:8,imageScan:{status:'scanned',artifactIds:[artifact.id]}}];
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const html=render({...payload,locale});assert.match(html,/linux\/arm64/);assert.match(html,/deploy\/compose\.yml:8/);
  assert.match(html,locale==='fr'?/référence de registre résolue vers l’empreinte analysée/:/registry reference resolved to the scanned digest/);
  assert.doesNotMatch(detailsById(html,artifactAnchor(artifact.id)),locale==='fr'?/Aucune déclaration source associée n’est disponible/:/No matching source declaration is available/);
 }
});

test('source and image executive summaries and charts stay separate for the same finding',()=>{
 const {payload}=fixture();
 const source=payload.cveMatches[2],image=payload.cveMatches[0];
 image.cve={...image.cve,id:'CVE-2099-2001',severity:'CRITICAL',cwes:['CWE-89']};
 source.cve={...source.cve,severity:'HIGH',cwes:['CWE-79']};
 image.findingId=source.findingId='same-finding';
 image.dep={...image.dep,ecosystem:source.dep.ecosystem,groupId:source.dep.groupId,artifactId:source.dep.artifactId,version:source.dep.version,coordKey:source.dep.coordKey};
 payload.cveMatches=[source,image];
 for(const render of [generateHtmlReport,generateWordReport]) {
  const html=render(payload), exec=html.slice(html.indexOf('<div class="exec-meta"'),html.indexOf('<div class="exec-rest"'));
  const sourceHeading=exec.indexOf('most critical · production findings'),imageHeading=exec.indexOf('most critical · images to update');
  assert.ok(sourceHeading>=0 && imageHeading>sourceHeading);
  const sourceBlock=exec.slice(sourceHeading,imageHeading),imageBlock=exec.slice(imageHeading);
  assert.match(sourceBlock,/CWE-79/);assert.doesNotMatch(sourceBlock,/CWE-89/);
  assert.match(imageBlock,/CWE-89/);assert.doesNotMatch(imageBlock,/CWE-79/);
  const split=html.indexOf('aria-label="Image overview charts"');assert.ok(split>0);
  const sourceCharts=html.slice(html.indexOf('aria-label="Overview charts"'),split),imageCharts=html.slice(split,html.indexOf('</section>',split));
  assert.match(sourceCharts,/CWE-79/);assert.doesNotMatch(sourceCharts,/CWE-89/);
  assert.match(imageCharts,/CWE-89/);assert.doesNotMatch(imageCharts,/CWE-79/);
 }
 const stats=require('../lib/cve-report').computeStats([source,image]);assert.equal(stats.direct,1);assert.equal(stats.total,2);
 const html=generateHtmlReport(payload),copy=html.slice(html.indexOf('<template class="exec-copy-rich">'),html.indexOf('</template>'));
 assert.match(copy,/production findings/);assert.match(copy,/images to update/);
});

test('an image scan with no image findings still renders its empty chart row',()=>{
 const {payload}=fixture();payload.cveMatches=payload.cveMatches.filter(m=>!m.dep.artifactTargetId);
 for(const render of [generateHtmlReport,generateWordReport]) {
  const html=render(payload),split=html.indexOf('aria-label="Image overview charts"');
  assert.ok(split>0);assert.match(html.slice(split,html.indexOf('</section>',split)),/No production CVE/);
 }
});

test('executive image ranking groups CVEs per image, orders by severity and uses only observed image updates',()=>{
 const {payload}=fixture(), first=payload.projectInfo.artifacts[0],second=payload.projectInfo.artifacts[1];
 first.imageUpdate={status:'available',targetTag:'v2',targetReference:'registry.example/app:v2'};
 second.imageUpdate={status:'unknown',targetReference:'unverified.example/should-not-appear',targetTag:'v3'};
 const image=payload.cveMatches[0],other=payload.cveMatches[1];
 payload.resolvedDeps=new Map([...payload.resolvedDeps].filter(([,d])=>d.artifactTargetId));
 payload.cveMatches=[
  ...['HIGH','CRITICAL','MEDIUM','LOW'].map((severity,i)=>({...image,cve:{id:`CVE-2099-${3000+i}`,severity},findingId:`first-${i}`})),
  {...other,cve:{id:'CVE-2099-4000',severity:'HIGH'}}
 ];
 for(const render of [generateHtmlReport,generateWordReport]) {
  const html=render(payload),start=html.indexOf('<div class="exec-meta"'),end=html.indexOf('<div class="exec-rest"');const exec=html.slice(start,end);
  assert.doesNotMatch(exec,/most critical · production findings|direct production dependencies/);
  assert.match(exec,/Top 2 most critical · images to update/);
  assert.ok(exec.indexOf('registry.example/app:v1')<exec.indexOf('other-image.tar'));
  assert.match(exec,/registry.example\/app:v2/);assert.doesNotMatch(exec,/unverified\.example/);
  for(const id of ['CVE-2099-3000','CVE-2099-3001','CVE-2099-3002','CVE-2099-4000'])assert.match(exec,new RegExp(id));
  assert.doesNotMatch(exec,/CVE-2099-3003/);
  assert.doesNotMatch(html,/aria-label="Overview charts"/);assert.match(html,/aria-label="Image overview charts"/);
 }
});

test('overview rows follow actual project and image scan evidence',()=>{
 const image={id:'image-empty',metadata:{source:'empty-image'}};
 const projectOnly={projectInfo:{name:'project'},parsedManifests:[{path:'/project/package-lock.json'}],cveMatches:[]};
 const mixed={...projectOnly,projectInfo:{name:'project',artifacts:[image]}};
 const noDescriptors={projectInfo:{name:'empty'},cveMatches:[]};
 const referenceOnly={projectInfo:{name:'reference',imageReferences:[{path:'compose.yml',declared:'example.org/image:1'}]},cveMatches:[]};
 for(const render of [generateHtmlReport,generateWordReport]) {
  const report=render(mixed);assert.match(report,/aria-label="Overview charts"/);assert.match(report,/aria-label="Image overview charts"/);
  for(const input of [projectOnly,noDescriptors,referenceOnly])assert.doesNotMatch(render(input),/aria-label="Image overview charts"/);
  assert.doesNotMatch(render(noDescriptors),/aria-label="Overview charts"/);
 }
});

test('overview totals include image findings from every input lane once',()=>{
 const {payload}=fixture();const source=payload.cveMatches[2],img=payload.cveMatches[0];
 payload.cveMatches=[source];payload.devCveMatches=[{...img,cve:{id:'CVE-2099-3001',severity:'MEDIUM'}}];
 payload.embeddedMatches=[{...img,dep:{...img.dep,artifactPath:'/another'},cve:{id:'CVE-2099-3002',severity:'CRITICAL'}}];
 payload.cveMatches.push(payload.devCveMatches[0]); // same physical occurrence in two input lanes
 for(const render of [generateHtmlReport,generateWordReport]) {
  const html=render(payload), summary=html.slice(html.indexOf('<div class="summary">'),html.indexOf('aria-label="Overview charts"'));
  assert.match(summary,/<div class="v">3<\/div><div class="l">Total CVEs<\/div>/);
  assert.match(summary,/<div class="v">2<\/div><div class="l">Image findings<\/div>/);
  assert.match(summary,/<div class="v">1<\/div><div class="l">Source findings<\/div>/);
  assert.match(summary,/<div class="v">1<\/div><div class="l">Critical<\/div>/);
  const exec=html.slice(html.indexOf('<div class="exec-rest"'),html.indexOf('<div class="summary">'));
  assert.match(exec,/<strong>3<\/strong> CVE findings/);assert.doesNotMatch(exec,/dev\/test CVE/);
 }
});

test('each image groups component sources and omits sub-dependencies without CVEs',()=>{
 const {ids,payload}=fixture(),first=payload.projectInfo.artifacts[0],second=payload.projectInfo.artifacts[1],finding=payload.cveMatches[0];
 const direct={ecosystem:'npm',name:'app',version:'1.0',imageRole:'direct',artifactTargetId:ids[0],artifactPath:'/app/package.json'};
 const vulnerable={ecosystem:'npm',name:'library',version:'2.0',imageRole:'transitive',artifactTargetId:ids[0],artifactPath:'/app/node_modules/library/package.json'};
 const clean={ecosystem:'npm',name:'clean-library',version:'3.0',imageRole:'transitive',artifactTargetId:ids[0],artifactPath:'/app/node_modules/clean-library/package.json'};
 const unknown={ecosystem:'npm',name:'unknown-role',version:'1.0',artifactTargetId:ids[0]};
 first.components=[direct,vulnerable,clean,unknown];first.componentCount=4;
 second.components=[{...vulnerable,artifactTargetId:ids[1]}];second.componentCount=1;
 payload.cveMatches=[{...finding,dep:vulnerable,cve:{id:'CVE-2099-3333',severity:'HIGH'}}];
 for(const [render,locale] of [[generateHtmlReport,'en'],[generateWordReport,'en'],[generateHtmlReport,'fr'],[generateWordReport,'fr']]) {
  const html=render({...payload,locale}),one=detailsById(html,artifactAnchor(ids[0])),two=detailsById(html,artifactAnchor(ids[1]));
  const directLabel=locale==='fr'?'Applications avec un descripteur racine':'Applications with a root descriptor';
  const subLabel=locale==='fr'?'Autres composants et sous-dépendances':'Other components and sub-dependencies';
  const d=one.indexOf(directLabel),s=one.indexOf(subLabel);
  assert.ok(d>=0&&s>d);
  assert.match(one.slice(d,s),/>app<\/code>/);
  assert.doesNotMatch(one,/clean-library/);
  assert.match(one.slice(s),/>library<\/code>/);
  assert.match(one.slice(s),new RegExp(`href="#${artifactAnchor(ids[0])}-cves">CVE-2099-3333`));
  assert.doesNotMatch(two,/CVE-2099-3333|>library<\/code>/);assert.match(one,/unknown-role/);
 }
});

test('a designated image header uses its archive name and a project scan retains its project header',()=>{
 const {payload}=fixture();
 payload.projectInfo.src='(artifact inventory)';
 payload.projectInfo.artifacts=payload.projectInfo.artifacts.slice(0,1);
 payload.projectInfo.artifacts[0].metadata={source:'/auditor/exports/release.tar',format:'docker'};
 const header=()=>generateHtmlReport(payload).match(/<header class="report-header">([\s\S]+?)<\/header>/)[1];
 assert.match(header(),/Audit target\s*<strong>release\.tar<\/strong>/);
 assert.doesNotMatch(header(),/auditor\/exports/);
 payload.projectInfo.src='/project';payload.projectInfo.name='dashboard';
 assert.match(header(),/Project:\s*<strong>dashboard<\/strong>/);
});
