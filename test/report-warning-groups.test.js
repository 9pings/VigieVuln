'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {groupReportWarnings}=require('../lib/reports/notices');
const {generateHtmlReport,generateWordReport}=require('../lib/reports/cve-report');

test('warning groups retain locations and distinguish sources and HTTP causes',()=>{
 const base={type:'image-scan-failed',reason:'image-acquisition-failed',cause:'HTTP 503',message:'Registry HTTP 503'};
 const warnings=[{...base,manifestPath:'/project/a.yml'},{...base,manifestPath:'/project/b.yml'},
  {...base,cause:'HTTP 401',message:'Authentication required'},
  {type:'source-unavailable',source:'osv',message:'HTTP 503'},
  {type:'source-unavailable',source:'euvd',message:'HTTP 503'}];
 const grouped=groupReportWarnings(warnings);
 assert.equal(grouped.length,3);const images=grouped.find(w=>w.type==='image-source-unavailable');
 assert.deepEqual(images.items.map(x=>x.id),['/project/a.yml','/project/b.yml','']);
 assert.ok(images.items.some(x=>/Authentication required/.test(x.detail)));
 assert.deepEqual(groupReportWarnings(grouped),grouped);
 assert.equal(warnings[0].count,undefined);
});

test('HTML and Word collapse repeated alerts without dropping locations or exposing absolute paths',()=>{
 const warnings=Array.from({length:60},(_,i)=>({type:'image-scan-failed',reason:'image-acquisition-failed',cause:'HTTP 503',manifestPath:`/project/module-${i}/compose.yml`,message:'Registry returned HTTP 503 <retry>'}));
 warnings.push({type:'dependency-coverage',severity:'info',reason:'image-content-unverified',message:'ordinary reference context'});
 const input={cveMatches:[],eolResults:[],obsoleteResults:[],outdatedResults:[],resolvedDeps:new Map(),projectInfo:{name:'fixture',src:'/project'},warnings};
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(input);
  assert.equal((html.match(/class="warn-block warn-image-source-unavailable"/g)||[]).length,1);
  if(render===generateHtmlReport)assert.match(html,/<details class="warning-details">/);
  assert.match(html,/module-59\/compose.yml/);
  assert.doesNotMatch(html,/\/project\/module-/);
  assert.match(html,/HTTP 503 &lt;retry&gt;/);
  assert.doesNotMatch(html,/warn-block warn-dependency-coverage/);
 }
});

test('one source outage across images keeps every affected image in the grouped detail',()=>{
 const warnings=['image-a','image-b'].map(artifactTargetId=>({type:'source-unavailable',source:'osv',artifactTargetId,message:'HTTP 503'}));
 const groups=groupReportWarnings(warnings);
 assert.equal(groups.length,1);assert.deepEqual(groups[0].artifactTargetIds,['image-a','image-b']);
 assert.deepEqual(groups[0].items.map(x=>x.artifactTargetId),['image-a','image-b']);
 const projectInfo={name:'fixture',artifacts:['image-a','image-b'].map((id,i)=>({id,kind:'oci-image',metadata:{acquisition:{reference:`registry.example/app-${i}:1`}},components:[],coverage:[]}))};
 const html=generateHtmlReport({cveMatches:[],eolResults:[],obsoleteResults:[],outdatedResults:[],resolvedDeps:new Map(),projectInfo,warnings});
 const alerts=html.slice(html.indexOf('class="warnings warnings-chapter"'),html.indexOf('class="warnings warnings-chapter"')+2000);
 assert.match(alerts,/registry.example\/app-0:1/);assert.match(alerts,/registry.example\/app-1:1/);
 assert.equal((alerts.match(/class="warn-block warn-image-source-unavailable"/g)||[]).length,1);
});

test('project, image and shared-source warnings stay separate for identical causes',()=>{
 const reason='binary-scan-error',message='Cannot inspect binary';
 const warnings=[
  {type:'dependency-coverage',reason,message,manifestPath:'/project/src/app'},
  {type:'dependency-coverage',reason,message,artifactTargetId:'image-a',manifestPath:'usr/bin/tool'},
  {type:'dependency-coverage',reason,message,artifactTargetId:'image-b',manifestPath:'opt/app/tool'},
  {type:'source-unavailable',source:'osv',artifactTargetId:'image-a',message:'HTTP 503'},
  {type:'image-scan-failed',artifactTargetId:'image-b',message:'Registry HTTP 503'},
  {type:'cve-enrichment-summary',severity:'warning',affectsCompleteness:false,artifactTargetIds:['image-a'],message:'CVE record enrichment is incomplete.'},
 ];
 const groups=groupReportWarnings(warnings), scoped=groups.filter(w=>w.type==='dependency-coverage');
 assert.equal(scoped.length,2);assert.equal(scoped.find(w=>!w.artifactTargetIds?.length).manifestPath,'/project/src/app');
 const images=scoped.find(w=>w.artifactTargetIds?.length);assert.deepEqual(images.artifactTargetIds,['image-a','image-b']);
 assert.ok(images.items.some(x=>x.manifestPaths?.includes('usr/bin/tool')));assert.ok(images.items.some(x=>x.manifestPaths?.includes('opt/app/tool')));
 assert.equal(groups.filter(w=>w.type==='image-source-unavailable').length,1);
 const projectInfo={name:'fixture',src:'/project',artifacts:['image-a','image-b'].map(id=>({id,kind:'oci-image',metadata:{source:id},components:[],coverage:[]}))};
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const report=render({cveMatches:[],projectInfo,warnings,locale});
  const block=report.slice(report.indexOf('class="warnings warnings-chapter"'),report.indexOf('</section>',report.indexOf('class="warnings warnings-chapter"'))+10);
  const p=report.indexOf('class="warning-scope warning-scope-project"'),i=report.indexOf('class="warning-scope warning-scope-image"'),g=report.indexOf('class="warning-scope warning-scope-global"');
  assert.ok(p>=0 && i>p && g>i);
  assert.match(block,locale==='fr'?/Avertissements de l’analyse du projet/:/Project scan warnings/);
  const project=report.slice(p,i),image=report.slice(i,g),shared=report.slice(g,report.indexOf('</section>',g));
  assert.match(project,/src\/app/);assert.doesNotMatch(project,/usr\/bin\/tool|opt\/app\/tool/);
  assert.match(image,/usr\/bin\/tool/);assert.match(image,/opt\/app\/tool/);assert.doesNotMatch(image,/src\/app/);
  assert.match(image,locale==='fr'?/Avertissements de l’analyse des images/:/Image scan warnings/);
  assert.equal((image.match(/warn-block warn-image-source-unavailable/g)||[]).length,1);
  assert.match(shared,locale==='fr'?/Avertissements des sources communes/:/Shared source warnings/);
  assert.equal((report.match(/warn-block warn-cve-enrichment-summary/g)||[]).length,1);
 }
});

test('warning grouping uses explicit image identifiers even without an individual target id',()=>{
 const grouped=groupReportWarnings([
  {type:'dependency-coverage',reason:'same',message:'same',artifactTargetIds:['a']},
  {type:'dependency-coverage',reason:'same',message:'same'},
 ]);
 assert.equal(grouped.length,2);assert.equal(require('../lib/reports/notices').warningScope(grouped[0]),'image');assert.equal(require('../lib/reports/notices').warningScope(grouped[1]),'project');
 const unavailable=groupReportWarnings([{type:'source-unavailable',source:'osv',message:'HTTP 503',artifactTargetIds:['a','b']}]);
 assert.equal(unavailable.length,1);assert.equal(unavailable[0].type,'image-source-unavailable');assert.deepEqual(unavailable[0].artifactTargetIds,['a','b']);
 assert.deepEqual(groupReportWarnings(unavailable),unavailable);
});

test('unpinned images are translated image warnings, not failures or CVEs, in HTML and Word',()=>{
 const warnings=require('../lib/images/references').unpinnedImageWarnings([{reference:'nginx:stable-alpine',path:'Dockerfile',line:3}]);
 assert.equal(require('../lib/reports/notices').warningScope(warnings[0]),'image');assert.deepEqual(groupReportWarnings(warnings),warnings);
 const input={cveMatches:[],eolResults:[],obsoleteResults:[],outdatedResults:[],resolvedDeps:new Map(),projectInfo:{name:'fixture',imageReferences:[{reference:'nginx:stable-alpine'}]},warnings};
 for(const render of [generateHtmlReport,generateWordReport])for(const locale of ['en','fr']){
  const html=render({...input,locale});assert.match(html,/warn-image-unpinned/);assert.match(html,/nginx:stable-alpine/);assert.match(html,/Dockerfile:3/);assert.match(html,/@sha256:&lt;digest&gt;/);
  assert.match(html,locale==='fr'?/Références d’images sans digest/:/Image references without a digest/);assert.doesNotMatch(html,/warn-image-source-unavailable/);
 }
});
