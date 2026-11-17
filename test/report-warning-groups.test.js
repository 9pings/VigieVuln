'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {groupReportWarnings}=require('../lib/report-notices');
const {generateHtmlReport,generateWordReport}=require('../lib/cve-report');

test('warning groups retain locations and distinguish sources and HTTP causes',()=>{
 const base={type:'image-scan-failed',reason:'image-acquisition-failed',cause:'HTTP 503',message:'Registry HTTP 503'};
 const warnings=[{...base,manifestPath:'/project/a.yml'},{...base,manifestPath:'/project/b.yml'},
  {...base,cause:'HTTP 401',message:'Authentication required'},
  {type:'source-unavailable',source:'osv',message:'HTTP 503'},
  {type:'source-unavailable',source:'euvd',message:'HTTP 503'}];
 const grouped=groupReportWarnings(warnings);
 assert.equal(grouped.length,4);assert.equal(grouped[0].count,2);
 assert.deepEqual(grouped[0].items.map(x=>x.id),['/project/a.yml','/project/b.yml']);
 assert.deepEqual(groupReportWarnings(grouped),grouped);
 assert.equal(warnings[0].count,undefined);
});

test('HTML and Word collapse repeated alerts without dropping locations or exposing absolute paths',()=>{
 const warnings=Array.from({length:60},(_,i)=>({type:'image-scan-failed',reason:'image-acquisition-failed',cause:'HTTP 503',manifestPath:`/project/module-${i}/compose.yml`,message:'Registry returned HTTP 503 <retry>'}));
 warnings.push({type:'dependency-coverage',severity:'info',reason:'image-content-unverified',message:'ordinary reference context'});
 const input={cveMatches:[],eolResults:[],obsoleteResults:[],outdatedResults:[],resolvedDeps:new Map(),projectInfo:{name:'fixture',src:'/project'},warnings};
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(input);
  assert.equal((html.match(/class="warn-block warn-image-scan-failed"/g)||[]).length,1);
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
 assert.equal((alerts.match(/class="warn-block warn-source-unavailable"/g)||[]).length,1);
});
