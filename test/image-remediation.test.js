'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {renderArtifactEvidence}=require('../lib/artifacts/report');
const id='oci:sha256:'+'a'.repeat(64);
const artifact={id,kind:'oci',metadata:{source:'registry.example/app:old',digest:'sha256:'+'a'.repeat(64),configDigest:'sha256:'+'b'.repeat(64),platform:{os:'linux',architecture:'amd64'},definitions:[{path:'compose.yml',line:12,binding:'manifest-digest'},{path:'unverified.yml',line:9}]},components:[],coverage:[]};
const matches=[{dep:{ecosystem:'system',name:'libfoo',version:'1',artifactTargetId:id},advisoryId:'DLA-1000-1',cve:{id:'DLA-1000-1',upstream:['CVE-2024-12345'],fixVersion:'2'}}];
test('image remediation proposes image replacement, with package detail secondary and no invented target',()=>{
 const html=renderArtifactEvidence({artifacts:[artifact]},'en',matches);
 assert.match(html,/Recommended image action/);assert.match(html,/publisher-provided image/);assert.match(html,/rebuild it from a corrected base and packages/);assert.match(html,/Scan the replacement image/);
 assert.match(html,/No replacement tag or digest has been verified/);assert.match(html,/Current manifest digest/);assert.match(html,/Configuration digest/);assert.match(html,/linux\/amd64/);assert.match(html,/compose\.yml:12/);
 const action=html.slice(html.indexOf('Recommended image action'),html.indexOf('Coverage information unavailable'));assert.doesNotMatch(action,/unverified\.yml/);
 assert.match(html,/<details class="report-subsection"><summary><h4>Component inventory and candidate corrections/);assert.match(html,/<code>libfoo<\/code>/);assert.match(html,/From finding; not present in inventory/);assert.match(html,/<td>2<\/td><td><a href="https:\/\/www\.vigievuln\.fr\/advisory\/osv\/DLA-1000-1">DLA-1000-1<\/a>/);assert.doesNotMatch(html,/patch (?:the )?running container/i);
});
test('image remediation stays conditional without a linked source and is localized',()=>{
 const a={...artifact,metadata:{source:'image.tar'}};const html=renderArtifactEvidence({artifacts:[a]},'fr',matches);
 assert.match(html,/Action recommandée sur l’image/);assert.match(html,/Aucune déclaration source associée/);assert.match(html,/Aucun tag ni empreinte de remplacement/);assert.match(html,/Inventaire des composants et corrections proposées/);
 const clean=renderArtifactEvidence({artifacts:[a]},'en',[]);assert.match(clean,/consult scan coverage/);assert.doesNotMatch(clean,/For a publisher-provided image/);
});

test('partial inventory retains unmatched findings without duplicating known components',()=>{
 const partial={...artifact,components:[{ecosystem:'system',name:'known',version:'1'}]};
 const known={dep:{ecosystem:'system',name:'known',version:'1',artifactTargetId:id},advisoryId:'DLA-1000-2',cve:{id:'DLA-1000-2',fixVersion:'3'}};
 const html=renderArtifactEvidence({artifacts:[partial]},'en',[...matches,known]);
 const table=html.slice(html.indexOf('<table class="image-inventory">'));
 assert.equal((table.match(/<code>known<\/code>/g)||[]).length,1);
 assert.match(html,/<code>libfoo<\/code>[\s\S]*?From finding; not present in inventory[\s\S]*?<td>2<\/td>/);
 assert.match(html,/<code>known<\/code>[\s\S]*?<td>3<\/td>/);
});

test('inventory lists affected components and their advisories even without a candidate fix',()=>{
 const a={...artifact,components:[{ecosystem:'system',name:'clean',version:'1'}]};
 const match={dep:{ecosystem:'system',name:'unfixed',version:'1',artifactTargetId:id},cve:{id:'CVE-2099-9999',severity:'HIGH'}};
 const html=renderArtifactEvidence({artifacts:[a]},'en',[match]),table=html.slice(html.indexOf('<table class="image-inventory">'));
 assert.match(table,/<code>unfixed<\/code>/);
 assert.doesNotMatch(table,/<code>clean<\/code>/);
 assert.match(table,/From finding; not present in inventory/);
 assert.match(table,/<td>—<\/td><td><a href="https:\/\/www\.vigievuln\.fr\/cve\/CVE-2099-9999">CVE-2099-9999<\/a>/);
});
