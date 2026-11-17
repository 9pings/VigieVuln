'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {buildFindings}=require('../lib/json-export');
const {generateHtmlReport,generateWordReport}=require('../lib/cve-report');

test('image OS files without advisories stay out of reports and source unmanaged counts',()=>{
 const image='example-image';
 const component=(name,extra={})=>({name,version:'1',ecosystem:'binary',provenance:'binary',coordKey:`${image}:${name}`,artifactTargetId:image,artifactPath:`/usr/lib/${name}`,manifestPaths:[`/usr/lib/${name}`],hashes:{sha256:'a'.repeat(64)},...extra});
 const clean=component('unaffected-system-library.so');
 const affected=component('affected-system-library.so');
 const advisory=component('advisory-only-package',{ecosystem:'system',packageType:'deb',provenance:'installed'});
 const os=component('unaffected-os-package',{ecosystem:'system',packageType:'deb',provenance:'installed'});
 const jar=component('unaffected-image-archive',{ecosystem:'maven',provenance:'embedded',groupId:'org.example',artifactId:'unaffected-image-archive'});
 const source={...component('project-native.so'),artifactTargetId:undefined,coordKey:'project-binary',manifestPaths:['/project/project-native.so']};
 const components=[clean,affected,advisory,os,jar];
 const artifacts=[{id:image,kind:'oci-image',componentCount:components.length,components,metadata:{source:'example:1'},coverage:[]}];
 const matches=[{dep:affected,cve:{id:'CVE-2025-12345',severity:'HIGH'},source:'osv'},
  {dep:advisory,advisoryId:'DLA-1234-1',cve:{id:'DLA-1234-1',severity:'UNKNOWN',summary:'Distribution advisory'},source:'osv'}];
 const before=JSON.stringify(artifacts);
 const payload={cveMatches:matches,resolvedDeps:new Map([...components,source].map(d=>[d.coordKey,d])),projectInfo:{name:'mixed',src:'/project',artifacts}};
 const json=buildFindings(payload);
 assert.equal(json.summary.unmanaged,1);assert.equal(json.unmanaged[0].declaredName,'project-native.so');assert.equal(json.embedded.length,0);
 assert.deepEqual(json.artifacts[0].components.map(d=>d.name),[affected.name,advisory.name]);
 assert.equal(json.artifacts[0].componentCount,5);assert.equal(json.artifacts[0].componentDetailsFiltered,true);assert.equal(json.cve.length,2);
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload);
  for(const hidden of [clean,os,jar])assert.ok(!html.includes(hidden.name),hidden.name);
  assert.match(html,/affected-system-library\.so/);assert.match(html,/DLA-1234-1/);assert.match(html,/project-native\.so/);
 }
 assert.equal(JSON.stringify(artifacts),before,'report projection never removes data from the scan inventory');
});
