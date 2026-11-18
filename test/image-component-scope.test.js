'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {acquireInventories,assessInventories}=require('../lib/artifacts/scan');
const {isNpmPackageDescriptor}=require('../lib/artifacts/component-scope');

test('only installed npm package roots are descriptors, including nested and scoped CLI packages',()=>{
 for(const p of ['app/package.json','usr/lib/node_modules/npm/package.json','node_modules/a/node_modules/b/package.json','node_modules/@scope/tool/package.json','node_modules/.pnpm/tool@1/node_modules/tool/package.json','C:\\root\\node_modules\\tool\\package.json'])assert.equal(isNpmPackageDescriptor(p),true,p);
 for(const p of ['node_modules/tool/dist/mjs/package.json','node_modules/tool/test/package.json','node_modules/.cache/package.json','node_modules/@scope/tool/dist/package.json'])assert.equal(isNpmPackageDescriptor(p),false,p);
});

test('images retain main components and installed libraries without expanding declared dependencies',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-image-components-')),root=path.join(dir,'root'),cacheDir=path.join(dir,'cache');
 t.after(()=>{require('../lib/cache-db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});
 const put=(p,text)=>{const f=path.join(root,p);fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,text);};
 put('app/package.json',JSON.stringify({name:'image-app',version:'1.0.0',dependencies:{'not-installed':'9.9.9'}}));
 put('app/package-lock.json',JSON.stringify({lockfileVersion:3,packages:{'node_modules/also-not-installed':{version:'9.9.9'}}}));
 put('usr/local/lib/node_modules/tool/package.json',JSON.stringify({name:'tool',version:'2.0.0',bin:{tool:'cli.js'},dependencies:{'not-installed':'9.9.9'}}));
 put('usr/local/lib/node_modules/tool/node_modules/child-tool/package.json',JSON.stringify({name:'child-tool',version:'3.0.0',bin:{child:'cli.js'}}));
 put('usr/local/lib/node_modules/tool/node_modules/child-tool/dist/mjs/package.json','{"type":"module"}');
 put('usr/local/lib/node_modules/tool/fixtures/package.json','{"name":"fixture","version":"99.0.0"}');
 put('app/dist/mjs/package.json','{"type":"module"}');
 put('php/composer.json','{"name":"example/app","version":"1.2.3","require":{"absent/library":"1.0.0"}}');
 put('php/vendor/composer/installed.json','{"packages":[{"name":"example/library","version":"4.0.0"}]}');
 put('php/vendor/example/library/composer.json','{"name":"example/library"}');
 put('python/pyproject.toml','[project]\nname="python-app"\nversion="1.0.0"\ndependencies=["not-installed==9.9.9"]');
 put('java/pom.xml','<project><groupId>example</groupId><artifactId>java-app</artifactId><version>1.0.0</version><dependencies><dependency><groupId>missing</groupId><artifactId>lib</artifactId><version>9.9.9</version></dependency></dependencies></project>');
 const [target]=await acquireInventories(root,{offline:true});
 assert.equal(target.warnings.filter(w=>w.reason==='installed-metadata-error').length,0,JSON.stringify(target.warnings));
 assert.deepEqual(target.deps.map(d=>d.name).sort(),['image-app','tool','child-tool','app','library','python-app','java-app'].sort());
 for(const dep of target.deps)assert.equal(dep.imageRole,['tool','child-tool','library'].includes(dep.name)?'transitive':'direct',dep.name);
 assert.equal(target.metadata.componentScope,'image-components/1');
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir}),now=Date.now(),advisory={id:'CVE-2024-12345',affected:[{package:{ecosystem:'npm',name:'child-tool'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'4.0.0'}]}]}]};
 store.commit({records:[{source:'osv',document:advisory,fetchedAt:now}],queries:[{source:'osv',ecosystem:'npm',name:'child-tool',version:'3.0.0',ids:[advisory.id],fetchedAt:now,complete:true}]});store.close();
 const assessed=await assessInventories([target],{cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[],fetcher:()=>assert.fail('network')});
 const finding=assessed.cveMatches.find(m=>m.cve.id===advisory.id);assert.ok(finding);assert.equal(finding.dep.imageRole,'transitive');assert.equal(finding.dep.artifactTargetId,target.id);
 const components=assessed.artifacts[0].components;assert.equal(components.length,7);assert.equal(components.find(c=>c.name==='child-tool').imageRole,'transitive');
 const {reportArtifacts}=require('../lib/artifacts/report-inventory');
 assert.equal(reportArtifacts(assessed.artifacts,assessed.cveMatches)[0].components.length,7);
});

test('classified image libraries remain in JSON without a CVE, including OS-owned components',()=>{
 const {reportArtifacts}=require('../lib/artifacts/report-inventory');
 const components=[{ecosystem:'binary',name:'app',imageRole:'direct'},{ecosystem:'npm',name:'tool',imageRole:'transitive',osPackageOwners:[{name:'npm'}]}];
 const [result]=reportArtifacts([{id:'img',components}],[]);assert.deepEqual(result.components,[components[1]]);assert.equal(result.componentDetailsFiltered,true);assert.equal(result.componentCount,2);
});
