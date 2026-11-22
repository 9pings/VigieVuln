'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {acquireInventories,assessInventories}=require('../lib/artifacts/scan');
const {isNpmPackageDescriptor}=require('../lib/artifacts/component-scope');

test('image sources distinguish global roots, project descriptors, nested libraries and OS ownership',()=>{
 const {imageComponentSource:source,imageComponentRole:role}=require('../lib/artifacts/component-scope');
 const dep=(ecosystem,artifactPath,extra={})=>({ecosystem,artifactPath,...extra});
 const cases=[
  [dep('system','var/lib/dpkg/status',{manager:'dpkg'}),'system'],
  [dep('npm','usr/local/lib/node_modules/@scope/tool/package.json'),'global'],
  [dep('npm','root/.nvm/versions/node/v24.0.0/lib/node_modules/tool/package.json'),'global'],
  [dep('npm','usr/local/lib/node_modules/tool/node_modules/child/package.json'),'other'],
  [dep('npm','app/node_modules/tool/package.json'),'other'],
  [dep('npm','srv/dedicated-app/package.json'),'project'],
  [dep('pypi','usr/local/lib/python3.12/site-packages/tool.dist-info/METADATA'),'global'],
  [dep('pypi','app/.venv/lib/python3.12/site-packages/tool.dist-info/METADATA'),'other'],
  [dep('ruby','var/lib/gems/3.1.0/specifications/tool.gemspec'),'global'],
  [dep('composer','root/.config/composer/vendor/composer/installed.json'),'global'],
  [dep('composer','srv/php/composer.json',{installEvidence:{source:'composer-project'}}),'project'],
  [dep('npm','usr/share/nodejs/tool/package.json',{osPackageOwners:[{manager:'dpkg'}]}),'system'],
  [dep('npm','app/dist/vendor.js',{installEvidence:{source:'retire'}}),'vendored'],
  [dep('maven','app.jar!/lib/tool.jar'),'other'],
  [dep('npm',null,{provenance:'sbom'}),'other'],
 ];
 for(const [d,category] of cases)assert.equal(source(d).category,category,d.artifactPath);
 assert.equal(role(cases[1][0]),'direct');assert.equal(role(cases[3][0]),'transitive');
});

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
 for(const dep of target.deps)assert.equal(dep.imageRole,['child-tool','library'].includes(dep.name)?'transitive':'direct',dep.name);
 assert.equal(target.metadata.componentScope,'image-components/2');
 const store=require('../lib/advisory-store').openAdvisoryStore({cacheDir}),now=Date.now(),advisory={id:'CVE-2024-12345',affected:[{package:{ecosystem:'npm',name:'child-tool'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'4.0.0'}]}]}]};
 store.commit({records:[{source:'osv',document:advisory,fetchedAt:now}],queries:[{source:'osv',ecosystem:'npm',name:'child-tool',version:'3.0.0',ids:[advisory.id],fetchedAt:now,complete:true}]});store.close();
 const assessed=await assessInventories([target],{cacheDir,offline:true,disableCveProject:true,disableGcve:true,enrich:[],fetcher:()=>assert.fail('network')});
 const finding=assessed.cveMatches.find(m=>m.cve.id===advisory.id);assert.ok(finding);assert.equal(finding.dep.imageRole,'transitive');assert.equal(finding.dep.artifactTargetId,target.id);
 const components=assessed.artifacts[0].components;assert.equal(components.length,7);assert.equal(components.find(c=>c.name==='child-tool').imageRole,'transitive');
 const {reportArtifacts}=require('../lib/artifacts/report-inventory');
 assert.equal(reportArtifacts(assessed.artifacts,assessed.cveMatches)[0].components.length,6);
});

test('image sub-dependencies without a CVE are omitted from the report projection',()=>{
 const {reportArtifacts}=require('../lib/artifacts/report-inventory');
 const components=[{ecosystem:'binary',name:'app',imageRole:'direct'},{ecosystem:'npm',name:'tool',imageRole:'transitive',osPackageOwners:[{name:'npm'}]}];
 const [result]=reportArtifacts([{id:'img',components}],[]);assert.deepEqual(result.components,[]);assert.equal(result.componentDetailsFiltered,true);assert.equal(result.componentCount,2);
});
