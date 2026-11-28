'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const {parseDocument,DomUtils} = require('htmlparser2');
const {generateHtmlReport} = require('../lib/reports/cve-report');

function fixture() {
  const id = 'host';
  const apps = [{id:'a',type:'wordpress',root:'srv/news'},{id:'b',type:'project',root:'srv/web'}];
  function component(name,section,owners,imageRole='direct') {
    return {name,version:'1.0',artifactTargetId:id,coordKey:name,systemSection:section,
      systemApplicationIds:owners,imageRole,ecosystem:'npm',artifactPath:name+'/package.json'};
  }
  const parts = [component('web-direct','project',['b']),component('web-indirect','dependency',['b'],'transitive'),
    component('php','runtime',[]),component('shared-lib','dependency',[],'transitive')];
  const host = {id,kind:'rootfs',distribution:{name:'Debian'},metadata:{format:'directory',source:'/disques/serveur.vhdx',diskFormat:'vhdx',
    systemApplications:{applications:apps,inventory:[{kind:'core',name:'WordPress',version:'6.6.2',applicationId:'a',path:'srv/news'}]}},
    components:parts,coverage:[]};
  const core = {...component('wordpress','project',['a']),provenance:'application'};
  return {locale:'fr',projectInfo:{name:'snapshot',artifacts:[host],imageReferences:[{reference:'cache:1',path:'compose.yaml'}]},
    cveMatches:[...parts,core].map((dep,i)=>({dep,source:'osv',applicationIds:dep.systemApplicationIds,
      cve:{id:'CVE-2026-'+(1000+i),severity:'HIGH',score:7}}))};
}
function tempCache(t) {
  const fs=require('node:fs'), path=require('node:path');
  const dir=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'vv-maintenance-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return dir;
}
const contents = node => DomUtils.textContent(node);
const byId = (doc,id) => DomUtils.getElementById(id,doc.children);
const sections = node => node.children.filter(n=>n.name==='details');

test('system report attributes each finding to its project relationship or to the host, with no container chapter by default',()=>{
  const doc=parseDocument(generateHtmlReport(fixture()));
  const cve=byId(doc,'chcve'), host=byId(doc,'chhost');
  const ordered=sections(cve.children.find(c=>c.name==='div'));
  assert.equal(ordered[0],host);
  const apps=ordered.slice(1);
  assert.match(contents(host.children.find(n=>n.name==='summary')),/^1\.1 Système hôte/);
  assert.match(contents(apps[0].children.find(n=>n.name==='summary')),/^1\.2 /);
  assert.equal(apps.length,2);
  assert.match(contents(apps[0]),/WordPress.*6\.6\.2.*srv\/news/s);
  assert.match(contents(apps[0]),/CVE-2026-1004/);
  assert.doesNotMatch(contents(apps[0]),/CVE-2026-100[0-3]/);
  assert.match(contents(apps[1]),/Dépendances directes \(1\).*CVE-2026-1000.*Dépendances transitives \(1\).*CVE-2026-1001/s);
  assert.doesNotMatch(apps.map(contents).join(''),/CVE-2026-100[23]/);
  assert.match(contents(host),/serveur\.vhdx.*Interpréteurs, applications et services.*php.*CVE-2026-1002.*Dépendances du système \(transitives\).*CVE-2026-1003/s);
  assert.doesNotMatch(contents(host),/CVE-2026-100[014]/);
  assert.equal(byId(doc,'chimages'),null);
});

test('only requested container inspection produces the Images chapter, including empty inspection and separate container results',()=>{
  const payload=fixture();
  const host=payload.projectInfo.artifacts[0];
  host.metadata.inspectLocalImages=true;
  assert.match(contents(byId(parseDocument(generateHtmlReport(payload)),'chimages')),/Aucune image supplémentaire/);
  const image={id:'other',kind:'docker',metadata:{source:'web.tar',format:'docker'},components:[],coverage:[]};
  payload.projectInfo.artifacts.push(image);
  payload.cveMatches.push({dep:{name:'container-component',artifactTargetId:'other',coordKey:'other',ecosystem:'npm',version:'1.0'},source:'osv',
    cve:{id:'CVE-2026-1099',severity:'HIGH',score:7}});
  image.productInventory = {entries: [], unobserved: []};
  payload.cveMatches.push({dep:{name:'runtime',artifactTargetId:'other',coordKey:'runtime',ecosystem:'npm',version:'2.0'},
    source:'osv',cve:{id:'CVE-2026-1100',severity:'LOW',score:3}});
  const doc=parseDocument(generateHtmlReport(payload)), body=contents(byId(doc,'chimages'));
  const ordered=sections(byId(doc,'chcve').children.find(c=>c.name==='div'));
  assert.deepEqual(ordered.map(s=>s.attribs.id),['chhost','system-app-0','system-app-1','chimages']);
  const cards = sections(byId(doc, 'chimages-cves'));
  assert.equal(cards.length, 1);
  const cardBody = cards[0].children.find(child => child.name === 'div');
  const lastSection = sections(cardBody).at(-1);
  assert.match(contents(cardBody), /Détection des interpréteurs/);
  assert.equal(cardBody.children.filter(n=>n.type==='tag').at(-1),lastSection);
  assert.match(contents(lastSection), /Inventaire des composants et corrections proposées/);
  assert.equal(lastSection.attribs.open, undefined);
  const tables=DomUtils.findAll(n=>n.name==='table' && n.attribs.class==='image-inventory',lastSection.children);
  assert.equal(tables.reduce((n,table)=>n+DomUtils.findOne(node=>node.name==='tbody',table.children).children.filter(row=>row.name==='tr').length,0),2);
  const lists=DomUtils.findAll(n=>n.name==='details' && n.attribs['data-image-source'],cardBody.children);
  assert.ok(lists.length && lists.every(n=>Object.hasOwn(n.attribs,'open')));
  assert.match(lists.map(contents).join(''),/CVE-2026-1099/);
  for (const component of sections(lastSection)) assert.equal(component.attribs.open, undefined);
  assert.match(body,/web\.tar/);
  assert.match(body,/CVE-2026-1099/);
  assert.doesNotMatch(body,/serveur\.vhdx|CVE-2026-100[0-4]/);
});

test('system and source reports use the same CMS owner groups, synthesis, controls and standard chapters',()=>{
  const payload=fixture(), app=payload.projectInfo.artifacts[0].metadata.systemApplications;
  const module={id:'module',applicationId:'a',kind:'plugin',name:'Example',version:'1.1',visibility:'private',path:'srv/news/wp-content/plugins/example'};
  app.inventory.push(module);
  const finding=payload.cveMatches.at(-1);
  Object.assign(finding,{ownerComponentIds:['module'],applicationRelation:'indirect'});
  const normal=parseDocument(generateHtmlReport({locale:'fr',projectInfo:{name:'news'},applications:[app.applications[0]],applicationInventory:app.inventory,
    cveMatches:[{...finding,dep:{...finding.dep,artifactTargetId:undefined}}]}));
  const system=parseDocument(generateHtmlReport(payload));
  const outline=n=>DomUtils.findAll(e=>e.name==='h3'||e.name==='h4',n.children).map(contents);
  const expected=outline(byId(normal,'chapps')).filter(t=>!t.includes('CMS & frameworks') && !t.startsWith('wordpress ·'));
  const actual=outline(byId(system,'system-app-0'));
  for(const title of expected) assert.ok(actual.includes(title),title);
  assert.match(actual.join(' '),/plugin Example 1.1/);
  for(const id of ['chbin','chmaint','ch4','ch5','ch6','ch7','ch8','chscan','chsrc','chexcl','chmethod','chappinv']) {
    assert.equal(byId(system,id).name,'details',id);
    assert.ok(DomUtils.findOne(e=>e.name==='a' && e.attribs.href==='#'+id,system.children),id);
  }
  for(const action of ['expand-all','collapse-all','expand-cves','collapse-cves'])
    assert.ok(DomUtils.findOne(e=>e.attribs?.['data-action']===action,system.children));
});

test('public themes share tables, private modules have individual scopes, and inventories start closed',()=>{
  const payload=fixture();
  const host=payload.projectInfo.artifacts[0];
  const state=host.metadata.systemApplications;
  const theme={applicationId:'a',id:'theme',kind:'theme',path:'srv/news/themes/light',name:'Light',visibility:'unknown'};
  const plugin={applicationId:'a',id:'internal',kind:'plugin',path:'srv/news/plugins/internal',name:'Internal',visibility:'private'};
  state.inventory.push(theme,plugin);
  function finding(n,owner,relation,managerRelation,isDev=false){
    const file=owner.path+'/composer.lock';
    return {cve:{id:'CVE-2099-'+n,severity:'HIGH'},applicationIds:['a'],ownerComponentIds:[owner.id],applicationRelation:relation,
      dep:{name:'package'+n,version:'1',ecosystem:'composer',coordKey:'pkg'+n,artifactTargetId:host.id,artifactPath:file,
        manifestPaths:[file],managerRelation,isDev}};
  }
  payload.cveMatches.push(finding(1111,theme,'direct'),finding(1112,theme,'indirect','direct'),
    finding(1113,plugin,'indirect','direct'),finding(1114,plugin,'indirect','transitive'),finding(1115,plugin,'indirect','direct',true));
  const doc=parseDocument(generateHtmlReport(payload)),app=byId(doc,'system-app-0');
  const childSections=n=>sections(n.children.find(c=>c.name==='div'));
  const title=n=>contents(n.children.find(c=>c.name==='summary'));
  const named=(n,re)=>childSections(n).find(c=>re.test(title(c)));
  const pub=named(app,/Modules et thèmes/),priv=named(app,/Composants privés/);
  assert.match(contents(named(pub,/CVE et avis directs/)),/CVE-2099-1111/);
  assert.match(contents(named(pub,/indirectes par module/)),/Light.*CVE-2099-1112/s);
  assert.ok(!DomUtils.findOne(n=>n.name==='summary' && contents(n).includes('Light'),app.children));
  const local=childSections(priv)[0];
  assert.match(title(local),/Internal/);
  assert.match(contents(named(local,/^Dépendances directes/)),/CVE-2099-1113/);
  assert.match(contents(named(local,/^Dépendances transitives/)),/CVE-2099-1114/);
  assert.match(contents(named(local,/développement/)),/Directes \(1\).*CVE-2099-1115/s);
  for(const inv of [named(pub,/Inventaire/),named(app,/Inventaire des composants/)]) assert.ok(!('open' in inv.attribs));
});

test('an embedded application keeps its publisher advisories during collection and offline replay', async () => {
  const app = {id:'site',root:'srv/site',type:'wordpress',pluginId:'wordpress'};
  const extension = {id:'shop-module',applicationId:app.id,kind:'plugin',path:'srv/site/wp-content/plugins/shop'};
  const embedded = {id:'embedded',root:extension.path+'/admin',type:'prestashop',pluginId:'prestashop'};
  const core = {id:'embedded-core',applicationId:embedded.id,kind:'core',path:embedded.root,version:'9.0.0'};
  const finding = {findingId:'physical-occurrence',applicationIds:[embedded.id],ownerComponentIds:[core.id],applicationRelation:'direct'};
  const inventory = {applications:[app,embedded],inventory:[extension,core],findings:[structuredClone(finding)],
    coverage:[{applicationId:embedded.id,componentId:core.id}]};
  require('../lib/applications/layout').reconcileApplications(inventory);
  assert.deepEqual(inventory.applications,[app]);
  assert.deepEqual(inventory.inventory,[extension]);
  assert.equal(inventory.coverage[0].applicationId,app.id);
  assert.equal(inventory.coverage[0].embeddedComponentId,core.id);
  const runner = require('../lib/applications/plugins/runner');
  const replay = await runner.runApplicationPlugins(null,{offline:true,savedInventory:inventory,
    plugins:[{...require('../lib/applications/plugins/prestashop'),async assess(target,components) {
      assert.equal(target.id,embedded.id);
      assert.deepEqual(components,[core]);
      return [structuredClone(finding)];
    }}]});
  assert.deepEqual(replay.findings,inventory.findings);
  assert.deepEqual(replay.findings[0].ownerComponentIds,[extension.id]);
  assert.deepEqual(replay.findings[0].applicationIds,[app.id]);
  assert.equal(replay.findings[0].applicationRelation,'indirect');
  assert.equal(replay.findings[0].findingId,finding.findingId);
});

test('paths in an audited filesystem are rooted in the target in HTML and Word',()=>{
  const payload=fixture(), target=payload.projectInfo.artifacts[0];
  payload.projectInfo.src='/auditor/work';
  const file='usr/local/bin/php', cert='srv/news/certs/site.pem';
  const binary={name:'php',provenance:'binary',artifactTargetId:target.id,manifestPaths:[file],hashes:{sha256:'123'}};
  payload.resolvedDeps=new Map([['php',binary]]);
  payload.certFindings=[{kind:'certificate',artifactTargetId:target.id,path:cert,issues:[]}];
  payload.excludedDirs=[{artifactTargetId:target.id,type:'default',dir:'var/lib/docker'}];
  target.metadata.projectDescriptors=['srv/news/composer.lock'];
  const expected=[file,cert,'srv/news','srv/news/composer.lock','var/lib/docker'];
  for(const render of [generateHtmlReport,require('../lib/reports/cve-report').generateWordReport]){
    const doc=parseDocument(render(payload));
    const paths=DomUtils.findAll(n=>n.name==='code',doc.children).map(contents);
    for(const path of expected){
      assert.ok(paths.includes('/'+path),path);
      assert.ok(!paths.includes(path) && !paths.includes('../'+path),path);
    }
  }
  assert.equal(binary.manifestPaths[0],file);
  const {targetPath}=require('../lib/artifacts/report-path');
  assert.equal(targetPath('./opt/../srv/app.jar!/META-INF/a.xml'),'/srv/app.jar!/META-INF/a.xml');
  assert.equal(targetPath('/var/lib/dpkg/status'),'/var/lib/dpkg/status');
  assert.equal(targetPath('.'),'/');
});

test('audit component tables show affected occurrences and host dependencies only show findings',()=>{
  const data=fixture(),target=data.projectInfo.artifacts[0];
  const clean={...target.components[0],coordKey:'clean-copy',artifactPath:'srv/other/node_modules/web-direct/package.json'};
  const os={...target.components[3],coordKey:'ignored',name:'ignored-system-lib',artifactPath:'usr/lib/ignored.so'};
  target.components.push(clean,os);
  data.cveMatches.push({dep:os,suppressed:true,cve:{id:'CVE-2099-9999'}});
  for (const render of [generateHtmlReport,require('../lib/reports/cve-report').generateWordReport]) {
    const doc=parseDocument(render(data)),host=byId(doc,'chhost'),app=byId(doc,'system-app-1');
    const subsection=(n,label)=>DomUtils.findOne(c=>c.name==='details' && c.children.some(t=>t.name==='summary' && contents(t).includes(label)),n.children);
    const deps=subsection(host,'Dépendances du système'),inv=subsection(app,'Inventaire des composants');
    assert.match(contents(deps),/CVE-2026-1003/);
    assert.doesNotMatch(contents(deps),/ignored-system-lib|CVE-2099-9999|Chemin de preuve/);
    assert.match(contents(inv),/web-direct.*CVE-2026-1000/s);
    assert.doesNotMatch(contents(inv),/srv\/other\/node_modules/);
  }
  const [artifact]=require('../lib/artifacts/report-inventory').reportArtifacts([target],data.cveMatches);
  assert.equal(artifact.componentCount,target.components.length);
  assert.ok(!artifact.components.includes(clean) && !artifact.components.includes(os));
  assert.equal(target.components.length,6);
});

test('module maintenance uses the installed version, catalogue identity and owning instance',async t=>{
  const cacheDir=tempCache(t);
  const {assessSystemMaintenance}=require('../lib/artifacts/system-maintenance');
  const {configureResourceRoute}=require('../lib/providers');
  const inventory=[
    {applicationId:'a',id:'one',kind:'theme',path:'srv/a/theme',releaseSlug:'public-theme',slug:'custom-dir',version:'1.0',evidence:[{path:'srv/a/theme/style.css'}]},
    {applicationId:'b',id:'two',kind:'theme',path:'srv/b/theme',catalogueStatus:'verified',slug:'public-theme',version:'2.1'},
    {applicationId:'a',id:'three',kind:'plugin',releaseSlug:'private-plugin',visibility:'private',version:'1.0'},
    {applicationId:'b',id:'four',kind:'plugin',slug:'unknown-plugin',version:'1.0'},
    {applicationId:'b',id:'five',kind:'theme',releaseSlug:'unavailable',version:'1.0'},
  ];
  const target={id:'target',deps:[],coverage:[],metadata:{systemApplications:{applications:[
    {id:'a',type:'wordpress',root:'srv/a'},{id:'b',type:'wordpress',root:'srv/b'}],inventory}}};
  const requested=[];
  const fetcher=async url=>{
    const slug=new URL(url).searchParams.get('request[slug]');requested.push(slug);
    return slug==='unavailable'?new Response(null,{status:404}):Response.json({slug,version:'2.1'});
  };
  configureResourceRoute({store:null,proxyUrl:null});
  const result=await assessSystemMaintenance([target],{cacheDir,eol:false,fetcher});
  assert.deepEqual(requested,['public-theme','unavailable']);
  assert.deepEqual(result.outdatedResults.map(r=>[r.dep.systemApplicationIds,r.dep.version,r.latest,r.dep.artifactPath,r.dep.cmsComponent.versionEvidencePath]),[[['a'],'1.0','2.1','srv/a/theme','srv/a/theme/style.css']]);
  assert.equal(target.coverage.at(-1).executed,2);assert.equal(target.coverage.at(-1).expected,3,'private and unidentified catalogue entries are ineligible');
  const offline=await assessSystemMaintenance([target],{cacheDir,eol:false,offline:true,fetcher});
  assert.deepEqual(offline.outdatedResults,result.outdatedResults);assert.equal(target.coverage.at(-1).executed,2);
  const cold=await assessSystemMaintenance([target],{cacheDir:tempCache(t),eol:false,offline:true,fetcher});
  assert.deepEqual(cold.outdatedResults,[]);assert.equal(target.coverage.at(-1).executed,0);
  await assessSystemMaintenance([target],{eol:false,allLibs:false,fetcher});
  assert.deepEqual(requested,['public-theme','unavailable']);
});

test('a PrestaShop module update uses the installed version once per physical instance',async t=>{
  const cacheDir=tempCache(t), lock='srv/store/composer.lock';
  const installed={id:'module-1',applicationId:'store',kind:'module',version:'1.0',coord:'prestashop/example',
    name:'Example',path:'srv/store/modules/example',evidence:[{field:'version',path:'srv/store/modules/example/example.php'},{path:lock}]};
  const declared={ecosystem:'composer',name:'example',namespace:'prestashop',version:'1.2',coordKey:'locked',
    artifactPath:lock,systemApplicationIds:['store']};
  const independent={...declared,coordKey:'other-project',systemApplicationIds:['other'],artifactPath:'srv/other/composer.lock'};
  const target={id:'system',coverage:[],deps:[declared,independent],metadata:{systemApplications:{
    applications:[{id:'store',type:'prestashop',root:'srv/store'},{id:'other',type:'project',root:'srv/other'}],inventory:[installed]}}};
  const entry={versionChecked:true,latest:'2.0',license:['MIT']};
  require('../lib/cache/json').save(cacheDir,'packagist',{meta:{fetchedAt:Date.now()},entries:{
    'prestashop/example@1.0':entry,'prestashop/example@1.2':entry}});
  const result=await require('../lib/artifacts/system-maintenance').assessSystemMaintenance([target],{offline:true,cacheDir,eol:false,licenses:true});
  assert.equal(result.licenseResults.assessed.length,2);
  assert.deepEqual(result.outdatedResults.map(r=>[r.dep.coordKey,r.dep.version,r.latest]).sort(),[
    ['module-1','1.0','2.0'],['other-project','1.2','2.0']]);
  assert.deepEqual(result.outdatedResults.find(r=>r.dep.cmsComponent).dep.cmsComponent,
    {kind:'module',name:'Example',path:installed.path,applicationRoot:'srv/store',descriptorPath:lock,versionEvidencePath:installed.evidence[0].path});
  assert.equal(target.coverage.at(-1).executed,1);
});

test('host alerts locate internal evidence while additional image alerts keep their own target',()=>{
  const data=fixture(),host=data.projectInfo.artifacts[0];
  const app=host.metadata.systemApplications.applications[0];
  host.metadata.inspectLocalImages=true;
  data.projectInfo.artifacts.push({id:'extra',kind:'docker',metadata:{reference:'example:1'},components:[],coverage:[]});
  data.warnings=[
    ...['srv/news/composer.lock','srv/api/composer.lock'].map(path=>({type:'dependency-coverage',reason:'bad-lock',
      artifactTargetId:host.id,manifestPath:path,message:'Unreadable '+path})),
    {type:'source-unavailable',artifactTargetId:host.id,message:'Host advisories unavailable'},
    {type:'cms-coverage',applicationId:app.id,artifactTargetId:host.id,capability:'advisories',execution:'partial',
      items:[{id:app.id}],diagnostic:'CMS_IDENTITY_UNVERIFIED'},
    {type:'source-unavailable',artifactTargetId:'extra',message:'Container advisories unavailable'},
  ];
  for(const render of [generateHtmlReport,require('../lib/reports/cve-report').generateWordReport]){
    const doc=parseDocument(render(data));
    const alerts=DomUtils.findAll(n=>n.attribs.class?.split(' ').includes('warnings'),doc.children).map(contents).join(' ');
    assert.doesNotMatch(alerts,/serveur\.vhdx|\/disques\//);
    assert.match(alerts,/wordpress · \/srv\/news/);
    const scope=name=>contents(DomUtils.findOne(n=>n.attribs.class?.includes('warning-scope-'+name),doc.children));
    assert.match(scope('system'),/\/srv\/news\/composer.lock/);
    assert.match(scope('system'),/\/srv\/api\/composer.lock/);
    assert.match(scope('system'),/Host advisories unavailable/);
    assert.doesNotMatch(scope('system'),/example:1/);
    assert.match(scope('image'),/example:1/);
  }
});

test('the source table aggregates component checks and long report sections have independent controls',()=>{
  const {inventoryDataSources,makeCommand}=require('../lib/cli-image');
  const defaults=makeCommand('analyse').parse(['host.json'],{from:'user'}).opts();
  for(const option of ['eol','eolSupport','allLibs','nvd','osv','distroAdvisories','publisherAdvisories','gcve','euvd','kev','epss','certfr'])assert.equal(defaults[option],true,option);
  assert.equal(defaults.licenses,false);
  assert.equal(makeCommand('analyse').parse(['--licenses','host.json'],{from:'user'}).opts().licenses,true);
  const data=fixture(),host=data.projectInfo.artifacts[0];
  host.coverage=['completed','completed','not-run'].map((execution,i)=>({sourceId:'github-prestashop-advisories',capability:'advisories',
    applicationId:'a',occurrenceId:'dep-'+i,execution}));
  const sources=inventoryDataSources([host]);
  assert.equal(sources.length,1);assert.equal(sources[0].status,'partial');assert.deepEqual(sources[0].checks,{completed:2,'not-run':1});
  data.projectInfo.provenance={dataSources:sources};
  data.eolResults=[{product:'Vue',productSlug:'vue',eol:'2023-12-31',latest:'3.5',dep:{name:'vue',scope:'transitive',version:'2.7'}}];
  data.coverage=host.coverage;
  const doc=parseDocument(generateHtmlReport(data));
  for(const title of [/Dépendances transitives \(1\) —/,/^Sources de données$/,/Couverture applicative \(3\)/,/Contrôles de couverture du système hôte/]){
    const summary=DomUtils.findOne(n=>n.name==='summary' && title.test(contents(n)),doc.children);
    assert.ok(summary,String(title));assert.equal(summary.parent.name,'details');assert.equal(summary.parent.attribs.open,undefined);
  }
  const method=contents(byId(doc,'chmethod'));
  assert.equal(method.split('github-prestashop-advisories').length-1,1);
});

test('CMS update rows distinguish the package descriptor from the installed version evidence',()=>{
  const root='srv/shop',dir=root+'/modules/example',lock=root+'/composer.lock',php=dir+'/example.php';
  const component={id:'module',kind:'module',applicationId:'shop',name:'example',coord:'prestashop/example',
    version:'1.0',path:dir,evidence:[{path:php,field:'$this->version'},{path:lock,field:'packages[name=prestashop/example].version'}]};
  const target={id:'host',metadata:{systemApplications:{applications:[{id:'shop',type:'prestashop',root}],inventory:[component]}}};
  for (const [descriptors,expected] of [
    [[dir+'/composer.json',dir+'/package.json'],dir+'/composer.json'],
    [[dir+'/package.json'],dir+'/package.json'],
    [[dir+'/composer.lock',dir+'/package-lock.json',dir+'/assets/package.json'],lock],
  ]){
    target.metadata.projectDescriptors=descriptors;
    const dep=require('../lib/artifacts/system-module-updates').moduleChecks(target).composer.get(component.id);
    assert.deepEqual(dep.manifestPaths,[expected]);assert.deepEqual(dep.versionPaths,{'1.0':[php]});
    const data=fixture();data.outdatedResults=[{dep,latest:'2.0'}];
    const json=require('../lib/reports/json-export').buildFindings(data).outdated[0].dep;
    assert.equal(json.artifactPath,expected);assert.equal(json.cmsComponent.versionEvidencePath,php);
    for(const render of [generateHtmlReport,require('../lib/reports/cve-report').generateWordReport]){
      const doc=parseDocument(render(data));
      const section=byId(doc,'ch6');
      const lines=DomUtils.findAll(n=>n.attribs.class==='defined-in',section.children).map(contents);
      assert.deepEqual(lines,['Descripteur /'+expected,'Version installée relevée dans /'+php]);
    }
  }
  target.metadata.projectDescriptors=[];component.evidence=[{path:php,field:'$this->version'}];
  const onlyNative=require('../lib/artifacts/system-module-updates').moduleChecks(target).composer.get(component.id);
  assert.equal(onlyNative.cmsComponent.descriptorPath,undefined);assert.equal(onlyNative.artifactPath,dir);
  assert.equal(onlyNative.cmsComponent.versionEvidencePath,php);
});

test('the host runtime table shows distribution advisories on owned executables and explains incomplete coverage',()=>{
  const data=fixture(),host=data.projectInfo.artifacts[0],file='usr/sbin/apache2';
  const pkg={artifactTargetId:host.id,systemSection:'runtime',ecosystem:'system',coordKey:'apache2-bin',manager:'dpkg',
    name:'apache2-bin',version:'2.4.57-2',architecture:'amd64',artifactPath:'/var/lib/dpkg/status'};
  const binary={...pkg,ecosystem:'binary',name:'apache2',coordKey:'apache2',artifactPath:file,version:'2.4.57',
    osPackageOwners:[{manager:'dpkg',name:pkg.name,version:pkg.version,architecture:'amd64'}]};
  const unknown={...binary,coordKey:'other',name:'php',artifactPath:'usr/bin/php',osPackageOwners:[]};
  host.components.push(pkg,binary,unknown);
  host.productInventory={entries:[{name:'php',path:'usr/bin/php',advisoryCheck:'distribution-incomplete'}]};
  data.cveMatches.push({dep:pkg,source:'osv',cve:{id:'DEBIAN-CVE-2024-38476',upstream:['CVE-2024-38476'],nvdEvidence:{records:[{id:'CVE-2024-38476',severity:'CRITICAL',score:9.8}]}}});
  const doc=parseDocument(generateHtmlReport(data)),section=byId(doc,'chhost');
  const rows=DomUtils.findAll(n=>n.name==='tr',section.children);
  assert.ok(rows.some(row=>contents(row).includes('/'+file) && contents(row.children.at(-1)).includes('Critiques 1') && !DomUtils.findOne(n=>n.name==='details',row.children.at(-1).children)));
  assert.ok(rows.some(row=>contents(row).includes('/usr/bin/php') && contents(row).includes('Version du paquet non vérifiée')));
});

test('system remediation keeps the candidate with the exact advisory and installed version',()=>{
  const payload=fixture();
  payload.cveMatches[0].cve.fixVersion='1.2.1';
  const chapter=byId(parseDocument(generateHtmlReport(payload)),'ch8');
  const candidates=DomUtils.findOne(n=>n.name==='details' && n.children.some(c=>c.name==='summary' && contents(c).includes('Versions correctives par avis')),chapter.children);
  assert.ok(candidates);
  assert.match(contents(candidates),/CVE-2026-1000 · 1.0 → 1.2.1/);
});

test('a host without projects or containers still renders host finding charts in its overview',()=>{
 const payload=fixture();
 const host=payload.projectInfo.artifacts[0];
 host.metadata.systemApplications={applications:[],inventory:[]};
 payload.cveMatches=payload.cveMatches.filter(m=>!m.applicationIds?.length);
 const doc=parseDocument(generateHtmlReport(payload));
 const headings=DomUtils.findAll(node=>node.attribs.class==='charts-heading',doc.children);
 assert.deepEqual(headings.map(contents),['Vue d’ensemble de l’hôte']);
 for(const id of ['host-chart-subdeps','host-chart-image-severity','host-chart-priority']){
  assert.ok(DomUtils.findOne(node=>node.name==='svg',byId(doc,id).children),id);
 }
});

test('project charts include CMS development dependencies and stay separate from optional images and host findings',()=>{
 const payload=fixture(),target=payload.projectInfo.artifacts[0];
 target.metadata.inspectLocalImages=true;
 const dependency=payload.cveMatches[1];
 dependency.dep.isDev=true;
 dependency.cve.cwes=['CWE-79'];
 // The inventory proves the application owner even without finding-level attribution.
 dependency.applicationIds=[];
 const host=payload.cveMatches[2];host.cve.cwes=['CWE-89'];
 payload.cveMatches=[host];payload.devCveMatches=[dependency];
 const before=JSON.stringify(payload);
 const render=()=>parseDocument(generateHtmlReport(payload));
 let doc=render();
 assert.deepEqual(DomUtils.findAll(n=>n.attribs.class==='charts-heading',doc.children).map(contents),
   ['Synthèse du projet','Synthèse des images','Vue d’ensemble de l’hôte']);
 for(const id of ['chart-cwe','chart-subdeps','chart-instances','chart-priority'])
   assert.ok(DomUtils.findOne(n=>n.name==='svg',byId(doc,id).children),id);
 assert.match(contents(byId(doc,'chart-cwe')),/CWE-79/);
 assert.doesNotMatch(contents(byId(doc,'chart-cwe')),/CWE-89/);
 assert.match(contents(byId(doc,'chart-instances')),/srv\/web/);
 assert.match(contents(byId(doc,'host-chart-cwe')),/CWE-89/);
 assert.doesNotMatch(contents(byId(doc,'host-chart-cwe')),/CWE-79/);
 assert.ok(byId(doc,'image-chart-subdeps'));
 assert.equal(DomUtils.findOne(n=>n.name==='svg',byId(doc,'image-chart-subdeps').children),null);
 assert.equal(JSON.stringify(payload),before,'chart attribution must not change the inventory or findings');
 const image={id:'container',kind:'docker',metadata:{source:'container.tar'},components:[],coverage:[]};
 payload.projectInfo.artifacts.push(image);
 payload.cveMatches.push({dep:{name:'image-lib',ecosystem:'npm',version:'1.0',coordKey:'image-lib',artifactTargetId:image.id},
   cve:{id:'CVE-2026-9999',severity:'HIGH',cwes:['CWE-22']}});
 doc=render();
 assert.match(contents(byId(doc,'image-chart-cwe')),/CWE-22/);
 assert.doesNotMatch(contents(byId(doc,'image-chart-cwe')),/CWE-79|CWE-89/);
 assert.doesNotMatch(contents(byId(doc,'chart-cwe')),/CWE-22/);
 assert.doesNotMatch(contents(byId(doc,'host-chart-cwe')),/CWE-22/);
 payload.projectInfo.artifacts.pop();target.metadata.inspectLocalImages=false;payload.cveMatches.pop();
 doc=render();assert.equal(byId(doc,'image-chart-subdeps'),null);
});

test('the executive summary and clipboard include ranked host CVEs and link to the host chapter',()=>{
  const payload=fixture();
  payload.projectInfo.artifacts[0].metadata.systemApplications={applications:[],inventory:[]};
  payload.cveMatches=payload.cveMatches.filter(m=>!m.applicationIds.length);
  const html=generateHtmlReport(payload);
  const doc=parseDocument(html);
  const summary=DomUtils.findOne(n=>n.attribs?.class?.split(' ').includes('exec-summary'),doc.children);
  const links=DomUtils.findAll(n=>n.name==='a' && n.attribs.href==='#chhost',summary.children);
  assert.deepEqual(links.map(contents).sort(),payload.cveMatches.map(m=>m.cve.id).sort());
  assert.match(contents(summary),/php/);
  assert.match(contents(summary),/shared-lib/);
});

test('audit header uses the original input identity independently of detected products',()=>{
 const {auditTargetName}=require('../lib/artifacts/system-report');
 const cases=[
  [{source:'/',format:'directory',hostname:'machine'},'/'],
  [{source:'/home/user/work/project/',acquisition:{kind:'rootfs-directory',source:'/home/user/work/project/'}},'project'],
  [{source:'/tmp/extracted',acquisition:{kind:'archive',source:'/archives/original.tar'},tags:['guessed-product:1']},'original.tar'],
  [{source:'C:\\archives\\server.vhdx',diskFormat:'vhdx',partition:'p2'},'server.vhdx'],
  [{source:'image.tar',tags:['different-tag:1'],acquisition:{kind:'registry',reference:'registry.example/team/web:release'}},'registry.example/team/web:release'],
  [{source:'sha256:abc',localDocker:{id:'sha256:abc',tags:['local-web:stable']}},'local-web:stable'],
  [{source:'sha256:abc',localDocker:{id:'sha256:abc',tags:['<none>:<none>']}},'sha256:abc'],
 ];
 for(const [metadata,expected] of cases){
  const payload=fixture(),host=payload.projectInfo.artifacts[0];
  Object.assign(host.metadata,metadata);
  host.productInventory={entries:[{label:'Guessed Apache',category:'service',version:'9.9',versionSource:'embedded-version-banner'}]};
  assert.equal(auditTargetName(host),expected);
  const doc=parseDocument(generateHtmlReport(payload));
  const header=DomUtils.findOne(n=>n.name==='header',doc.children);
  const label=DomUtils.findOne(n=>n.name==='strong',header.children);
  assert.equal(contents(label),expected);
 }
});
