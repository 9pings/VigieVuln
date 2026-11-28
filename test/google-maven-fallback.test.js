const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {buildRepoList,orderRepos,GOOGLE_MAVEN,createRepoHealth,fetchPomFromRepos}=require('../lib/providers/maven/repo');
const {guardedFetch,createSourceHealth}=require('../lib/scan/source-health');
const {fetchPom,effectivePom}=require('../lib/codecs/maven/transitive');
function temp(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-google-maven-'));t.after(()=>{require('../lib/cache/db').closeCacheDbs();fs.rmSync(dir,{recursive:true,force:true});});return dir;}
const pom='<project><modelVersion>4.0.0</modelVersion><groupId>androidx.core</groupId><artifactId>core-ktx</artifactId><version>1.17.0</version></project>';

test('Google Android stays after every Central mirror and configured repository, including rotated lookups',()=>{
 const repos=buildRepoList([{name:'internal',url:'https://internal.invalid/'}]);
 for(const key of ['',...Array.from({length:20},(_,i)=>'coordinate:'+i)]){
  const ordered=orderRepos(repos,key);assert.equal(ordered[0].name,'internal');
  assert.equal(ordered.at(-1).url,GOOGLE_MAVEN.url);assert.equal(ordered.at(-1).mirror,false);
 }
 const explicit=buildRepoList([{name:'explicit-google',url:GOOGLE_MAVEN.url}]);
 assert.equal(orderRepos(explicit,'some:key')[0].name,'explicit-google');
 assert.equal(explicit.filter(r=>r.url===GOOGLE_MAVEN.url).length,1);
 const health=createRepoHealth();assert.equal(health.markDown(repos.at(-1),'HTTP 503'),false);
});

test('Central hit avoids Google; Central misses resolve on Google and replay offline',async t=>{
 const cacheDir=path.join(temp(t),'poms-cache'),calls=[];
 const repos=buildRepoList([]);
 const fetcher=async url=>{calls.push(url);return String(url).startsWith(GOOGLE_MAVEN.url)?new Response(pom):new Response('',{status:404});};
 assert.equal(await fetchPom('androidx.core','core-ktx','1.17.0',{repos,cacheDir,fetcher}),pom);
 assert.equal(calls.length,repos.length);assert.ok(calls.at(-1).startsWith(GOOGLE_MAVEN.url));
 assert.equal(await fetchPom('androidx.core','core-ktx','1.17.0',{repos,cacheDir,offline:true,fetcher:()=>{throw Error('offline network');}}),pom);
 calls.length=0;
 await fetchPomFromRepos(repos,'public','library','1',{fetcher:async url=>{calls.push(url);return new Response('<project/>');}});
 assert.equal(calls.length,1);assert.ok(!calls[0].startsWith(GOOGLE_MAVEN.url));
});

test('Google 429 uses spaced retries and Retry-After, with a fresh timeout each attempt',async()=>{
 const waits=[],events=[],signals=[];let googleCalls=0;
 const fetcher=guardedFetch({health:createSourceHealth(),retries:2,sleep:async ms=>waits.push(ms),onRetry:e=>events.push(e),fetch:async(url,init)=>{
  if(!String(url).startsWith(GOOGLE_MAVEN.url))return new Response('',{status:404});
  signals.push(init.signal);return ++googleCalls<3?new Response('',{status:429,headers:{'retry-after':'8'}}):new Response(pom);
 }});
 const hit=await fetchPomFromRepos(buildRepoList([]),'androidx.core','core-ktx','1.17.0',{fetcher,health:createRepoHealth()});
 assert.equal(hit.body,pom);assert.deepEqual(waits,[8000,8000]);assert.equal(events.length,2);
 assert.notEqual(signals[0],signals[1]);
});

test('Google uses the shared proxy operation without direct client access or Central cache collision',async t=>{
 const dir=temp(t),{configureResourceRoute,providerKey}=require('../lib/providers');
 const {startProxyCacheServer,createCacheStore}=require('../lib/cache/proxy-cache');
 const {validateResource}=require('../lib/cache/resource/validate');
 const params={path:'androidx/core/core-ktx/1.17.0/core-ktx-1.17.0.pom',method:'GET'};
 assert.notEqual(providerKey('maven','artifact',params),providerKey('maven','artifact',{...params,repository:'google'}));
 assert.throws(()=>validateResource({provider:'maven',type:'artifact',params:{...params,repository:'https://untrusted.invalid'}}));
 const upstream=[];
 const running=await startProxyCacheServer({host:'127.0.0.1',port:0,store:createCacheStore(path.join(dir,'proxy')),
  fetcher:async url=>{upstream.push(url);return String(url).startsWith(GOOGLE_MAVEN.url)?new Response(pom):new Response('',{status:404});}});
 try{
  const fetcher=(url,init)=>{assert.ok(String(url).startsWith(running.url));return fetch(url,init);};
  configureResourceRoute({proxyUrl:running.url,hosted:true,store:null,hostedStore:null,health:null,fetcher});
  const hit=await fetchPomFromRepos(buildRepoList([]),'androidx.core','core-ktx','1.17.0',{fetcher});
  assert.equal(hit.body,pom);assert.equal(upstream.length,2);
  assert.ok(upstream[0].startsWith('https://repo1.maven.org/'));assert.ok(upstream[1].startsWith(GOOGLE_MAVEN.url));
 }finally{configureResourceRoute({proxyUrl:null,hosted:false,store:null,hostedStore:null,health:null,fetcher:null});await new Promise(r=>running.server.close(r));}
});

test('all-repository POM absence stays an alert online, memoized and offline; an unqueried repository invalidates absence',async t=>{
 const cacheDir=path.join(temp(t),'poms-cache'),repos=buildRepoList([]),effCache=new Map(),absent=[],missing=[];
 const opts={repos,cacheDir,effCache,fetcher:async()=>new Response('',{status:404}),onAbsentPom:p=>absent.push(p),onMissingPom:p=>missing.push(p)};
 await effectivePom('internal','library','1',opts);await effectivePom('internal','library','1',opts);
 assert.equal(absent.length,2);assert.equal(missing.length,2);
 await effectivePom('internal','library','1',{...opts,effCache:new Map(),offline:true,fetcher:()=>{throw Error('offline network');}});
 assert.equal(absent.length,3);
 await effectivePom('internal','library','1',{...opts,effCache:new Map(),offline:true,repos:[...repos,{url:'https://another.invalid/'}]});
 assert.equal(absent.length,3);assert.equal(missing.length,4);
 await effectivePom('internal','library','1',{...opts,offline:true,repos:[...repos,{url:'https://another.invalid/'}]});
 assert.equal(absent.length,3,'memoized absence also belongs to its repository scope');
});

test('a Google error after Central 404 never becomes confirmed POM absence',async t=>{
 const absent=[],cacheDir=path.join(temp(t),'poms-cache'),repos=buildRepoList([]);
 for(const status of [401,403,405,429,503]){
  await fetchPom('example','library',String(status),{cacheDir,repos,onAbsentPom:p=>absent.push(p),
   fetcher:async url=>new Response('',{status:String(url).startsWith(GOOGLE_MAVEN.url)?status:404})});
 }
 assert.equal(absent.length,0);
});

for(const status of [404,503])test(`CLI POM ${status} after repository fanout: confirmed absence alerts; unavailable source cancels`,t=>{
 const dir=temp(t),src=path.join(dir,'src'),hook=path.join(dir,'hook.cjs'),out=path.join(dir,'out');fs.mkdirSync(src);
 fs.writeFileSync(path.join(src,'pom.xml'),'<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>private.example</groupId><artifactId>library</artifactId><version>1.0</version></dependency></dependencies></project>');
 fs.writeFileSync(hook,`globalThis.fetch=async url=>{
  const u=new URL(url);
  if(u.pathname.endsWith('.pom'))return new Response('',{status:${status}});
  if(u.pathname.endsWith('maven-metadata.xml'))return new Response('',{status:404});
  if(u.pathname.endsWith('/maven2/'))return new Response('');
  throw Error('Unexpected network source '+u.hostname);
 };`);
 const run=extra=>require('node:child_process').spawnSync(process.execPath,['--require',hook,path.resolve(__dirname,'../vigievuln.js'),
  'scan',src,'--ecosystem','maven','--no-all-libs','--retries','0','-d','eol,retire,certs','--no-osv-db','-o',out,...extra],
  {cwd:dir,env:{PATH:process.env.PATH,HOME:dir,USERPROFILE:dir,FORCE_COLOR:'0'},encoding:'utf8',timeout:30000});
 const result=run([]);
 if(status===404){
  assert.equal(result.status,0,result.stdout+'\n'+result.stderr);
  let report=JSON.parse(fs.readFileSync(path.join(out,'findings.json')));
  assert.equal(report.summary.scanReliable,true);assert.ok(report.warnings.some(w=>w.type==='private-libs'&&w.items.some(i=>i.id==='private.example:library:1.0')));
  const replay=run(['--offline']);assert.equal(replay.status,0,replay.stdout+'\n'+replay.stderr);
 }else{
  // Every advisory source is unreachable in this fixture (the hook rejects them), so no
  // source assessed the only package: the scan is still cancelled (fatal coverage gap).
  assert.equal(result.status,2,result.stdout+'\n'+result.stderr);
  assert.match(result.stderr,/Scan cancelled/);
  assert.match(result.stderr,/Advisory discovery is incomplete for 1 package\/version\(s\)[\s\S]*private\.example:library@1\.0 — OSV \+ a second advisory source/);
  // The unresolved POM is reported as a dependency-coverage gap, never as a confirmed absence.
  assert.match(result.stdout,/\[dependency-coverage\] 1 Maven POM\(s\) could not be resolved[^\n]*\n\s*· private\.example:library:1\.0/);
  assert.doesNotMatch(result.stdout+result.stderr,/absent from all configured registries/);
  assert.equal(fs.existsSync(path.join(out,'findings.json')),false);
 }
});
