const test = require('node:test');
const assert = require('node:assert/strict');
const {createProxyThrottle} = require('../lib/providers/proxy-throttle');

test('proxy 429 respects Retry-After, retries the request and announces the wait', async () => {
  let time=10000, calls=0; const waits=[], messages=[];
  const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{waits.push(ms);time+=ms},warn:m=>messages.push(m)});
  const response=await limiter.request(async()=>++calls===1 ? new Response('',{status:429,headers:{'retry-after':'3'}}) : new Response('ok'),null);
  assert.equal(response.status,200); assert.equal(calls,2); assert.ok(waits.some(ms=>ms>=3000));
  assert.match(messages.join('\n'),/HTTP 429.*3s/);
});

test('persistent proxy rate limits stop after three retries', async () => {
  let time=0,calls=0; const limiter=createProxyThrottle({maxRateRetries:3,now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
  const response=await limiter.request(async()=>{calls++;return new Response('',{status:429,headers:{'retry-after':'1'}})});
  assert.equal(response.status,429);assert.equal(calls,4);
});

test('a retry delay longer than one minute is reported and never retried early', async () => {
  let calls=0;const messages=[];const limiter=createProxyThrottle({warn:m=>messages.push(m)});
  const response=await limiter.request(async()=>{calls++;return new Response('',{status:429,headers:{'retry-after':'3600'}})});
  assert.equal(response.status,429);assert.equal(calls,1);assert.match(messages.join('\n'),/3600s/);
});

test('proxy upstream admission denial retries, but an ordinary 503 is returned', async () => {
  let time=0,calls=0; const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
  const res=await limiter.request(async()=>++calls===1 ? new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'2'}}) : new Response('ok'));
  assert.equal(res.status,200);assert.equal(calls,2);assert.ok(time>=2000);
  const unavailable=await limiter.request(async()=>new Response('',{status:503}));
  assert.equal(unavailable.status,503);
});

test('transient proxy errors retry the same resource without declaring all cached resources down', async () => {
  const {configureResourceRoute,getResource}=require('../lib/providers');
  const {createSourceHealth}=require('../lib/scan/source-health');
  const health=createSourceHealth();let calls=0;
  configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health,token:'test',fetcher:async (_url,init)=>{
    const id=JSON.parse(init.body).params.name;
    if(id==='bad-package') {calls++;return new Response('',{status:502});}
    return Response.json({name:id});
  }});
  try {
    assert.equal((await getResource('npm','package',{name:'bad-package'})).status,502);
    assert.equal(calls,3);
    assert.equal((await getResource('npm','package',{name:'cached-package'})).status,200);
    assert.equal(health.isDown('npm'),true, 'the missing resource remains visible as incomplete coverage');
  } finally { configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null}); }
});

test('proxy requests are spread out and stay below the per-minute budget', async () => {
  let time=0;const starts=[];const limiter=createProxyThrottle({intervalMs:35,maxPerMinute:3,now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
  for(let i=0;i<4;i++) await limiter.request(async()=>{starts.push(time);return new Response('ok')});
  assert.deepEqual(starts,[0,35,70,60000]);
});

test('the hosted provider retries the same lookup after a proxy 429', async () => {
  const {configureResourceRoute,getResource}=require('../lib/providers');
  const requests=[];
  configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher:async (_url,init)=>{
    requests.push(JSON.parse(init.body));
    return requests.length===1 ? new Response('',{status:429,headers:{'retry-after':'1'}}) : Response.json({data:[]});
  }});
  try {
    const result=await getResource('epss','scores',{ids:['CVE-2021-44228']});
    assert.equal(result.status,200);assert.equal(requests.length,2);assert.deepEqual(requests[0],requests[1]);
  } finally { configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null}); }
});

test('hosted npm applies the network deadline after rate-limit waiting', async () => {
  const {configureResourceRoute}=require('../lib/providers');
  const {fetchPackument}=require('../lib/codecs/npm/registry');
  let calls=0;
  const fetcher=async (_url,init)=>{
    calls++;
    if (calls===1) return new Response('',{status:429,headers:{'retry-after':'1'}});
    assert.equal(init.signal.aborted,false);
    return Response.json({name:'example',versions:{}});
  };
  configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,store:null,health:null,token:'test',fetcher});
  try { assert.equal((await fetchPackument('example',{timeoutMs:50,fetcher})).name,'example');assert.equal(calls,2); }
  finally { configureResourceRoute({proxyUrl:null,hosted:false,store:null,health:null,token:null,fetcher:null}); }
});

test('one request budget accepts long Retry-After without disabling other requests',async()=>{
 let time=0,calls=0;const waits=[];const limiter=createProxyThrottle({intervalMs:0,maxWaitMs:180000,now:()=>time,sleep:async ms=>{waits.push(ms);time+=ms},warn:()=>{}});
 const response=await limiter.request(async()=>++calls===1?new Response('',{status:429,headers:{'retry-after':'90'}}):calls===2?new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'100'}}):new Response('ok'));
 assert.equal(response.status,503);assert.equal(calls,2);assert.equal(time,90000);assert.deepEqual(waits,[90000]);
 const cached=await limiter.request(async()=>new Response('cached'));
 assert.equal(cached.status,200,'another resource can still be served from proxy cache');
 let limitedCalls=0;const limited=await limiter.request(async()=>{limitedCalls++;return limitedCalls===1?new Response('',{status:429,headers:{'retry-after':'100'}}):new Response('recovered')});
 assert.equal(limited.status,200);assert.equal(limitedCalls,2,'another request retains its own retry allowance');
 assert.equal(time,190000);
});

test('concurrent requests respect a shared cooldown and retry date without an early burst',async()=>{
 let time=100000;const releases=[],waits=[],starts=[];const sleeper=(ms)=>new Promise(resolve=>{waits.push(ms);releases.push(resolve);});
 const limiter=createProxyThrottle({intervalMs:0,maxWaitMs:100000,now:()=>time,sleep:sleeper,warn:()=>{}});let calls=0;
 const first=limiter.request(async()=>{starts.push(time);return ++calls===1?new Response('',{status:429,headers:{'retry-after':new Date(170000).toUTCString()}}):new Response('ok')});
 await new Promise(setImmediate);const second=limiter.request(async()=>{starts.push(time);return new Response('ok')});await new Promise(setImmediate);
 assert.deepEqual(starts,[100000]);assert.deepEqual(waits,[70000,70000]);
 time=170000;for(const release of releases)release();
 await Promise.all([first,second]);assert.deepEqual(starts,[100000,170000,170000]);
});

test('budget-exhausted admission denial still permits a different NVD cache hit',async()=>{
 const {configureResourceRoute,getResource}=require('../lib/providers');const calls=[];
 configureResourceRoute({proxyUrl:'https://proxy.invalid',hosted:true,resetRateLimit:true,proxyRateLimitMaxWaitMs:0,store:null,health:null,token:'key',fetcher:async(_url,init)=>{const q=JSON.parse(init.body);calls.push(q.provider);assert.equal(new Headers(init.headers).get('x-fad-proxy-token'),'key');return q.provider==='euvd'?new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'90'}}):Response.json({vulnerabilities:[],totalResults:0});}});
 try{assert.equal((await getResource('euvd','vulnerability',{id:'EUVD-2024-1'})).status,503);assert.equal((await getResource('nvd','cve',{id:'CVE-2024-1234'})).status,200);assert.deepEqual(calls,['euvd','nvd']);}
 finally{configureResourceRoute({proxyUrl:null,hosted:false,resetRateLimit:true,proxyRateLimitMaxWaitMs:null,token:null,fetcher:null});}
});

test('successive stale quota responses retain a readable cached body after budget exhaustion',async()=>{
 let now=0,calls=0;const limiter=createProxyThrottle({maxWaitMs:5000,now:()=>now,sleep:async ms=>{now+=ms},warn:()=>{}});
 const res=await limiter.request(async()=>{calls++;return Response.json({saved:calls},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'429','x-fad-proxy-refresh-cause':'rate-limit','retry-after':'2'}})});
 assert.equal(calls,2);assert.deepEqual(await res.json(),{saved:2});assert.equal(res.headers.get('x-fad-proxy-refresh-cause'),'rate-limit');
});

test('stale responses with 403 or unknown refresh causes are not retried',async()=>{
 for(const [status,cause] of [['403','upstream-http'],['503','upstream-http'],['429','unknown']]){let calls=0;const limiter=createProxyThrottle({warn:()=>{}});const res=await limiter.request(async()=>{calls++;return Response.json({saved:true},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':status,'x-fad-proxy-refresh-cause':cause,'retry-after':'1'}})});assert.equal(calls,1);assert.deepEqual(await res.json(),{saved:true});}
});

test('default permits 15 retries with at least three seconds of cooldown',async()=>{
 let time=0,calls=0;const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
 const response=await limiter.request(async()=>++calls<=15?new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'1'}}):new Response('recovered'));
 assert.equal(response.status,200);assert.equal(calls,16);assert.equal(time,45000);
});

test('successive lookups each retain their retry budget despite earlier waits and scan work',async()=>{
 let time=0,totalCalls=0;const waits=[],messages=[];
 const limiter=createProxyThrottle({intervalMs:0,maxWaitMs:6000,now:()=>time,sleep:async ms=>{waits.push(ms);time+=ms},warn:m=>messages.push(m)});
 const query=async()=>{let calls=0;return limiter.request(async()=>{totalCalls++;return ++calls===1?new Response('',{status:429,headers:{'retry-after':'3'}}):new Response('ok');});};
 assert.equal((await query()).status,200);
 time+=120000; // ordinary successful scan work, not retry waiting
 assert.equal((await query()).status,200);
 assert.deepEqual(waits,[3000,3000]);assert.equal(totalCalls,4);
 assert.equal((await query()).status,200);
 assert.equal(totalCalls,6);assert.deepEqual(waits,[3000,3000,3000]);
 assert.doesNotMatch(messages.join('\n'),/budget exhausted/);
});

test('concurrent cooldowns are coordinated and cached 200 explains the upstream failure',async()=>{
 let time=0;const releases=[],messages=[];
 const limiter=createProxyThrottle({intervalMs:0,maxWaitMs:6000,now:()=>time,sleep:()=>new Promise(resolve=>releases.push(resolve)),warn:m=>messages.push(m)});
 let calls=0;
 const first=limiter.request(async()=>++calls===1?Response.json({cached:true},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'429','x-fad-proxy-refresh-cause':'rate-limit'}}):new Response('ok'));
 await new Promise(setImmediate);
 const second=limiter.request(async()=>new Response('other'));
 await new Promise(setImmediate);
 time=3000;releases.splice(0).forEach(resolve=>resolve());
 await Promise.all([first,second]);
 assert.match(messages.join('\n'),/refresh HTTP 429; cached response available/);
 assert.doesNotMatch(messages.join('\n'),/HTTP 200/);
 calls=0;const third=limiter.request(async()=>++calls===1?new Response('',{status:429}):new Response('ok'));
 await new Promise(setImmediate);assert.equal(calls,1);assert.equal(releases.length,1);
 time=6000;releases.splice(0).forEach(resolve=>resolve());
 assert.equal((await third).status,200);
});

test('one skip releases all waiting retries and preserves stale responses',async()=>{
 let notify,subscriptions=0,unsubscriptions=0;const limiter=createProxyThrottle({intervalMs:0,now:()=>0,sleep:()=>new Promise(()=>{}),warn:()=>{},subscribeSkip:cb=>{notify=cb;subscriptions++;return ()=>unsubscriptions++;}});
 const retry=()=>limiter.request(async()=>Response.json({cached:true},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'429','x-fad-proxy-refresh-cause':'rate-limit','retry-after':'1'}}));
 const first=retry();await new Promise(setImmediate);const waiting=limiter.request(async()=>{throw Error('queued request must not be sent')});await new Promise(setImmediate);assert.equal(subscriptions,1);notify();
 assert.deepEqual(await (await first).json(),{cached:true});await assert.rejects(waiting,e=>e.code==='PROXY_RETRY_SKIPPED');assert.equal(unsubscriptions,1);
 assert.equal((await limiter.request(async()=>new Response('available'))).status,200,'fresh requests remain possible');
});

test('TTY skip listeners restore raw and paused state and leave unrelated keys alone',async()=>{
 const {EventEmitter}=require('node:events'),{ttySkipSubscription}=require('../lib/providers/proxy-throttle');
 for(const raw of [false,true])for(const paused of [false,true]){
  const input=new EventEmitter();input.isTTY=true;input.isRaw=raw;let isPaused=paused,calls=0;
  input.setRawMode=value=>{input.isRaw=value};input.isPaused=()=>isPaused;input.resume=()=>{isPaused=false};input.pause=()=>{isPaused=true};
  const dispose=ttySkipSubscription(()=>calls++,input);input.emit('data',Buffer.from('q'));input.emit('data',Buffer.from('\x1b[A'));input.emit('data',Buffer.from('some pasted text'));assert.equal(calls,0);input.emit('data',Buffer.from('s'));assert.equal(calls,1);input.emit('data',Buffer.from('\x1b'));await new Promise(resolve=>setTimeout(resolve,550));assert.equal(calls,2);dispose();assert.equal(input.isRaw,raw);assert.equal(isPaused,paused);assert.equal(input.listenerCount('data'),0);
 }
 assert.equal(ttySkipSubscription(()=>{},{isTTY:false}),null);
});

test('TTY Ctrl+C restores input before forwarding the interrupt and setup failure rolls back raw mode',()=>{
 const {EventEmitter}=require('node:events'),{ttySkipSubscription}=require('../lib/providers/proxy-throttle'),input=new EventEmitter();input.isTTY=true;input.isRaw=false;let paused=true,signalled=0;
 input.setRawMode=v=>{input.isRaw=v};input.isPaused=()=>paused;input.pause=()=>{paused=true};input.resume=()=>{paused=false};
 ttySkipSubscription(()=>assert.fail('not a skip'),input,()=>{signalled++;assert.equal(input.isRaw,false);assert.equal(paused,true);assert.equal(input.listenerCount('data'),0);});input.emit('data',Buffer.from('\x03'));assert.equal(signalled,1);
 input.resume=()=>{throw Error('resume failed')};assert.equal(ttySkipSubscription(()=>{},input),null);assert.equal(input.isRaw,false);assert.equal(input.listenerCount('data'),0);
});

test('mixed transient and quota retries share the cap and three second spacing',async()=>{
 let time=0,calls=0;const times=[];const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
 const response=await limiter.request(async()=>{times.push(time);calls++;return calls<=2?new Response('',{status:502}):new Response('',{status:429,headers:{'retry-after':'1'}})});
 assert.equal(response.status,429);assert.equal(calls,16);assert.equal(time,45000);assert.ok(times.slice(1).every((t,i)=>t-times[i]>=3000));
});

test('skipping an uncached limited request reports a structured skipped error',async()=>{
 let skip;const limiter=createProxyThrottle({sleep:()=>new Promise(()=>{}),warn:()=>{},subscribeSkip:cb=>{skip=cb;return ()=>{}}});
 const pending=limiter.request(async()=>new Response('',{status:503,headers:{'x-fad-proxy':'denied','retry-after':'3'}}));await new Promise(setImmediate);skip();await assert.rejects(pending,e=>e.code==='PROXY_RETRY_SKIPPED'&&e.status===503);
});

test('network failure after a stale quota response retains readable cached data but abort remains explicit',async()=>{
 for(const abort of [false,true]){
  let time=0,calls=0;const signal=new AbortController();const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
  const pending=limiter.request(async()=>{if(++calls===1)return Response.json({cached:true},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'429','x-fad-proxy-refresh-cause':'rate-limit','retry-after':'1'}});if(abort){signal.abort();throw Error('transport interrupted');}throw Error('connection lost');},signal.signal);
  if(abort)await assert.rejects(pending,e=>e.name==='AbortError');else{const response=await pending;assert.equal(response.headers.get('x-fad-proxy'),'stale');assert.deepEqual(await response.json(),{cached:true});}assert.equal(calls,2);
 }
});

test('skip stops transient retries while permitting initial lookups of other resources',async()=>{
 let skip,time=0,calls=0;const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms;return new Promise(()=>{})},warn:()=>{},subscribeSkip:cb=>{skip=cb;return ()=>{}}});
 const pending=limiter.request(async()=>new Response('',{status:429,headers:{'retry-after':'3'}}));await new Promise(setImmediate);skip();await assert.rejects(pending,e=>e.code==='PROXY_RETRY_SKIPPED');
 const response=await limiter.request(async()=>{calls++;return new Response('',{status:502})});assert.equal(response.status,502);assert.equal(calls,1);
});


test('each resource receives all 15 retries even after a previous resource exhausted its allowance',async()=>{
 let time=0;const messages=[];
 const limiter=createProxyThrottle({intervalMs:0,now:()=>time,sleep:async ms=>{time+=ms},warn:m=>messages.push(m)});
 for(let resource=0;resource<3;resource++){
  let calls=0;
  const result=await limiter.request(async()=>{
   calls++;
   if(resource===2 && calls===16)return new Response('recovered');
   return Response.json({cached:resource},{headers:{'x-fad-proxy':'stale','x-fad-proxy-reason':'refresh-failed','x-fad-proxy-refresh-status':'503','x-fad-proxy-refresh-cause':'admission','retry-after':'3'}});
  },null,{label:'npm.package'});
  assert.equal(calls,16);
  if(resource===2)assert.equal(await result.text(),'recovered');
  else assert.deepEqual(await result.json(),{cached:resource});
 }
 assert.equal(time,135000);
 assert.doesNotMatch(messages.join('\n'),/budget exhausted|rate limit.*503|No further retries/);
 assert.equal(messages.filter(m=>/retry 15\/15 for this request/.test(m)).length,3);
 assert.match(messages[0],/Proxy upstream request temporarily deferred \[npm.package\].*refresh HTTP 503; cached response available/);
});

test('an exhausted request budget does not cancel or disable a concurrent retry',async()=>{
 let time=0;const releases=[];
 const limiter=createProxyThrottle({intervalMs:0,now:()=>time,sleep:()=>new Promise(resolve=>releases.push(resolve)),warn:()=>{}});
 let calls=0;
 const recovering=limiter.request(async()=>++calls===1?new Response('',{status:429}):new Response('ok'));
 await new Promise(setImmediate);
 const denied=limiter.request(async()=>new Response('',{status:503,headers:{'x-fad-proxy':'denied'}}),null,{waitBudgetMs:0});
 await new Promise(setImmediate);
 time=3000;releases.splice(0).forEach(resolve=>resolve());
 assert.equal((await denied).status,503);
 assert.equal((await recovering).status,200);
 assert.equal(calls,2);
});

test('hosted transport and HTTP outages announce every retry with its resource and delay', async () => {
  let time=0,calls=0;
  const messages=[];
  const limiter=createProxyThrottle({now:()=>time, sleep:async ms=>{time+=ms},warn:m=>messages.push(m)});
  const result=await limiter.request(async()=>{
    calls++;
    if(calls===1) throw Error('connection lost');
    if(calls===2) return new Response(null,{status:503,headers:{'retry-after':'9'}});
    return new Response('recovered');
  },null,{label:'osv.vuln'});
  assert.equal(await result.text(),'recovered');
  assert.equal(time,12000);
  assert.match(messages[0],/osv.vuln.*transport failure.*3s.*retry 1\/2/);
  assert.match(messages[1],/osv.vuln.*HTTP 503.*9s.*retry 2\/2/);
});
