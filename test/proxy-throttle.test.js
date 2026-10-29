const test = require('node:test');
const assert = require('node:assert/strict');
const {createProxyThrottle} = require('../lib/proxy-throttle');

test('proxy 429 respects Retry-After, retries the request and announces the wait', async () => {
  let time=10000, calls=0; const waits=[], messages=[];
  const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{waits.push(ms);time+=ms},warn:m=>messages.push(m)});
  const response=await limiter.request(async()=>++calls===1 ? new Response('',{status:429,headers:{'retry-after':'3'}}) : new Response('ok'),null);
  assert.equal(response.status,200); assert.equal(calls,2); assert.ok(waits.some(ms=>ms>=3000));
  assert.match(messages.join('\n'),/HTTP 429.*3s/);
});

test('persistent proxy rate limits stop after three retries', async () => {
  let time=0,calls=0; const limiter=createProxyThrottle({now:()=>time,sleep:async ms=>{time+=ms},warn:()=>{}});
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
  const {createSourceHealth}=require('../lib/source-health');
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
