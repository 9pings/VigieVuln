'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { acquireInventories, assessInventories } = require('../lib/artifacts/scan');
const { catalog, imageProduct } = require('../lib/artifacts/product-catalog');
const { assessProductAdvisories, evaluateConfiguration } = require('../lib/artifacts/product-advisories');
const { renderImageCves, renderArtifactEvidence } = require('../lib/artifacts/report');

function temp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-fingerprints-'));
  t.after(() => {
    require('../lib/cache/db').closeCacheDbs();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}
function elf(text, bundled = false) {
  const buf = Buffer.alloc(1024);
  buf.set([127, 69, 76, 70, 2, 1, 1]);
  buf.writeUInt16LE(3, 16);
  buf.writeUInt16LE(62, 18);
  buf.writeBigUInt64LE(64n, 32);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(1, 56);
  buf.writeUInt32LE(1, 64);
  buf.writeUInt32LE(4, 68);
  buf.writeBigUInt64LE(960n, 96);
  buf.write(text, 321, 'latin1');
  if (bundled) {
    buf.write('\n---- Bun! ----\n', 1000);
    buf.writeBigUInt64LE(1024n, 1016);
  }
  return buf;
}
test('all fingerprint files load, OS names and dependency package names stay distinct', () => {
  const dir = path.resolve(__dirname, '../data/fingerprints');
  const paths = fs.readdirSync(dir, { recursive: true }).filter((s) => s.endsWith('.json'));
  assert.equal(paths.length, catalog.size);
  for (const p of paths) {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, p)));
    assert.equal(catalog.get(doc.id)?.category, doc.category);
    assert.equal(p.split(path.sep)[0], doc.category === 'service' ? 'services' : 'interpreters');
    for (const n of ['executable', 'osPackage']) assert(doc[n].startsWith('^') && doc[n].endsWith('$'));
  }
  for (const [name, id] of [
    ['php8.3-fpm', 'php'],
    ['python3.11-minimal', 'python'],
    ['openssh-server', 'openssh'],
    ['exim4-daemon-heavy', 'exim'],
    ['postgresql-16', 'postgres']
  ])
    assert.equal(imageProduct({ name, ecosystem: 'system' }).id, id);
  for (const name of ['openssh-client', 'postgresql-client-16', 'python3-requests', 'nginx-doc'])
    assert.equal(imageProduct({ name, ecosystem: 'system' }), null);
  assert.equal(imageProduct({ name: 'redis', ecosystem: 'npm' }), null);
});

test('inventory, assessment and both report views carry product identities without requiring a finding', async (t) => {
  const base = temp(t),
    root = path.join(base, 'root'),
    cacheDir = path.join(base, 'cache');
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, 'my-worker'), elf('\0Bun v1.3.0 (Linux x64)\0', true));
  fs.writeFileSync(path.join(root, 'decoy'), elf('AppleWebKit/605.1.15\0Bun v1.3.0 (Linux x64)\0'));
  fs.writeFileSync(path.join(root, 'php'), elf('\0X-Powered-By: PHP/8.3.1\0'));
  fs.writeFileSync(path.join(root, 'nginx'), elf('unknown'));
  const [target] = await acquireInventories(root, { offline: true });
  const bun = target.deps.find((d) => d.ecosystem === 'image-product');
  assert.deepEqual([bun.name, bun.version, bun.artifactPath], ['bun', '1.3.0', 'my-worker']);
  assert.equal(target.deps.find((d) => d.name === 'my-worker').version, null);
  assert.equal(target.deps.find((d) => d.name === 'decoy').binaryEvidence, undefined);
  assert.equal(target.deps.find((d) => d.name === 'php').version, '8.3.1');
  const opts = {
    cacheDir,
    offline: true,
    nativeSources: [],
    enrich: [],
    fetcher: () => assert.fail('offline request')
  };
  const assessed = await assessInventories([target], opts);
  const artifact = assessed.artifacts[0],
    inventory = artifact.productInventory;
  assert(
    inventory.entries.some(
      (e) => e.id === 'bun' && e.advisoryCheck === 'indeterminate' && e.version === '1.3.0'
    )
  );
  assert(inventory.entries.some((e) => e.id === 'nginx' && e.version === null));
  assert(inventory.unobserved.includes('WebKitGTK'));
  assert(artifact.coverage.some((c) => c.product === 'bun' && c.execution === 'not-run'));
  const evidence = renderArtifactEvidence({ artifacts: [artifact] }, 'fr', []);
  assert.match(evidence, /Produits du catalogue sans preuve observée/);
  assert.match(evidence, /Services réseau/);
  assert.match(evidence, /Interpréteurs et moteurs/);
  const match = (dep) => ({ dep, cve: { id: 'CVE-2024-12345' } });
  const cves = renderImageCves(
    { artifacts: [artifact] },
    [match(bun), match(target.deps.find((d) => d.name === 'nginx'))],
    'fr',
    { renderCveTable: () => '' }
  );
  assert.match(cves, /data-image-source="interpreter"/);
  assert.match(cves, /data-image-source="service"/);
});

test('NVD uses product identity and version, replays offline, respects ownership and exclusions', async (t) => {
  const cacheDir = temp(t);
  const record = {
    id: 'CVE-2025-12345',
    published: '2025-01-01T00:00:00Z',
    lastModified: '2025-01-02T00:00:00Z',
    descriptions: [{ lang: 'en', value: 'Fixture' }],
    references: [],
    configurations: [
      {
        nodes: [
          {
            operator: 'OR',
            cpeMatch: [
              { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vulnerable: true, versionEndExcluding: '8.3.2' }
            ]
          }
        ]
      }
    ]
  };
  const dep = {
    name: 'php',
    ecosystem: 'binary',
    version: '8.3.1',
    binaryEvidence: { product: 'php' },
    artifactPath: 'usr/local/bin/php'
  };
  const target = { packages: [], deps: [dep] };
  let calls = 0;
  const fetcher = async (url) => {
    calls++;
    assert.match(new URL(url).searchParams.get('virtualMatchString'), /^cpe:2.3:a:php:php:8\.3\.[12]$/);
    return Response.json({
      startIndex: 0,
      totalResults: 1,
      resultsPerPage: 1,
      vulnerabilities: [{ cve: record }]
    });
  };
  assert.equal((await assessProductAdvisories(target, { cacheDir, fetcher })).matches[0].cve.id, record.id);
  assert.equal((await assessProductAdvisories(target, { cacheDir, offline: true, fetcher })).matches.length, 1);
  dep.version = '8.3.2';
  assert.equal((await assessProductAdvisories(target, { cacheDir, fetcher })).matches.length, 0);
  assert.equal(
    (await assessProductAdvisories(target, { cacheDir, nvd: false, fetcher })).coverage[0].execution,
    'not-applicable'
  );
  dep.osPackageOwners = [{ manager: 'apk', name: 'php83' }];
  assert.equal((await assessProductAdvisories(target, { cacheDir, fetcher })).coverage.length, 0);
  assert.equal(calls, 2);
  const restricted = {
    operator: 'AND',
    nodes: [
      record.configurations[0].nodes[0],
      { cpeMatch: [{ criteria: 'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*', vulnerable: false }] }
    ]
  };
  assert.equal(evaluateConfiguration(restricted, 'php:php', '8.3.1'), true);
  assert.equal(evaluateConfiguration({ ...restricted, negate: true }, 'php:php', '8.3.1'), null);
});

test('a referenced runtime library needs an unambiguous identity before assigning its version', () => {
  const { applyProductVersions } = require('../lib/artifacts/image-products');
  const bin = {
    name: 'python3.12',
    ecosystem: 'binary',
    artifactPath: 'bin/python3.12',
    binaryMetadata: { format: 'elf', machine: 62, bits: 64, needed: ['libpython3.12.so'] }
  };
  const lib = {
    name: 'libpython3.12.so',
    ecosystem: 'binary',
    artifactPath: 'lib/a/libpython3.12.so',
    binaryMetadata: {
      format: 'elf',
      machine: 62,
      bits: 64,
      soname: 'libpython3.12.so',
      products: [{ id: 'python', version: '3.12.5', source: 'Py_Version' }]
    }
  };
  const two = [structuredClone(bin), lib, { ...lib, artifactPath: 'lib/b/libpython3.12.so' }];
  applyProductVersions(two);
  assert.equal(two[0].version, undefined);
  const one = [structuredClone(bin), lib];
  applyProductVersions(one);
  assert.equal(one[0].binaryEvidence.versionPath, lib.artifactPath);
});

test('Bun ELF section format, JavaScriptCore without a release, and conflicting banners', async (t) => {
  const root = temp(t);
  const built = Buffer.alloc(2 * 1024 * 1024);
  elf('\0Bun v1.4.5 (Linux x64)\0').copy(built);
  built.write('vendor/WebKit/Source/JavaScriptCore/runtime\0JSC::VM::VM\0JSC Heap Collector Thread\0', 480);
  built.writeBigUInt64LE(1024n, 40);
  built.writeUInt16LE(64, 58);
  built.writeUInt16LE(3, 60);
  built.writeUInt16LE(1, 62);
  const names = 1088,
    graph = 1152;
  built.writeUInt32LE(3, names + 4);
  built.writeBigUInt64LE(1280n, names + 24);
  built.writeBigUInt64LE(16n, names + 32);
  built.write('\0.bun\0', 1280);
  built.writeUInt32LE(1, graph);
  built.writeUInt32LE(1, graph + 4);
  built.writeBigUInt64LE(1408n, graph + 24);
  built.writeBigUInt64LE(72n, graph + 32);
  built.writeBigUInt64LE(64n, 1408);
  built.write('\n---- Bun! ----\n', 1464);
  fs.writeFileSync(path.join(root, 'invoicing'), built);
  fs.writeFileSync(path.join(root, 'php'), elf('\0X-Powered-By: PHP/8.3.15\0X-Powered-By: PHP/8.2.7\0'));
  const [target] = await acquireInventories(root, { offline: true });
  const embedded = target.deps.filter((d) => d.ecosystem === 'image-product');
  assert(embedded.some((d) => d.name === 'bun' && d.version === '1.4.5'));
  assert(embedded.some((d) => d.name === 'javascriptcore' && d.version === null));
  assert.equal(target.deps.find((d) => d.name === 'php').version, null);
});

test('CPython uses the exported constant and rejects non-final releases', async (t) => {
  const root = temp(t);
  const b = elf('');
  b.writeBigUInt64LE(384n, 40);
  b.writeUInt16LE(64, 58);
  b.writeUInt16LE(3, 60);
  const names = 448,
    symbols = 512;
  b.writeUInt32LE(3, names + 4);
  b.writeBigUInt64LE(640n, names + 24);
  b.writeBigUInt64LE(12n, names + 32);
  b.write('\0Py_Version\0', 640);
  b.writeUInt32LE(11, symbols + 4);
  b.writeBigUInt64LE(672n, symbols + 24);
  b.writeBigUInt64LE(48n, symbols + 32);
  b.writeUInt32LE(1, symbols + 40);
  b.writeBigUInt64LE(24n, symbols + 56);
  b.writeUInt32LE(1, 696);
  b[700] = 0x11;
  b.writeUInt16LE(1, 702);
  b.writeBigUInt64LE(768n, 704);
  b.writeBigUInt64LE(8n, 712);
  b.writeUInt32LE(0x030c10f0, 768);
  const fp = path.join(root, 'python3.12');
  fs.writeFileSync(fp, b);
  let [target] = await acquireInventories(root, { offline: true });
  assert.equal(target.deps[0].version, '3.12.16');
  b.writeUInt32LE(0x030c10c1, 768);
  fs.writeFileSync(fp, b);
  [target] = await acquireInventories(root, { offline: true });
  assert.equal(target.deps[0].version, null);
});

test('Apache and PHP critical advisory ranges distinguish the affected and fixed upstream releases offline',async t=>{
  const cacheDir=temp(t);
  // Release boundaries from the Apache 2.4 security notices and PHP 7.4.33
  // changelog. Use the matching NVD CPE leaves, including the exclusive fix.
  const pin=(product,version)=>({vulnerable:true,criteria:'cpe:2.3:a:'+product+':'+version+':*:*:*:*:*:*:*'});
  const records=[
    ['CVE-2021-41773',[pin('apache:http_server','2.4.49')]],
    ['CVE-2021-42013',[pin('apache:http_server','2.4.49'),pin('apache:http_server','2.4.50')]],
    ['CVE-2022-37454',[{...pin('php:php','*'),versionStartIncluding:'7.2.0',versionEndExcluding:'7.4.33'}]],
  ].map(([id,cpeMatch])=>({cve:{id,published:'2022-11-03T00:00:00Z',lastModified:'2022-11-03T00:00:00Z',
    descriptions:[{lang:'en',value:id}],references:[],configurations:[{nodes:[{operator:'OR',cpeMatch}]}]}}));
  for (const [product,name,version,expected] of [
    ['apache','httpd','2.4.49',['CVE-2021-41773','CVE-2021-42013']],['apache','httpd','2.4.51',[]],
    ['php','php-fpm','7.4.0',['CVE-2022-37454']],['php','php-fpm','7.4.33',[]],
  ]){
    const artifactPath='usr/local/bin/'+name,dep={ecosystem:'binary',name,version,artifactPath,binaryEvidence:{product}};
    const target={packages:[],deps:[dep]};
    const relevant=records.filter(({cve})=>cve.configurations[0].nodes[0].cpeMatch[0].criteria.includes(':'+catalog.get(product).cpe+':'));
    const fetcher=()=>Response.json({startIndex:0,totalResults:relevant.length,resultsPerPage:relevant.length,vulnerabilities:relevant});
    for(const offline of [false,true]){
      const result=await assessProductAdvisories(target,{cacheDir,offline,fetcher:offline?()=>assert.fail('unexpected offline query'):fetcher});
      assert.equal(result.coverage[0].execution,'completed',result.coverage[0].reason);
      assert.deepEqual(result.matches.map(m=>m.cve.id),expected);
    }
  }
});

test('OS-owned upstream matches remain candidates and yield to an exact downstream assessment', () => {
  const owner={manager:'apk',name:'py3-example',version:'2.0-r1'};
  const match={dep:{osPackageOwners:[owner],ecosystem:'pypi',name:'example',version:'2.0',artifactPath:'lib/example/METADATA'},
    cve:{id:'CVE-2099-1234',sourceAdvisoryId:'GHSA-example'}};
  const observations=require('../lib/artifacts/applications').upstreamPackageObservations;
  const [obs]=observations([match],[],[]);
  assert.equal(obs.source,'osv-upstream');
  assert.equal(obs.status,'possible');
  assert.deepEqual(obs.evidence.packageOwner,owner);
  assert.deepEqual(observations([match],[{dep:{...owner,ecosystem:'system'},cve:match.cve}],[]),[]);
  assert.deepEqual(observations([match],[],[{id:match.cve.id,dep:owner,status:'fixed'}]),[]);
});

test('product lookups retry HTTP 429 with fresh per-attempt deadlines and retain confirmed empty answers offline',async t=>{
 const cacheDir=temp(t),waits=[],notices=[],signals=[];
 const {guardedFetch,createSourceHealth}=require('../lib/scan/source-health');
 const target={packages:[],deps:[{name:'php',ecosystem:'binary',version:'8.3.1',binaryEvidence:{product:'php'},artifactPath:'usr/local/bin/php'}]};
 const fetcher=guardedFetch({health:createSourceHealth(),retries:2,sleep:async ms=>waits.push(ms),onRetry:n=>notices.push(n),fetch:async(url,opts)=>{
  signals.push(opts.signal);
  return signals.length<3?new Response(null,{status:429,headers:{'retry-after':'12'}}):Response.json({startIndex:0,totalResults:0,resultsPerPage:0,vulnerabilities:[]});
 }});
 const live=await assessProductAdvisories(target,{cacheDir,fetcher});
 assert.equal(live.coverage[0].execution,'completed');assert.equal(live.coverage[0].result,'no-match');
 assert.deepEqual(waits,[12000,12000]);assert.equal(notices.length,2);
 assert.notEqual(signals[0],signals[1]);assert.notEqual(signals[1],signals[2]);
 const repository=require('../lib/cache/repository').createCacheRepository(cacheDir);
 const key=JSON.stringify(['php:php','8.3.1']);
 const old=repository.get('image-product-nvd/2',key);
 repository.put('image-product-nvd/2',key,old.value,{fetchedAt:Date.now()-86400000});
 const replay=await assessProductAdvisories(target,{cacheDir,offline:true,fetcher:()=>assert.fail('offline network')});
 assert.equal(replay.coverage[0].execution,'completed');assert.deepEqual(replay.matches,[]);
});

test('unidentified runtime version records the applicability limit without a network outage',async t=>{
 const cacheDir=temp(t),target={packages:[],deps:[{name:'php',ecosystem:'binary',version:null,binaryEvidence:{product:'php'},artifactPath:'usr/local/bin/php'}]};
 const result=await assessProductAdvisories(target,{cacheDir,fetcher:()=>assert.fail('no exact version to query')});
 assert.equal(result.coverage[0].execution,'not-applicable');
 assert.equal(result.coverage[0].affectsCompleteness,false);
 assert.match(result.coverage[0].reason,/No exact runtime version/);
});

test('deployment prerequisites are assumed while the vulnerable product and version remain required',()=>{
 const apache={vulnerable:true,criteria:'cpe:2.3:a:apache:http_server:*:*:*:*:*:windows:x64:*',versionEndExcluding:'2.4.62'};
 const windows={vulnerable:false,criteria:'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*'};
 const config={operator:'AND',nodes:[{cpeMatch:[apache]},{cpeMatch:[windows]}]};
 assert.equal(evaluateConfiguration(config,'apache:http_server','2.4.49'),true);
 assert.equal(evaluateConfiguration(config,'apache:http_server','2.4.62'),false);
 assert.equal(evaluateConfiguration({...config,operator:'OR'},'apache:http_server','2.4.62'),false);
 const odoo={vulnerable:true,criteria:'cpe:2.3:a:odoo:odoo:*:*:*:*:community:*:*:*',versionEndIncluding:'13.0'};
 const python={vulnerable:false,criteria:'cpe:2.3:a:python:python:*:*:*:*:*:*:*:*',versionStartIncluding:'3.6'};
 assert.equal(evaluateConfiguration({operator:'AND',nodes:[{cpeMatch:[odoo]},{cpeMatch:[python]}]},'python:python','3.13.18'),false);
 assert.equal(evaluateConfiguration({cpeMatch:[{...apache,criteria:'cpe:2.3:a:apache:http_server:2.4.49:alpha1:*:*:*:*:*:*'}]},'apache:http_server','2.4.49'),null);
});

test('product cache from the previous environment policy cannot hide newly included findings',async t=>{
 const cacheDir=temp(t),repo=require('../lib/cache/repository').createCacheRepository(cacheDir);
 repo.put('image-product-nvd/1',JSON.stringify(['php:php','8.3.1']),{records:[],unknown:['CVE-2025-12345']},{fetchedAt:Date.now()});
 const target={packages:[],deps:[{name:'php',ecosystem:'binary',version:'8.3.1',binaryEvidence:{product:'php'},artifactPath:'usr/local/bin/php'}]};
 let requests=0;
 const result=await assessProductAdvisories(target,{cacheDir,fetcher:async()=>{
  requests++;
  return Response.json({startIndex:0,totalResults:1,resultsPerPage:1,vulnerabilities:[{cve:{
   id:'CVE-2025-12345',published:'2025-01-01T00:00:00Z',lastModified:'2025-01-02T00:00:00Z',
   descriptions:[{lang:'en',value:'Example advisory'}],references:[],
   configurations:[{operator:'AND',nodes:[{cpeMatch:[{vulnerable:true,criteria:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',versionEndExcluding:'8.3.2'}]},
    {cpeMatch:[{vulnerable:false,criteria:'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*'}]}]}]
  }}]});
 }});
 assert.equal(requests,1);assert.equal(result.matches.length,1);assert.equal(result.coverage[0].unknown,0);
 const replay=await assessProductAdvisories(target,{cacheDir,offline:true,fetcher:()=>assert.fail('offline network')});
 assert.deepEqual(replay.matches.map(m=>m.cve.id),['CVE-2025-12345']);
});
