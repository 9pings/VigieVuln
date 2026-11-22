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
    require('../lib/cache-db').closeCacheDbs();
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
  assert.equal(evaluateConfiguration(restricted, 'php:php', '8.3.1'), null);
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
