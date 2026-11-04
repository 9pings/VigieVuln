'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const maven = require('../lib/codecs/maven.codec');
const binary = require('../lib/codecs/binary.codec');
const { buildFindings } = require('../lib/json-export');
const { diffFindings } = require('../lib/diff');
function tree(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-isolation-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
const goodPom = '<project><modelVersion>4.0.0</modelVersion><groupId>demo</groupId><artifactId>app</artifactId><version>1.0</version><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.2.3</version></dependency></dependencies></project>';

test('malformed POM warns with its path, preserves valid modules and never counts failure as parsed', async t => {
  const dir = tree(t), bad = path.join(dir, 'broken', 'pom.xml'), good = path.join(dir, 'pom.xml');
  fs.mkdirSync(path.dirname(bad)); fs.writeFileSync(bad, '<project><broken>'); fs.writeFileSync(good, goodPom);
  const result = await maven.collect(dir, { scanJars: false });
  assert.ok(result.deps.has('org.example:lib'));
  assert.deepEqual(result.parsedManifests, [good]);
  assert.deepEqual(result._maven.pomFiles, [good]);
  assert.ok(result.warnings.some(w => w.type === 'dependency-coverage' && w.reason === 'pom-parse-error' && w.manifestPath === bad));
  const doc = buildFindings({ resolvedDeps: result.deps, warnings: result.warnings });
  const delta = diffFindings({ cve: [{ id: 'CVE-2099-0001', dep: { coord: 'demo:old', version: '1' } }] }, doc);
  assert.equal(delta.cve.removed.length, 0); assert.equal(delta.cve.unassessed.length, 1);
});

test('POM read failure is explicit even when permissions tests run as root', async t => {
  const dir = tree(t), file = path.join(dir, 'pom.xml'); fs.writeFileSync(file, goodPom);
  const read = fs.readFileSync;
  t.mock.method(fs, 'readFileSync', function(fp, ...args) {
    if (fp === file) throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
    return read.call(this, fp, ...args);
  });
  const result = await maven.collect(dir, { scanJars: false });
  assert.equal(result.deps.size, 0); assert.equal(result._maven.pomFiles.length, 0);
  assert.ok(result.warnings.some(w => w.manifestPath === file && /permission denied/.test(w.message)));
});

test('oversized binary cannot erase other binaries; detection avoids hashing it', async t => {
  const dir = tree(t), huge = path.join(dir, 'huge.dll');
  fs.writeFileSync(path.join(dir, 'before.dll'), 'MZfirst'); fs.writeFileSync(path.join(dir, 'after.dll'), 'MZlast');
  const fd = fs.openSync(huge, 'w');
  try { fs.writeSync(fd, Buffer.from('MZ')); fs.ftruncateSync(fd, 5 * 1024 ** 3); } finally { fs.closeSync(fd); }
  assert.equal(binary.detect(dir), true);
  const result = await binary.collect(dir);
  assert.deepEqual([...result.deps.values()].map(d => d.name).sort(), ['after.dll', 'before.dll']);
  assert.ok(result.warnings.some(w => w.type === 'dependency-coverage' && w.manifestPath === huge && /limit/.test(w.message)));
});

test('unreadable binary is isolated and identifies its path', async t => {
  const dir = tree(t), bad = path.join(dir, 'bad.dll');
  fs.writeFileSync(bad, 'MZbad'); fs.writeFileSync(path.join(dir, 'good.dll'), 'MZgood');
  const open = fs.openSync;
  t.mock.method(fs, 'openSync', function(fp, ...args) {
    if (fp === bad) throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
    return open.call(this, fp, ...args);
  });
  const result = await binary.collect(dir);
  assert.deepEqual([...result.deps.values()].map(d => d.name), ['good.dll']);
  assert.ok(result.warnings.some(w => w.type === 'dependency-coverage' && w.manifestPath === bad));
});

test('multi-chunk binary hashes match full-file hashes without readFileSync', async t => {
  const dir = tree(t), file = path.join(dir, 'large.so');
  const bytes = Buffer.alloc(3 * 1024 * 1024 + 17, 123); bytes.set([0x7f, 0x45, 0x4c, 0x46]); fs.writeFileSync(file, bytes);
  const expected = { sha1: crypto.createHash('sha1').update(bytes).digest('hex'), sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const read = fs.readFileSync;
  t.mock.method(fs, 'readFileSync', function(fp, ...args) { if (fp === file) throw Error('whole-file read forbidden'); return read.call(this, fp, ...args); });
  const result = await binary.collect(dir);
  assert.equal(result.warnings.length, 0);
  assert.deepEqual([...result.deps.values()][0].hashes, expected);
});
