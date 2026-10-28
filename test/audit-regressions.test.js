'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { parseRequirementsTxt } = require('../lib/codecs/pypi/parse');

test('malformed Composer names and versions are rejected promptly', () => {
  const script = `const {validateResource}=require('./lib/resource-cache/validate');
    const {cmpComposerVersions}=require('./lib/packagist-audit');
    for (const name of ['a'.repeat(190)+'!', 'vendor/'+'a'.repeat(180)+'!']) {
      try { validateResource({provider:'packagist',type:'package',params:{name}}); process.exit(2); } catch(e) { if(e.status!==400) throw e; }
    }
    if (cmpComposerVersions('1.0-beta'+'1'.repeat(200)+'!', '1.0') !== null) process.exit(3);`;
  const result = spawnSync(process.execPath, ['-e', script], {cwd:path.join(__dirname,'..'), timeout:3000});
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, String(result.stderr));
});

test('requirements includes cannot read files outside the scan root, including symlinks', t => {
  const parent=fs.mkdtempSync(path.join(os.tmpdir(),'vv-include-'));
  t.after(()=>fs.rmSync(parent,{recursive:true,force:true}));
  const root=path.join(parent,'project'); fs.mkdirSync(root);
  fs.writeFileSync(path.join(parent,'secret.txt'),'secret-dependency==9.9.9\n');
  fs.writeFileSync(path.join(root,'requirements.txt'),'-r ../secret.txt\nallowed==1.0\n');
  const result=parseRequirementsTxt(path.join(root,'requirements.txt'),root);
  assert.deepEqual(result.deps.map(d=>d.name),['allowed']);
  assert.match(result.missing[0],/outside scan root/);
  try { fs.symlinkSync(path.join(parent,'secret.txt'),path.join(root,'link.txt')); }
  catch(e) { if (['EPERM','EACCES'].includes(e.code)) return; throw e; }
  fs.writeFileSync(path.join(root,'requirements.txt'),'-r link.txt\n');
  assert.equal(parseRequirementsTxt(path.join(root,'requirements.txt'),root).deps.length,0);
});
