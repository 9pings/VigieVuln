const isolatedTestCache = require('./helpers/isolated-cache')('osv-db-multieco');
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {newOsvIndex, addOsvRecord, matchOsvDbDeps, matchOsvDbRecords, rangeVerdict, compareSemver} = require('../lib/osv-db');
const {makeDepRecord} = require('../lib/dep-record');

test('offline npm index matches an unqueried version using the advisory range', () => {
 const index = newOsvIndex('npm', 1700000000000);
 addOsvRecord(index, {id:'GHSA-test', aliases:['CVE-2020-1234'], affected:[{package:{ecosystem:'npm',name:'@scope/widget'},ranges:[{type:'SEMVER',events:[{introduced:'1.0.0'},{fixed:'1.3.0'}]}]}]});
 const dep = makeDepRecord({ecosystem:'npm',name:'@scope/widget',version:'1.2.0',manifestPath:'package-lock.json'});
 const found = matchOsvDbDeps(new Map([[dep.coordKey,dep]]), index);
 assert.equal(found.length,1);assert.equal(found[0].source,'osv');assert.equal(found[0].cve.id,'CVE-2020-1234');
 assert.equal(found[0].cve.fixVersion,'1.3.0','the proposed semver fix is outside every affected range');
 dep.version='1.3.0';dep.versions=['1.3.0'];assert.equal(matchOsvDbDeps(new Map([[dep.coordKey,dep]]),index).length,0);
});

test('npm fix candidates still covered by another range are skipped', () => {
 const index = newOsvIndex('npm');
 addOsvRecord(index,{id:'GHSA-overlapping',affected:[{package:{ecosystem:'npm',name:'widget'},ranges:[
  {type:'SEMVER',events:[{introduced:'1.0.0'},{fixed:'1.3.0'}]},
  {type:'SEMVER',events:[{introduced:'1.2.0'},{fixed:'1.4.0'}]},
 ]}]});
 const dep=makeDepRecord({ecosystem:'npm',name:'widget',version:'1.2.0'});
 const found=matchOsvDbDeps(new Map([[dep.coordKey,dep]]),index);
 assert.equal(found.length,1);assert.equal(found[0].cve.fixVersion,'1.4.0','1.3.0 remains affected by the overlapping range');
});

test('an undecidable range or version never certifies a proposed npm fix', () => {
 const {vulnToMatch}=require('../lib/osv');
 const dep=makeDepRecord({ecosystem:'npm',name:'widget',version:'1.2.0'});
 const record={id:'GHSA-undecidable',affected:[{package:{ecosystem:'npm',name:'widget'},ranges:[
  {type:'SEMVER',events:[{introduced:'1.0.0'},{fixed:'1.3.0'}]},
  {type:'GIT',events:[{introduced:'0'}]},
 ]}]};
 assert.equal(vulnToMatch(dep,record).cve.fixVersion,null,'a fix cannot be verified safe against the GIT range');
 assert.equal(vulnToMatch({...dep,version:'not-semver'},record).cve.fixVersion,null);
 const malformed=structuredClone(record);malformed.affected[0].ranges.pop();malformed.affected[0].ranges[0].events[1].fixed='not-semver';
 assert.equal(vulnToMatch(dep,malformed).cve.fixVersion,null);
});

test('Go case-sensitive package paths do not collide', () => {
 const index=newOsvIndex('Go');
 addOsvRecord(index,{id:'GO-1',affected:[{package:{ecosystem:'Go',name:'example.org/Lib'},versions:['1.0.0']}]});
 const other=makeDepRecord({ecosystem:'go',name:'example.org/lib',version:'1.0.0'});
 assert.equal(matchOsvDbDeps(new Map([[other.coordKey,other]]),index).length,0);
});

test('unsupported or malformed ranges remain unknown, not clean', () => {
 assert.equal(rangeVerdict('1.0.0',{type:'GIT',events:[{introduced:'0'}]},'npm'),null);
 assert.equal(rangeVerdict('1.0.0',{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0'}]},'PyPI'),null);
 assert.equal(rangeVerdict('not-semver',{type:'SEMVER',events:[{introduced:'0'}]},'npm'),null);
 assert.equal(compareSemver('9007199254740993.0.0','9007199254740992.0.0'),1);
 assert.equal(compareSemver('1.0.0+..','1.0.0'),null);
 const index=newOsvIndex('PyPI');
 addOsvRecord(index,{id:'PYSEC-x',affected:[{package:{ecosystem:'PyPI',name:'Example_Pkg'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0'}]}]}]});
 const dep=makeDepRecord({ecosystem:'pypi',name:'example-pkg',version:'1.0'});const unknown=[];
 assert.equal(matchOsvDbDeps(new Map([[dep.coordKey,dep]]),index,{onUnknown:x=>unknown.push(x)}).length,0);
 assert.equal(unknown.length,1);
});

test('streamed seed matches a never-queried version and rejects tampering', async () => {
 const fs=require('node:fs'), path=require('node:path'), os=require('node:os'), crypto=require('node:crypto');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-osv-stream-'));
 try {
  const file=path.join(dir,'records.jsonl'), rec={id:'GHSA-test',aliases:['CVE-2020-1234'],affected:[{package:{ecosystem:'npm',name:'widget'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0.0'}]}]}]};
  const bytes=Buffer.from(JSON.stringify(rec)+'\n');fs.writeFileSync(file,bytes);
  const meta={recordsFile:file,ecosystem:'npm',recordCount:1,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};
  const dep=makeDepRecord({ecosystem:'npm',name:'widget',version:'1.2.3'}), deps=new Map([[dep.coordKey,dep]]);
  assert.equal((await matchOsvDbRecords(deps,meta)).length,1);
  fs.appendFileSync(file,' ');
  await assert.rejects(matchOsvDbRecords(deps,meta));
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});

test('Maven numeric components beyond safe precision remain unknown', () => {
 const {rangeVerdict}=require('../lib/osv-db');
 assert.equal(rangeVerdict('9007199254740992',{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'9007199254740993'}]},'Maven'),null);
});
