'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {execFile, spawnSync} = require('node:child_process');
const exec = require('node:util').promisify(execFile);
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const cli = path.resolve(__dirname,'../vigievuln.js');

// mkfs and qemu-img create test media only. The collector itself runs with an empty PATH.
const available = tool => spawnSync(tool,[tool === 'mkfs.ext4' ? '-V' : '--version']).status === 0;
test('VM disk reader inventories Linux partitions, skips links, and reports unreadable partitions', {
  skip:process.platform !== 'linux' || !available('mkfs.ext4'),
}, async t => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-disk-test-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const tree=path.join(dir,'root'), pkg=path.join(tree,'srv/app/node_modules/library');
  fs.mkdirSync(pkg,{recursive:true});
  fs.writeFileSync(path.join(tree,'srv/app/package.json'),'{"name":"shop","version":"3.1.0"}');
  fs.writeFileSync(path.join(pkg,'package.json'),'{"name":"library","version":"1.0.0"}');
  fs.writeFileSync(path.join(tree,'libc6:amd64.list'),'lib/x86_64-linux-gnu/libc.so.6\n');
  fs.symlinkSync('/etc',path.join(tree,'alias'));
  const scratch=path.join(dir,'scratch'), home=path.join(dir,'home');
  fs.mkdirSync(scratch);
  const env={...process.env,PATH:'',HOME:home,TMPDIR:scratch};
  const raw=path.join(dir,'fs.raw');
  await exec('mkfs.ext4',['-q','-F','-d',tree,raw,'8M']);
  const output=path.join(dir,'inventory.json');
  const collect=file=>exec(process.execPath,[cli,'system','collect',file,'--output',output],{env});
  const read=()=>require('../lib/artifacts/scan').readSnapshot(output);
  const verify=target=>{
    assert.equal(target.metadata.acquisition.kind,'vm-disk');
    assert.ok(target.metadata.systemApplications.inventory.some(c=>c.name==='shop' && c.version==='3.1.0'));
    assert.ok(target.deps.some(c=>c.name==='library' && c.systemSection==='dependency' && c.imageRole==='transitive'));
    assert.ok(!target.deps.some(c=>c.artifactPath?.startsWith('alias/')));
    assert.deepEqual(fs.readdirSync(scratch),[]);
    assert.equal(fs.existsSync(home),false);
  };
  await collect(raw);
  verify(read()[0]);
  if (available('qemu-img')) {
    for (const [format,ext] of [['qcow2','qcow2'],['vhdx','vhdx'],['vpc','vhd'],['vmdk','vmdk'],['vdi','vdi']]) {
      const file=path.join(dir,'disk.'+ext);
      await exec('qemu-img',['convert','-f','raw','-O',format,raw,file]);
      await collect(file);
      verify(read()[0]);
    }
  }
  const partition=fs.readFileSync(raw), first=2048, sectors=partition.length/512;
  const disk=Buffer.alloc((first+2*sectors)*512);
  disk.writeUInt16LE(0xaa55,510);
  function putChs(lba, offset) {
    const cylinder=Math.floor(lba/(255*63));
    disk[offset]=Math.floor(lba/63)%255;
    disk[offset+1]=(lba%63+1) | ((cylinder>>2)&0xc0);
    disk[offset+2]=cylinder&0xff;
  }
  for (let i=0;i<2;i++) {
    const offset=446+16*i;
    putChs(first+i*sectors,offset+1);
    putChs(first+(i+1)*sectors-1,offset+5);
    disk[offset+4]=0x83;
    disk.writeUInt32LE(first+i*sectors,offset+8);
    disk.writeUInt32LE(sectors,offset+12);
    partition.copy(disk,(first+i*sectors)*512);
  }
  const mbr=path.join(dir,'partitions.img');
  fs.writeFileSync(mbr,disk);
  await collect(mbr);
  const both=read();
  assert.equal(both.length,2);
  assert.notEqual(both[0].id,both[1].id);
  both.forEach(verify);
  disk.fill(0,(first+sectors)*512);
  fs.writeFileSync(mbr,disk);
  await assert.rejects(collect(mbr),{code:2});
  const [kept]=read();
  verify(kept);
  assert.ok(kept.coverage.some(c=>c.collector==='artifact-reader' && c.execution==='partial'));
  const saved=fs.readFileSync(output);
  fs.writeFileSync(mbr,'not an image');
  await assert.rejects(collect(mbr));
  assert.deepEqual(fs.readFileSync(output),saved);
  assert.deepEqual(fs.readdirSync(scratch),[]);
});
