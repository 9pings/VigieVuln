const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanBinaries } = require("../lib/codecs/binary/scan");

function tmpTree() {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-bin-"));
	// real ELF .so (magic + padding)
	fs.writeFileSync(path.join(root, "libssl.so.1.1"), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]));
	// real PE .dll
	fs.writeFileSync(path.join(root, "user32.dll"), Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(62)]));
	// PNG renamed .so → must be REJECTED (magic mismatch)
	fs.writeFileSync(path.join(root, "spoof.so"), Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.alloc(60)]));
	// genuine image → rejected (extension not allowlisted)
	fs.writeFileSync(path.join(root, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
	// nested + a skip dir
	fs.mkdirSync(path.join(root, "node_modules"));
	fs.writeFileSync(path.join(root, "node_modules", "ignored.dll"), Buffer.from([0x4d, 0x5a, 0x00, 0x00]));
	fs.mkdirSync(path.join(root, "sub"));
	fs.writeFileSync(path.join(root, "sub", "libz.so"), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]));
	return root;
}

test("scanBinaries finds only magic-confirmed binaries, skips assets + skip-dirs", () => {
	const root = tmpTree();
	const out = scanBinaries(root).sort((a, b) => a.path.localeCompare(b.path));
	const names = out.map(r => path.basename(r.path)).sort();
	assert.deepEqual(names, ["libssl.so.1.1", "libz.so", "user32.dll"]);   // no spoof.so, no logo.png, no node_modules
});

test("scanBinaries records kind, size, hashes, declaredName", () => {
	const root = tmpTree();
	const dll = scanBinaries(root).find(r => path.basename(r.path) === "user32.dll");
	assert.equal(dll.kind, "pe");
	assert.equal(dll.size, 64);
	assert.match(dll.sha1, /^[0-9a-f]{40}$/);
	assert.match(dll.sha256, /^[0-9a-f]{64}$/);
	assert.equal(dll.declaredName, "user32.dll");
});

test('source binary collection excludes Python environments, with an explicit override for system/image inventory',t=>{
	const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-binary-env-'));
	t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
	const binary=Buffer.concat([Buffer.from([0x7f,0x45,0x4c,0x46]),Buffer.alloc(60)]);
	const excluded=['.venv','venv','.tox','site-packages','__pycache__','.mypy_cache'];
	for(const dir of [...excluded,'committed']){
		fs.mkdirSync(path.join(root,'nested',dir),{recursive:true});
		fs.writeFileSync(path.join(root,'nested',dir,'library.so'),binary);
	}
	const progress=[];
	assert.deepEqual(scanBinaries(root,{onProgress:p=>progress.push(p)}).map(r=>path.relative(root,r.path).split(path.sep).join('/')),['nested/committed/library.so']);
	assert.equal(progress.length,1);
	assert.equal(scanBinaries(root,{defaultExcludes:false}).length,excluded.length+1);
	assert.equal(scanBinaries(path.join(root,'nested','.venv')).length,1,'an explicitly selected scan root is still scanned');
});

test('ELF core dumps are rejected by type, independently of name and endianness',t=>{
	const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-binary-core-'));
	t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
	for(const [name,endian,type] of [['core.64',1,4],['innocent.so',2,4],['library.so',1,3],['program',2,2]]){
		const bytes=Buffer.alloc(64);Buffer.from([127,69,76,70,2,endian,1]).copy(bytes);
		if(endian===1)bytes.writeUInt16LE(type,16);else bytes.writeUInt16BE(type,16);
		fs.writeFileSync(path.join(root,name),bytes);
	}
	assert.deepEqual(scanBinaries(root).map(r=>path.basename(r.path)).sort(),['library.so','program']);
	fs.rmSync(path.join(root,'library.so'));fs.rmSync(path.join(root,'program'));
	assert.deepEqual(scanBinaries(root,{detectOnly:true}),[]);
});
