const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");
const childProcess = require("node:child_process");

const modulePath = path.join(__dirname, "../lib/cache-archive.js");
const source = fs.readFileSync(modulePath, "utf8");
const localRequire = createRequire(modulePath);

function loadCache(home, spawn = childProcess.spawn) {
	const module = { exports: {} };
	vm.runInNewContext(source, {
		module, console, process,
		require(name) {
			if (name === "os") return { ...os, homedir: () => home };
			if (name === "child_process") return { ...childProcess, spawn };
			return localRequire(name);
		},
	}, { filename: modulePath });
	return module.exports;
}

for (const [mode, opts] of [["merge", {}], ["replace", { replace: true }], ["force", { force: true }]]) {
	test(`tar ${mode}: archive paths stay with Node, including spaces and drive-like names`, async t => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad archive paths "));
		t.after(() => fs.rmSync(root, { recursive: true, force: true }));
		const online = path.join(root, "online é"), offline = path.join(root, "offline é");
		fs.mkdirSync(path.join(online, ".vigie-vuln"), { recursive: true });
		fs.writeFileSync(path.join(online, ".vigie-vuln", "payload.json"), '{"id":"imported"}');
		fs.writeFileSync(path.join(online, ".vigie-vuln", "config.json"), '{"secret":true}');
		// On POSIX a literal Windows-style name exercises ':' and backslashes too.
		const archive = path.join(root, process.platform === "win32" ? "cache snapshot.tgz" : "C:\\cache snapshot.tgz");
		const calls = [];
		const spawn = (command, args, options) => {
			assert.equal(command, "tar");
			assert.equal(args[1], "-", "tar must read/write an inherited descriptor, not parse the archive path");
			assert.ok(!args.includes("-C"), "the OS must set the working directory");
			assert.ok(args.every(arg => !arg.includes(root)));
			calls.push({ args, options });
			return childProcess.spawn(command, args, options);
		};
		const exported = await loadCache(online, spawn).exportCache(archive);
		assert.ok(exported.size > 0);
		await loadCache(offline, spawn).importCache(archive, opts);
		assert.deepEqual(JSON.parse(fs.readFileSync(path.join(offline, ".vigie-vuln", "payload.json"))), { id: "imported" });
		assert.ok(!fs.existsSync(path.join(offline, ".vigie-vuln", "config.json")));
		assert.equal(calls.length, 2);
		assert.equal(calls[0].options.cwd, online);
		assert.ok(calls[1].args.includes("--no-same-owner"));
		assert.ok(!fs.readdirSync(offline).some(name => name.includes(".import-")));
	});
}

test("failed tar import reports the error, cleans staging and closes the archive", async t => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad archive failure "));
	t.after(() => fs.rmSync(root, { recursive: true, force: true }));
	const archive = path.join(root, "invalid.tar.gz");
	fs.writeFileSync(archive, "not an archive");
	for (const missing of [false, true]) {
		let fd;
		const cache = loadCache(root, (command, args, options) => {
			fd = options.stdio[0];
			return childProcess.spawn(missing ? path.join(root, "missing-tar") : command, args, options);
		});
		await assert.rejects(cache.importCache(archive), missing ? /ENOENT/ : /tar failed/);
		assert.throws(() => fs.fstatSync(fd), { code: "EBADF" });
		assert.ok(!fs.readdirSync(root).some(name => name.includes(".import-")));
	}
});

for (const opts of [{}, {replace:true}]) test(`legacy archive imports into the new cache (${opts.replace?'replace':'merge'})`, async t => {
	const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-legacy-archive-'));
	t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
	const old=path.join(root,'old'), dest=path.join(root,'new'), archive=path.join(root,'old.tar.gz');
	fs.mkdirSync(path.join(old,'.fad-checker'),{recursive:true});fs.mkdirSync(dest);
	fs.writeFileSync(path.join(old,'.fad-checker','payload.json'),'legacy');
	childProcess.execFileSync('tar',['-czf',archive,'.fad-checker'],{cwd:old});
	await loadCache(dest).importCache(archive,opts);
	assert.equal(fs.readFileSync(path.join(dest,'.vigie-vuln','payload.json'),'utf8'),'legacy');
	assert.equal(fs.existsSync(path.join(dest,'.fad-checker')),false);
});

for (const opts of [{}, {replace:true}]) test(`cache import rejects archived links (${opts.replace?'replace':'merge'})`, async t => {
  if (process.platform === 'win32') return t.skip('archive fixture uses Unix symlinks');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'vv-link-archive-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const source=path.join(root,'source'), dest=path.join(root,'dest'), archive=path.join(root,'bad.tar.gz');
  fs.mkdirSync(path.join(source,'.vigie-vuln'),{recursive:true}); fs.mkdirSync(dest);
  fs.symlinkSync(path.join(root,'outside'),path.join(source,'.vigie-vuln','redirect'));
  childProcess.execFileSync('tar',['-czf',archive,'.vigie-vuln'],{cwd:source});
  await assert.rejects(loadCache(dest).importCache(archive,opts),/links or special files/);
  assert.equal(fs.existsSync(path.join(dest,'.vigie-vuln','redirect')),false);
});
