const { test } = require("node:test");
const assert = require("node:assert");
const { enrichUnmanaged } = require("../lib/inventory/unmanaged");
const { makeDepRecord } = require("../lib/inventory/dep-record");

function rec(name, hashes) { return makeDepRecord({ ecosystem: "binary", name, manifestPath: `/p/${name}`, provenance: "binary", hashes, declaredName: name }); }

test("enrichUnmanaged sets identity + integrity per record (deps.dev=pristine, circl=known-good, none=unknown)", async () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", rec("a.dll", { sha1: "a".repeat(40), sha256: "1".repeat(64) }));
	resolved.set("binary:/p/b.so", rec("b.so", { sha1: "b".repeat(40), sha256: "2".repeat(64) }));
	resolved.set("binary:/p/c.so", rec("c.so", { sha1: "c".repeat(40), sha256: "3".repeat(64) }));
	resolved.set("g:a", makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/pom.xml" })); // untouched

	const fetcher = async (url) => {
		if (url.includes("deps.dev")) {
			if (url.includes(encodeURIComponent(Buffer.from("a".repeat(40), "hex").toString("base64")))) {
				return { ok: true, json: async () => ({ results: [{ version: { versionKey: { system: "NUGET", name: "A.Pkg", version: "2.0" } } }] }) };
			}
			return { ok: true, json: async () => ({ results: [] }) };
		}
		// CIRCL: b.so known, c.so unknown
		if (url.endsWith("2".repeat(64))) return { ok: true, json: async () => ({ FileName: "libb.so", ProductCode: { ProductName: "libb", ProductVersion: "1.1" }, db: "ubuntu" }) };
		return { ok: true, json: async () => ({ message: "Non existing SHA-256" }) };
	};

	const summary = await enrichUnmanaged(resolved, { fetcher, cache: {} });
	const a = resolved.get("binary:/p/a.dll"), b = resolved.get("binary:/p/b.so"), c = resolved.get("binary:/p/c.so");
	assert.deepEqual(a.identity, { ecosystem: "nuget", name: "A.Pkg", version: "2.0", source: "deps.dev" });
	assert.equal(a.integrity, "pristine");
	assert.equal(b.integrity, "known-good");
	assert.equal(b.identity.name, "libb");
	assert.equal(c.identity, null);
	assert.equal(c.integrity, "unknown");
	assert.equal(resolved.get("g:a").identity, undefined); // managed deps not touched
	assert.deepEqual(summary, { total: 3, identified: 2, pristine: 1, knownGood: 1, unknown: 1, malicious: 0 });
});

test("enrichUnmanaged offline does not call the fetcher", async () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", rec("a.dll", { sha1: "a".repeat(40), sha256: "1".repeat(64) }));
	let called = false;
	await enrichUnmanaged(resolved, { fetcher: async () => { called = true; return { ok: true, json: async () => ({}) }; }, cache: {}, offline: true });
	assert.equal(called, false);
	assert.equal(resolved.get("binary:/p/a.dll").integrity, "unknown");
});

test('image and system binaries never enter source-project hash identification, including cached identities',async()=>{
 const source=rec('vendored.dll',{sha1:'a'.repeat(40),sha256:'1'.repeat(64)});
 const image={...rec('image.so',{sha1:'b'.repeat(40),sha256:'2'.repeat(64)}),artifactTargetId:'image:1'};
 const system={...rec('host.so',{sha1:'c'.repeat(40),sha256:'3'.repeat(64)}),artifactTargetId:'host:1'};
 const untouched=JSON.stringify([image,system]),calls=[],progress=[];
 const result=await enrichUnmanaged(new Map([['project',source],['image',image],['host',system]]),{
   cache:{},fetcher:async url=>{calls.push(url);return {ok:true,json:async()=>({results:[{version:{versionKey:{system:'NUGET',name:'Source.Package',version:'1.0'}}}]})};},
   onProgress:(done,total)=>progress.push([done,total]),
 });
 assert.equal(result.total,1);assert.equal(result.identified,1);assert.equal(calls.length,1);
 assert.equal(source.identity.name,'Source.Package');assert.deepEqual(progress,[[1,1]]);
 assert.equal(JSON.stringify([image,system]),untouched);
 const excluded=await enrichUnmanaged(new Map([['image',image],['host',system]]),{
   cache:{},fetcher:()=>{throw Error('image binary must not be queried');},
   onProgress:()=>{throw Error('image binary must not enter progress');},
 });
 assert.equal(excluded.total,0);
});
