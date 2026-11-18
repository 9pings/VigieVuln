const { test } = require("node:test");
const assert = require("node:assert");

const { diffFindings, summarizeDiff, findingKey, newProductionCveCount } = require("../lib/diff");

function cve(id, coord, version, extra = {}) {
	return { id, severity: extra.severity || "HIGH", suppressed: !!extra.suppressed, cpeFiltered: !!extra.cpeFiltered, dep: { ecosystem: extra.ecosystem || "maven", coord, version } };
}
function doc(cveArr, extra = {}) {
	return { cve: cveArr, eol: extra.eol || [], obsolete: [], outdated: extra.outdated || [], licenses: [] };
}

test("findingKey is stable on id + ecosystem + coord + version", () => {
	const k1 = findingKey(cve("CVE-1", "g:a", "1.0.0"));
	const k2 = findingKey(cve("CVE-1", "g:a", "1.0.0", { severity: "LOW" }));
	assert.strictEqual(k1, k2, "severity does not affect identity");
	assert.notStrictEqual(k1, findingKey(cve("CVE-1", "g:a", "2.0.0")), "version changes identity");
});

test('diff CLI exposes previous and current unassessed findings', t => {
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-diff-console-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const gap={warnings:[{type:'source-unavailable',message:'fixture unavailable'}]};
 const before={...doc([cve('CVE-2024-11111','g:a','1')]),...gap},after={...doc([cve('CVE-2024-22222','g:b','1')]),...gap};
 const base=path.join(dir,'base.json'),current=path.join(dir,'current.json');fs.writeFileSync(base,JSON.stringify(before));fs.writeFileSync(current,JSON.stringify(after));
 const result=spawnSync(process.execPath,[path.resolve(__dirname,'../vigievuln.js'),'diff',base,current],{encoding:'utf8',env:{...process.env,NO_COLOR:'1'}});
 assert.strictEqual(result.status,0,result.stderr);assert.match(result.stdout,/1 previous unassessed/);assert.match(result.stdout,/1 current unassessed/);
});

test("diffFindings classifies added / removed / unchanged CVEs", () => {
	const base = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-2", "g:b", "2.0.0")]);
	const cur = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-3", "g:c", "3.0.0")]);
	const d = diffFindings(base, cur);
	assert.deepStrictEqual(d.cve.added.map(f => f.id), ["CVE-3"]);
	assert.deepStrictEqual(d.cve.removed.map(f => f.id), ["CVE-2"]);
	assert.deepStrictEqual(d.cve.unchanged.map(f => f.id), ["CVE-1"]);
});

test("a version bump shows the old finding removed and the new one added", () => {
	const base = doc([cve("CVE-9", "g:a", "1.0.0")]);
	const cur = doc([cve("CVE-9", "g:a", "1.0.1")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.added.length, 1);
	assert.strictEqual(d.cve.removed.length, 1);
});

test("diffFindings diffs EOL and outdated categories by dep identity", () => {
	const base = { cve: [], eol: [{ product: "java", dep: { ecosystem: "maven", coord: "g:a", version: "8" } }], obsolete: [], outdated: [], licenses: [] };
	const cur = { cve: [], eol: [], obsolete: [], outdated: [{ latest: "2.0", dep: { ecosystem: "npm", coord: "left-pad", version: "1.0" } }], licenses: [] };
	const d = diffFindings(base, cur);
	assert.strictEqual(d.eol.removed.length, 1);
	assert.strictEqual(d.outdated.added.length, 1);
});

test("summarizeDiff counts; new production CVEs exclude suppressed and cpe-filtered", () => {
	const base = doc([]);
	const cur = doc([
		cve("CVE-A", "g:a", "1.0.0", { severity: "CRITICAL" }),
		cve("CVE-B", "g:b", "1.0.0", { suppressed: true }),
		cve("CVE-C", "g:c", "1.0.0", { cpeFiltered: true }),
	]);
	const d = diffFindings(base, cur);
	assert.strictEqual(newProductionCveCount(d), 1, "only CVE-A is a new production finding");
	const s = summarizeDiff(d);
	assert.strictEqual(s.cve.added, 3);
	assert.strictEqual(s.cve.addedProduction, 1);
	assert.strictEqual(s.cve.addedBySeverity.CRITICAL, 1);
});

test("diffFindings tolerates a baseline document missing a category", () => {
	const base = { cve: [cve("CVE-1", "g:a", "1.0.0")] }; // no eol/outdated keys
	const cur = doc([cve("CVE-1", "g:a", "1.0.0")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.unchanged.length, 1);
	assert.strictEqual(d.eol.added.length, 0);
});

const { eolKey } = require("../lib/diff");

test("eol identity includes status: unsupported → eol on the same dep is a CHANGE, legacy docs default to eol", () => {
	const dep = { ecosystem: "composer", coord: "symfony/framework-bundle", version: "5.4.45" };
	const base = doc([], { eol: [{ product: "Symfony", status: "unsupported", dep }] });
	const cur = doc([], { eol: [{ product: "Symfony", status: "eol", dep }] });
	const d = diffFindings(base, cur);
	assert.strictEqual(d.eol.added.length, 1);
	assert.strictEqual(d.eol.removed.length, 1);
	assert.strictEqual(d.eol.unchanged.length, 0);
	assert.strictEqual(eolKey({ dep }), eolKey({ status: "eol", dep }), "a pre-status baseline entry equals a status:eol entry");
});

test("physical Composer copies have distinct diff identities", () => {
	const first = { ...cve("CVE-1", "vendor/lib", "1.0", { ecosystem: "composer" }), findingId: "fad-cve-first" };
	const second = { ...first, findingId: "fad-cve-second" };
	const d = diffFindings(doc([first]), doc([first, second]));
	assert.deepStrictEqual(d.cve.added.map(f => f.findingId), ["fad-cve-second"]);
	assert.strictEqual(d.cve.unchanged.length, 1);
});

test("missing advisory coverage marks an absent application finding unassessed, not resolved", () => {
	const old = { ...cve("CVE-1", "vendor/lib", "1.0", { ecosystem: "composer" }),
		findingId: "fad-cve-first", applicationIds: ["wordpress:site"] };
	const cur = { ...doc([]), coverage: [{ applicationId: "wordpress:site", capability: "advisories",
		execution: "not-run", result: "indeterminate" }] };
	const d = diffFindings(doc([old]), cur);
	assert.strictEqual(d.cve.removed.length, 0);
	assert.deepStrictEqual(d.cve.unassessed, [old]);
	assert.strictEqual(summarizeDiff(d).cve.unassessed, 1);
});

test("ordinary findings remain unassessed when advisory or inventory coverage is incomplete", () => {
	const old = cve('CVE-1', 'lodash', '1.0', { ecosystem: 'npm' });
	for (const type of ['source-unavailable', 'source-stale', 'osv-coverage', 'parse-error', 'dependency-coverage', 'no-lockfile']) {
		const d = diffFindings(doc([old]), { ...doc([]), warnings: [{ type, message: 'gap' }] });
		assert.deepStrictEqual(d.cve.removed, []);
		assert.deepStrictEqual(d.cve.unassessed, [old]);
	}
	assert.equal(diffFindings(doc([old]), { ...doc([]), warnings: [{ type: 'suppressed' }] }).cve.removed.length, 1);
});

test("new production gate excludes dev/test/provided but includes embedded findings", () => {
	const findings = [
		{ ...cve('DEV', 'dev', '1'), dep: { isDev: true } },
		{ ...cve('TEST', 'test', '1'), dep: { scope: 'test' } },
		{ ...cve('PROVIDED', 'provided', '1'), dep: { scope: 'provided' } },
		{ ...cve('EMBEDDED', 'binary', '1'), dep: { isDev: true, provenance: 'embedded' } },
		cve('PROD', 'prod', '1'),
	];
	const s = summarizeDiff(diffFindings(doc([]), doc(findings)));
	assert.equal(s.cve.added, 5);
	assert.equal(s.cve.addedProduction, 2);
	assert.equal(s.cve.addedBySeverity.HIGH, 2);
});

test("baseline validation rejects unrelated JSON and malformed findings but permits legacy exports", () => {
	const { validateFindingsDocument } = require('../lib/diff');
	for (const invalid of [null, [], {}, { schema: 'other', cve: [] }, { cve: {} }, { cve: [null] }, { cve: [{ id: 'CVE-1' }] }])
		assert.throws(() => validateFindingsDocument(invalid));
	assert.deepStrictEqual(validateFindingsDocument({ cve: [] }), { cve: [] });
	assert.equal(validateFindingsDocument({ schema: 'fad-findings/1', cve: [cve('CVE-1', 'g:a', '1')] }).cve.length, 1);
});

test('actual source gaps prevent false remediation while normal cached observations do not', () => {
 const {buildFindings}=require('../lib/json-export'),old=cve('CVE-1','lodash','1.0',{ecosystem:'npm'});
 const gaps=[
  {projectInfo:{provenance:{}},warnings:[{type:'source-stale',message:'osv: cached data may be outdated.'}]},
  {projectInfo:{provenance:{freshnessNotices:[{message:'osv: the source could not be refreshed; cached data was used.'}]}},warnings:[]},
  {projectInfo:{provenance:{sourceLimitations:[{source:'CVEProject',message:'partial projection'}]}},warnings:[]},
  {projectInfo:{provenance:{mavenDepthLimitReached:true}},warnings:[]},
 ];
 for(const evidence of gaps){const d=diffFindings(doc([old]),buildFindings({cveMatches:[],...evidence}));assert.deepStrictEqual(d.cve.removed,[]);assert.deepStrictEqual(d.cve.unassessed,[old]);}
 const legacyRaw={...doc([]),warnings:[{type:'source-stale',message:'osv: cached data from 2026-01-01T00:00:00Z was used.'}]};assert.equal(diffFindings(doc([old]),legacyRaw).cve.removed.length,1);
 for(const evidence of [
  {projectInfo:{provenance:{freshnessNotices:[{source:'osv',at:'2026-01-01T00:00:00Z',message:'osv: cached data from 2026-01-01T00:00:00Z was used.'}]}}},
  {projectInfo:{provenance:{notices:[{severity:'info',message:'Selected the EU profile.'}]}}},
  {warnings:[{type:'source-stale',severity:'info',message:'A cache was used.'}]},
 ]){const current=buildFindings({cveMatches:[],...evidence});assert.equal(diffFindings(doc([old]),current).cve.removed.length,1);}
});

test('baseline project mismatch is a warning hint, never a reason to refuse a diff', () => {
 const {baselineProjectWarning}=require('../lib/diff');
 const base={...doc([cve('CVE-1','g:a','1')]),project:{name:'old-project'}};
 const current={...doc([cve('CVE-1','g:a','1')]),project:{name:'renamed-project'}};
 assert.equal(baselineProjectWarning(base,current).type,'baseline-project-mismatch');
 assert.match(baselineProjectWarning(base,current).message,/comparison continues/);
 assert.equal(diffFindings(base,current).cve.unchanged.length,1);
 for(const project of [undefined,{}, {name:''},{name:'old-project'},{name:' old-project '}])
  assert.equal(baselineProjectWarning(base,{project}),null);
 assert.doesNotMatch(baselineProjectWarning(base,{project:{name:'malicious\nname\x1b'}}).message,/[\r\n\x1b]/);
});

test('image occurrences use target, architecture and only explicit aliases', () => {
 const coverage=[{capability:'advisories',collector:'system-osv',execution:'completed'}];
 const a={id:'old',metadata:{},coverage}, b={id:'other',metadata:{},coverage};
 const hit=(id,target,purl='pkg:deb/debian/x@1?arch=amd64')=>({...cve(id,'x','1',{ecosystem:'system'}),dep:{ecosystem:'system',coord:'x',version:'1',artifactTargetId:target,purl,artifactPath:'/status'}});
 let base={...doc([hit('CVE-1','old')]),artifacts:[a,b]}, current={...doc([hit('CVE-1','other')]),artifacts:[a,b]};
 let d=diffFindings(base,current); assert.equal(d.cve.added.length,1);assert.equal(d.cve.unassessed.length,0);assert.equal(d.cve.removed.length,1);
 current={...doc([{...hit('GHSA-1','old'),aliases:['CVE-1']}]),artifacts:[a]};
 assert.equal(diffFindings({...base,artifacts:[a]},current).cve.unchanged.length,1);
 current.cve[0].aliases=[];current.cve[0].upstream=['CVE-1'];
 assert.equal(diffFindings({...base,artifacts:[a]},current).cve.unchanged.length,0);
 current.cve[0]=hit('CVE-1','old','pkg:deb/debian/x@1?arch=arm64');
 assert.equal(diffFindings({...base,artifacts:[a]},current).cve.unchanged.length,0);
});

test('an image-scoped outage does not change source-project or other image comparisons',()=>{
 const coverage=[{capability:'advisories',collector:'system-osv',execution:'completed'}],images=['a','b'].map(id=>({id,metadata:{},coverage}));
 const hit=id=>({...cve('CVE-2024-11111','pkg','1',{ecosystem:'system'}),source:'osv',dep:{ecosystem:'system',coord:'pkg',version:'1',artifactTargetId:id}});
 const project=cve('CVE-2024-22222','g:a','1'),before={...doc([project,hit('a'),hit('b')]),artifacts:images},after={...doc([]),artifacts:images,warnings:[{type:'source-unavailable',artifactTargetId:'a',message:'registry source failed'}]};
 const d=diffFindings(before,after);assert.deepStrictEqual(d.cve.removed.map(f=>f.dep.artifactTargetId||'project').sort(),['b','project']);assert.deepStrictEqual(d.cve.unassessed.map(f=>f.dep.artifactTargetId),['a']);
 const inverse=diffFindings({...doc([]),artifacts:images,warnings:after.warnings},{...doc([project,hit('a'),hit('b')]),artifacts:images});assert.deepStrictEqual(inverse.cve.added.map(f=>f.dep.artifactTargetId||'project').sort(),['b','project']);assert.deepStrictEqual(inverse.cve.unassessedAdded.map(f=>f.dep.artifactTargetId),['a']);
});

test('changed image digest requires a verified unique declaration to compare; source gaps stay uncertain', () => {
 const image=(id,execution='completed')=>({id,metadata:{platform:{os:'linux',architecture:'amd64'},definitions:[{path:'compose.yml',line:8,role:'deployment',binding:'manifest-digest'}]},coverage:[{capability:'advisories',collector:'system-osv',execution}]});
 const hit=(id)=>({...cve('DLA-1','x','1',{ecosystem:'system'}),source:'OSV',dep:{ecosystem:'system',coord:'x',version:'1',purl:'pkg:deb/debian/x@1?arch=amd64',artifactTargetId:id,artifactPath:'/status'}});
 const before={...doc([hit('a')]),artifacts:[image('a')]};
 let after={...doc([hit('b')]),artifacts:[image('b')]};
 assert.equal(diffFindings(before,after).cve.unchanged.length,1);
 after={...doc([]),artifacts:[image('b','not-run')]};
 assert.equal(diffFindings(before,after).cve.unassessed.length,1);
 const inverse=diffFindings({...doc([]),artifacts:[image('a','not-run')]},{...doc([hit('b')]),artifacts:[image('b')]});
 assert.equal(inverse.cve.added.length,0);assert.equal(inverse.cve.unassessedAdded.length,1);assert.equal(newProductionCveCount(inverse),0);
 after.artifacts[0].metadata.definitions=[];
 assert.equal(diffFindings(before,after).cve.unassessed.length,1);
});

test('changed hash from an explicit alias or a linked image digest retains finding identity', () => {
 const image=id=>({id,metadata:{platform:{os:'linux',architecture:'amd64'},definitions:[{path:'compose.yml',line:8,binding:'manifest-digest'}]},coverage:[{capability:'advisories',collector:'osv-application',execution:'completed'}]});
 const finding=(id,hash,target)=>({...cve(id,'lib','1',{ecosystem:'npm'}),findingId:hash,dep:{ecosystem:'npm',coord:'lib',version:'1',artifactTargetId:target,artifactPath:'/app/package-lock.json',purl:'pkg:npm/lib@1'}});
 const old=finding('CVE-2026-1234','fad-cve-old','a');
 const current={...finding('GHSA-1234','fad-cve-new','b'),aliases:['CVE-2026-1234']};
 assert.equal(diffFindings({...doc([old]),artifacts:[image('a')]},{...doc([current]),artifacts:[image('b')]}).cve.unchanged.length,1);
});

test('an unavailable baseline source cannot prove a later finding is new', () => {
 const old={...doc([]),warnings:[{type:'source-unavailable',message:'advisory source unavailable'}]};
 const current=doc([cve('CVE-2026-1234','g:a','1')]);
 const d=diffFindings(old,current);
 assert.equal(d.cve.added.length,0);assert.equal(d.cve.unassessedAdded.length,1);assert.equal(newProductionCveCount(d),0);
});

test('a non-blocking record enrichment warning does not make baseline findings unassessed', () => {
 const warning={type:'source-unavailable',severity:'warning',affectsCompleteness:false,message:'CVE record refresh failed'};
 const previous={...doc([cve('CVE-2026-1234','g:a','1')]),warnings:[]};
 const current={...doc([]),warnings:[warning]};
 const diff=diffFindings(previous,current);
 assert.equal(diff.cve.removed.length,1);
 assert.equal(diff.cve.unassessed.length,0);
});

test('a multi-CVE advisory is not an alias of each individual CVE', () => {
 const multi={...cve('DLA-1','x','1'),aliases:['CVE-2026-1000','CVE-2026-1001']};
 const single=cve('CVE-2026-1000','x','1');
 const d=diffFindings(doc([multi]),doc([single]));
 assert.equal(d.cve.unchanged.length,0);assert.equal(d.cve.added.length,1);assert.equal(d.cve.removed.length,1);
});

test('an incomplete application baseline cannot prove a later finding is new', () => {
 const old={...doc([]),coverage:[{applicationId:'site',capability:'advisories',execution:'partial'}]};
 const current=doc([{...cve('CVE-1','x','1'),applicationIds:['site']}]);
 assert.equal(diffFindings(old,current).cve.unassessedAdded.length,1);
});

test('unverified declaration or unknown platform does not bind changed images', () => {
 const image=(id,binding,platform)=>({id,metadata:{platform,definitions:[{path:'compose.yml',line:2,binding}]}});
 const f=id=>({...cve('CVE-1','x','1'),dep:{ecosystem:'npm',coord:'x',version:'1',artifactTargetId:id}});
 for(const [binding,platform] of [['guessed',{os:'linux',architecture:'amd64'}],['manifest-digest',null]]) {
  const d=diffFindings({...doc([f('a')]),artifacts:[image('a',binding,platform)]},{...doc([f('b')]),artifacts:[image('b',binding,platform)]});
  assert.equal(d.cve.unchanged.length,0);assert.equal(d.cve.unassessed.length,1);assert.equal(d.cve.unassessedAdded.length,1);
 }
});

test('image delta consults each contributing detection source instead of assuming system OSV',()=>{
 const hit=source=>({...cve('CVE-2024-1000','nginx','1',{ecosystem:'system'}),source,dep:{ecosystem:'system',coord:'nginx',version:'1',sourceName:'nginx',sourceVersion:'1',manager:'dpkg',artifactTargetId:'a'}});
 const cov=(collector,execution)=>({capability:'advisories',collector,source:collector,execution});
 const artifact=coverage=>({id:'a',metadata:{},coverage});
 const old=source=>({...doc([hit(source)]),artifacts:[artifact([cov(source,'completed'),cov('system-osv','completed')])]});
 for(const source of ['nginx-vendor-advisories','debian-security-tracker-history']){
  const current={...doc([]),artifacts:[artifact([cov('system-osv','completed')])]};
  const d=diffFindings(old(source),current);assert.equal(d.cve.removed.length,0);assert.equal(d.cve.unassessed.length,1,source);
  const inverse=diffFindings({...doc([]),artifacts:[artifact([cov('system-osv','completed')])]},old(source));
  assert.equal(inverse.cve.added.length,0);assert.equal(inverse.cve.unassessedAdded.length,1,source);
 }
 const current={...doc([]),artifacts:[artifact([cov('system-osv','completed'),cov('nginx-vendor-advisories','completed')])]};
 assert.equal(diffFindings(old('nginx-vendor-advisories'),current).cve.removed.length,1);
 const both=old('nginx-vendor-advisories+osv+nvd');
 assert.equal(diffFindings(both,{...doc([]),artifacts:[artifact([cov('system-osv','completed')])]}).cve.unassessed.length,1);
});

test('vendor observation uncertainty does not prove a finding removed despite completed consultation',()=>{
 const f={...cve('CVE-2024-1000','nginx','1',{ecosystem:'system'}),source:'nginx-vendor-advisories',dep:{ecosystem:'system',coord:'nginx',version:'1',sourceName:'nginx',manager:'dpkg',artifactTargetId:'a'}};
 const artifact={id:'a',metadata:{},coverage:[{capability:'advisories',collector:'nginx-vendor-advisories',execution:'completed'}],advisoryObservations:[{dep:{name:'nginx'},cveId:f.id,status:'unknown',reason:'vendor identity not established'}]};
 assert.equal(diffFindings({...doc([f]),artifacts:[artifact]},{...doc([]),artifacts:[artifact]}).cve.unassessed.length,1);
});

test('historical absence stays uncertain but an explicit source-version fix is recognized even when feed is unavailable',()=>{
 const f={...cve('CVE-2024-1000','curl','1',{ecosystem:'system'}),source:'debian-security-tracker-history',fixVersion:'2-1',historicalEvidence:{fixes:[{version:'2-1',source:'DLA/list'}]},dep:{ecosystem:'system',coord:'curl',version:'1-1',sourceName:'curl',sourceVersion:'1-1',packageType:'deb',manager:'dpkg',artifactTargetId:'a',purl:'pkg:deb/debian/curl@1-1?arch=amd64'}};
 const coverage=[{capability:'inventory',collector:'dpkg',execution:'completed'},{capability:'advisories',collector:'debian-security-tracker-history',execution:'completed',completeness:'historical-only',queriedPackages:['curl']}];
 const artifact={id:'a',metadata:{},coverage,components:[{name:'curl',packageType:'deb',architecture:'amd64',sourceName:'curl',sourceVersion:'1-1'}]};
 const before={...doc([f]),artifacts:[artifact]},unchangedPkg={...doc([]),artifacts:[artifact]};assert.equal(diffFindings(before,unchangedPkg).cve.unassessed.length,1);
 const fixed={...artifact,coverage:[coverage[0]],components:[{...artifact.components[0],sourceVersion:'2-1'}]};
 const after={...doc([]),artifacts:[fixed],warnings:[{type:'source-unavailable',source:'debian-security-tracker-history',artifactTargetId:'a',message:'offline'}]};
 assert.equal(diffFindings(before,after).cve.removed.length,1);
 fixed.components[0].packageOrigin={status:'third-party'};assert.equal(diffFindings(before,after).cve.unassessed.length,1);
 delete fixed.components[0].packageOrigin;
 fixed.components[0].sourceVersion=null;assert.equal(diffFindings(before,after).cve.unassessed.length,1);
});

test('a failed unrelated image source does not invalidate a consulted vendor detection source',()=>{
 const f={...cve('CVE-2024-1000','nginx','1',{ecosystem:'system'}),source:'nginx-vendor-advisories',dep:{ecosystem:'system',coord:'nginx',version:'1',artifactTargetId:'a'}};
 const artifact={id:'a',metadata:{},coverage:[{capability:'advisories',collector:'nginx-vendor-advisories',execution:'completed'}]};
 const current={...doc([]),artifacts:[artifact],warnings:[{type:'source-unavailable',source:'system-osv',artifactTargetId:'a',message:'unavailable'}]};
 assert.equal(diffFindings({...doc([f]),artifacts:[artifact]},current).cve.removed.length,1);
});
