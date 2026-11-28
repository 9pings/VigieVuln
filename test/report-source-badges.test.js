'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {generateHtmlReport,generateWordReport}=require('../lib/reports/cve-report');
const {projectImageCves}=require('../lib/artifacts/cve-view');
function report(match,render=generateHtmlReport){return render({cveMatches:[match],resolvedDeps:new Map([['d',match.dep]]),projectInfo:{name:'sources'}});}
const dep={ecosystem:'npm',name:'example',version:'1',coord:'example',coordKey:'d'};
test('source badges expose consulted evidence independently and reject derived aliases',()=>{
 const m={dep,source:'nvd',cve:{id:'CVE-2024-12345',severity:'HIGH',aliases:['GHSA-abcd-efgh-ijkl'],euvd:{id:'EUVD-2024-123'},euvdEvidence:{status:'enriched'},gcve:'GCVE-0-2024-12345',gcveEvidence:{kind:'derived-alias'}}};
 for(const render of [generateHtmlReport,generateWordReport]){let html=report(m,render);assert.match(html,/class="source euvd" href="https:\/\/euvd\.enisa\.europa\.eu\/vulnerability\/EUVD-2024-123"/);assert.match(html,/class="source nvd"/);assert.doesNotMatch(html,/class="source (?:gcve|ghsa)"/);}
 m.cve.euvdEvidence.status='unavailable';assert.doesNotMatch(report(m),/class="source euvd"/);
});
test('GHSA requires a consulted advisory and native GCVE evidence yields its own link',()=>{
 const m={dep,source:'osv+osv',cve:{id:'CVE-2024-12345',severity:'HIGH',aliases:['GHSA-abcd-efgh-ijkl'],gcve:'GCVE-42-2024-12345',gcveEvidence:{kind:'native-record'}}};
 const html=report(m);assert.match(html,/class="source ghsa" href="https:\/\/github\.com\/advisories\/GHSA-abcd-efgh-ijkl"/);assert.match(html,/class="source gcve" href="https:\/\/www\.vigievuln\.fr\/advisory\/gcve\/GCVE-42-2024-12345"/);assert.equal((html.match(/class="source osv"/g)||[]).length,2,'once in row and once in detail panel');
});
test('image projection retains observed GHSA advisory through CVE projection and merge',()=>{
 const imageDep={...dep,ecosystem:'system',artifactTargetId:'a'};
 const m={dep:imageDep,source:'osv',cve:{id:'GHSA-abcd-efgh-ijkl',aliases:['CVE-2024-12345'],severity:'HIGH'}};
 const p=projectImageCves([m])[0];assert.deepEqual(p.cve.sourceGhsaIds,['GHSA-abcd-efgh-ijkl']);assert.match(report({...p,dep}),/class="source ghsa"/);
 const absent=projectImageCves([{...m,source:'nvd'}])[0];assert.deepEqual(absent.cve.sourceGhsaIds,[]);assert.doesNotMatch(report({...absent,dep}),/class="source ghsa"/);
});
test('a CVE detail panel displays only its primary description while retaining source metadata',()=>{
 const id='CVE-2024-12345',m={dep,source:'nvd+osv',cve:{id,severity:'HIGH',description:'Primary CVE explanation',nvdEvidence:{records:[{id,description:'Alternative NVD description',score:7.2,cvssVector:'CVSS:3.1/X',published:'2024-01-01'}]},euvdDetails:{id:'EUVD-2024-123',source:'euvd',description:'Alternative ENISA description',score:6.5,published:'2024-02-01',references:['https://example.org/enisa']},distributionAdvisories:[{id:'DLA-123',description:'Alternative distribution description',fixVersion:'2'}]}};
 for(const render of [generateHtmlReport,generateWordReport]){let html=report(m,render);assert.equal((html.match(/<div class="full-desc">Primary CVE explanation/g)||[]).length,1);assert.doesNotMatch(html,/Alternative NVD description|Alternative ENISA description|Alternative distribution description/);assert.match(html,/EUVD-2024-123/);assert.match(html,/6\.5/);assert.match(html,/example.org\/enisa/);assert.match(html,/DLA-123/);}
});
test('multi-CVE native GCVE projection links every row to its observed native advisory, never the derived alias',()=>{
 const a='CVE-2024-12345',b='CVE-2024-12346',native='GCVE-42-2024-native',imageDep={...dep,ecosystem:'system',artifactTargetId:'a'};
 const m={dep:imageDep,source:'GCVE:GNA-42',cve:{id:a,aliases:[b],gcve:native,cveEvidence:[{id:a,gcveAlias:'GCVE-0-2024-12345',gcveEvidence:{kind:'derived-alias'}},{id:b,gcveAlias:'GCVE-0-2024-12346',gcveEvidence:{kind:'derived-alias'}}]}};
 const projected=projectImageCves([m]);assert.equal(projected.length,2);
 for(const row of projected){assert.deepEqual(row.cve.sourceGcveIds,[native]);const html=report({...row,dep});assert.match(html,/class="source gcve" href="https:\/\/www\.vigievuln\.fr\/advisory\/gcve\/GCVE-42-2024-native"/);assert.doesNotMatch(html,/class="source gcve" href="[^"]*GCVE-0-/);}
 const noNative=projectImageCves([{...m,cve:{...m.cve,gcve:'GCVE-0-2024-12345',gcveEvidence:{kind:'derived-alias'}}}]);for(const row of noNative)assert.doesNotMatch(report({...row,dep}),/class="source gcve"/);
});
test('publisher GHSA badge links its observed advisory instead of a raw source label',()=>{const m={dep,source:'github-publisher',advisoryId:'GHSA-abcd-efgh-ijkl',cve:{id:'GHSA-abcd-efgh-ijkl',severity:'HIGH',advisorySource:'https://github.com/example/app/security/advisories/GHSA-abcd-efgh-ijkl'}};const html=report(m);assert.match(html,/class="source ghsa" href="https:\/\/github\.com\/example\/app\/security\/advisories\/GHSA-abcd-efgh-ijkl"/);assert.doesNotMatch(html,/>github-publisher<\//);});
