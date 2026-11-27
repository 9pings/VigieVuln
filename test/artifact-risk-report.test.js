'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {renderLinkedCves,renderRiskEvidence,renderRiskAttribution}=require('../lib/artifacts/risk-report');
test('vendor provenance keeps scope separate from risk and escapes untrusted declarations',()=>{
 const {renderVendorEvidence,renderHistoricalEvidence}=require('../lib/artifacts/risk-report');
 const html=renderVendorEvidence({vendorEvidence:{upstreamVersion:'1.24.0',versionRange:'1.0.0-1.25.3',packageOrigin:{declared:'<script>vendor</script>'},advisoryURL:'javascript:alert(1)',observedAt:1700000000000}},'fr');
 assert.match(html,/1\.24\.0/);assert.match(html,/&lt;script&gt;vendor/);assert.match(html,/<time datetime=/);assert.match(html,/configuration effective/);assert.doesNotMatch(html,/<script>|javascript:/);
 const historical=renderHistoricalEvidence({historicalEvidence:{distribution:{id:'debian',versionId:'11'},commit:'a'.repeat(40),cutoff:'2026-08-31',originStatus:'distribution-context'}},'fr');
 assert.match(historical,/salsa\.debian\.org/);assert.match(historical,/après sa date limite/);assert.match(historical,/non authentifié/);
});
test('linked CVEs and per-CVE metadata remain distinct from distribution advisory',()=>{
 const cve={id:'DLA-3951-1',upstream:['CVE-2024-8096'],riskEvidence:{source:'nvd',id:'CVE-2024-8096',relationship:'upstream'},nvdEvidence:{records:[{id:'CVE-2024-8096',relationship:'upstream',severity:'MEDIUM',score:6.5,cvssVector:'CVSS:3.1/X',cwes:['CWE-295'],published:'2024-09-11',description:'Description',references:[{url:'https://example.org/advisory'}]}]}};
 const compact=renderLinkedCves(cve,'en');assert.match(compact,/CVE-2024-8096/);assert.match(compact,/MEDIUM · 6.5/);assert.doesNotMatch(compact,/<table/);
 const detail=renderRiskEvidence(cve,'en');assert.match(detail,/Upstream CVE/);assert.doesNotMatch(detail,/<table/);assert.match(detail,/class="kv"/);assert.match(detail,/https:\/\/www\.vigievuln\.fr\/cve\/CVE-2024-8096/);assert.match(detail,/https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-8096/);assert.match(detail,/original advisory remains/);assert.match(detail,/CWE-295/);assert.match(detail,/example.org\/advisory/);assert.match(renderRiskAttribution(cve,'en'),/associated CVE/);
});
test('advisory cell shows six distinct linked CVEs and counts the rest',()=>{
 const ids=Array.from({length:8},(_,i)=>'CVE-2024-'+(1000+i));
 const cve={id:'DSA-1',upstream:[...ids.slice(0,6),ids[0]]};
 assert.doesNotMatch(renderLinkedCves(cve,'fr'),/…/);
 cve.nvdEvidence={records:ids.map(id=>({id,score:5.5}))};
 const preview=renderLinkedCves(cve,'fr');
 assert.equal((preview.match(/<a /g)||[]).length,6);
 assert.match(preview,/CVE-2024-1005<\/a> <small>\(5\.5\)<\/small> … \(\+2\)/);
 assert.doesNotMatch(preview,/CVE-2024-1006/);
 assert.match(renderRiskEvidence(cve,'fr'),/CVE-2024-1007/);
});
test('multi-CVE records preserve per-CVE severity, language and secure links',()=>{
 const cve={id:'DLA-1',upstream:['CVE-2024-12345','CVE-2024-56789'],related:['CVE-2024-11111'],nvdEvidence:{records:[{id:'CVE-2024-12345',relationship:'upstream',severity:'HIGH',score:8.1,description:'<script>alert(1)</script>',references:[{url:'javascript:alert(1)'},{url:'https://example.com/?a=1&b=2'}]},{id:'CVE-2024-56789',relationship:'upstream',severity:'LOW',score:2.4}]}};
 const html=renderRiskEvidence(cve,'fr');assert.match(html,/CVE en amont/);assert.match(html,/8\.1/);assert.match(html,/2\.4/);assert.doesNotMatch(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>|javascript:/);assert.match(html,/a=1&amp;b=2/);assert.doesNotMatch(renderLinkedCves(cve,'fr'),/CVE-2024-11111/);
});
test('no CVE is invented and primary CVE is not repeated in compact cell',()=>{
 assert.equal(renderLinkedCves({id:'DLA-1',upstream:[]},'en'),'');assert.equal(renderRiskEvidence({id:'DLA-1'},'en'),'');
 assert.equal(renderLinkedCves({id:'CVE-2024-12345',upstream:['CVE-2024-12345'],nvdEvidence:{records:[{id:'CVE-2024-12345'}]}},'en'),'');
 assert.match(renderLinkedCves({id:'DLA-1',upstream:['CVE-2024-12345']},'en'),/CVE-2024-12345/);
 assert.equal(renderRiskAttribution({riskEvidence:{source:'nvd',id:'<bad>',relationship:'upstream'}},'en'),'');
});
test('distribution advisory links use VigieVuln and keep original source secondary',()=>{
 const {renderDistributionAdvisories}=require('../lib/artifacts/risk-report');const html=renderDistributionAdvisories({distributionAdvisories:[{id:'DLA-3951-1',fixVersion:'1-2',relationship:'upstream',description:'Update <only>',sourceURL:'https://debian.org/advisory'}]},'en');
 assert.match(html,/https:\/\/www\.vigievuln\.fr\/advisory\/osv\/DLA-3951-1/);assert.match(html,/https:\/\/debian\.org\/advisory/);assert.match(html,/1-2/);assert.doesNotMatch(html,/Update &lt;only&gt;/);assert.doesNotMatch(html,/<table/);
 assert.doesNotMatch(renderDistributionAdvisories({distributionAdvisories:[{id:'<bad>',sourceURL:'javascript:alert(1)'}]}),/javascript:/);
});
test('ENISA details show attributed risk and safe source links',()=>{
 const {renderEuvdEvidence}=require('../lib/artifacts/risk-report');const cve={id:'CVE-2024-8096',riskEvidence:{source:'euvd',id:'CVE-2024-8096',relationship:'identity'},euvdDetails:{id:'EUVD-2024-48936',score:6.5,severity:'MEDIUM',description:'ENISA context',references:['https://example.org/reference','javascript:alert(1)']}};
 const html=renderEuvdEvidence(cve,'en');assert.match(html,/ENISA EUVD/);assert.match(html,/6\.5/);assert.doesNotMatch(html,/ENISA context/);assert.match(html,/https:\/\/euvd\.enisa\.europa\.eu\/vulnerability\/EUVD-2024-48936/);assert.doesNotMatch(html,/javascript:/);assert.match(renderRiskAttribution(cve,'en'),/ENISA EUVD/);
});
test('full image HTML and Word report show European context alongside native discovery source',()=>{
 const {generateHtmlReport,generateWordReport}=require('../lib/cve-report'),id='CVE-2024-12345';
 const details={id:'EUVD-2024-1',source:'euvd',score:6.5,severity:'MEDIUM',description:'Distinct ENISA explanation',references:['https://example.org/enisa-ref']};
 const dep={artifactTargetId:'img',ecosystem:'system',manager:'dpkg',name:'demo',version:'1',coordKey:'img:demo',artifactPath:'/var/lib/dpkg/status',scope:'runtime'};
 const cve={id,severity:'UNKNOWN',cveEvidence:[{id,euvd:{id:'EUVD-2024-1',exploitedSince:null},euvdDetails:details,certfr:[{ref:'CERTFR-2024-AVI-001',kind:'avis',title:'CERT'}]}]};
 const payload={cveMatches:[{dep,cve,source:'gcve'}],resolvedDeps:new Map([[dep.coordKey,dep]]),projectInfo:{name:'test',artifacts:[{id:'img',kind:'image',metadata:{source:'demo'},coverage:[]}]}};
 for(const html of [generateHtmlReport(payload),generateWordReport(payload)]){assert.equal((html.match(/<div class="full-desc">Distinct ENISA explanation/g)||[]).length,1);assert.match(html,/EUVD-2024-1/);assert.match(html,/CERTFR-2024-AVI-001/);assert.match(html,/example.org\/enisa-ref/);assert.match(html,/gcve/i);}
});
test('EUVD evidence omits repeated main values but retains contradictory values and dates',()=>{
 const {renderEuvdEvidence}=require('../lib/artifacts/risk-report');
 const detail={id:'EUVD-2024-1',score:6.5,severity:'MEDIUM',description:'Only one description',published:'2024-09-11',references:['https://example.org/reference']};
 const repeated=renderEuvdEvidence({score:6.5,severity:'MEDIUM',description:detail.description,published:detail.published,osvRefs:[{url:'https://example.org/reference'}],euvdDetails:detail},'en',{omitRepeated:true});
 assert.doesNotMatch(repeated,/Only one description|6\.5|example\.org\/reference/);assert.match(repeated,/EUVD-2024-1/);
 const different=renderEuvdEvidence({score:9,severity:'HIGH',description:'Another',euvdDetails:detail},'en',{omitRepeated:true});assert.match(different,/6\.5/);assert.match(different,/MEDIUM/);assert.match(different,/<time datetime="2024-09-11">/);assert.doesNotMatch(different,/Only one description/);
});
