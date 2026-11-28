'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const {renderTime,localizeReportTimes}=require('../lib/reports/time');
const {generateHtmlReport,generateWordReport}=require('../lib/reports/cve-report');

test('report times preserve instants, calendar dates and unzoned timestamps',()=>{
 assert.match(renderTime('2026-11-05T00:30:00+02:00','fr'), /<time datetime="2026-11-05T00:30:00\+02:00">[^<]*04\/11\/2026[^<]*UTC<\/time>/);
 assert.equal(renderTime('2026-11-05'),'<time datetime="2026-11-05">2026-11-05</time>');
 assert.equal(renderTime('2026-11-05T00:30:00'),'<time datetime="2026-11-05T00:30:00">2026-11-05 00:30:00</time>');
 for(const invalid of ['2026-02-30','2026-11-05T25:30:00Z','unknown','<script>'])assert.doesNotMatch(renderTime(invalid), /<time|<script>/);
});
test('browser localization changes instants across zones but never shifts date-only values',()=>{
 for(const zone of ['America/Los_Angeles','Asia/Tokyo']){
  const elements=['2026-11-05T00:30:00Z','2026-11-05','2026-11-05T00:30:00'].map(raw=>({getAttribute:()=>raw,textContent:'original'}));
  const document={documentElement:{lang:'en-GB'},querySelectorAll:()=>elements};
  const intl={DateTimeFormat:function(locale,opts){return new Intl.DateTimeFormat(locale,{timeZone:zone,...opts});}};
  vm.runInNewContext(`(${localizeReportTimes.toString()})(document)`,{document,Intl:intl,Date});
  assert.match(elements[0].textContent,zone==='Asia/Tokyo'?/05\/11\/2026, 09:30/:/04\/11\/2026, 16:30/);
  assert.equal(elements[1].textContent,'05/11/2026');
  assert.equal(elements[2].textContent,'original','unspecified zones are never guessed');
 }
});
test('CVE detail keeps each shared field once, preserves differing evidence and distribution references',()=>{
 const stamp='2026-11-05T00:30:00Z',id='CVE-2024-8096';
 const record={id,relationship:'identity',severity:'MEDIUM',score:6.5,description:'Distinct evidence description.',cwes:['CWE-295'],published:stamp,modified:stamp,cvssVector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',cvssVersion:'CVSS:3.1',references:[{url:'https://example.org/source'}]};
 const cve={...record,nvdRefs:record.references,nvdEvidence:{records:[record]},riskEvidence:{id,source:'nvd',relationship:'identity'},fixVersion:'1.2',distributionAdvisories:[{id:'DLA-3951-1',fixVersion:'1.2',description:'Distribution fix.'}]};
 const payload={projectInfo:{name:'times'},cveMatches:[{dep:{ecosystem:'npm',name:'sample',artifactId:'sample',version:'1.0'},cve,source:'nvd+osv'}]};
 for(const render of [generateHtmlReport,generateWordReport]){
  const html=render(payload),panel=html.match(/<div class="detail-panel">([\s\S]*?)<\/td><\/tr>/)[1];
  assert.equal(panel.split('Distinct evidence description.').length-1,1);
  assert.equal(panel.split('https://example.org/source').length-1,2,'one URL as href and label');
  assert.doesNotMatch(panel,/linked-cve-evidence/);
  assert.match(panel,/advisory\/osv\/DLA-3951-1/);
  assert.equal(panel.split('1.2').length-1,1,'candidate belongs to its distribution advisory');
  assert.equal((panel.match(/<time datetime="2026-11-05T00:30:00Z">/g)||[]).length,2,'published and modified retain full timestamps');
 }
 const {renderRiskEvidence}=require('../lib/artifacts/risk-report');
 const extra=renderRiskEvidence({...cve,nvdEvidence:{records:[{...record,score:7.5,description:'Different source description.'}]}},'en',{omitRepeated:true});
 assert.match(extra,/7.5/);assert.doesNotMatch(extra,/Different source description|CWE-295|example.org/);
});
