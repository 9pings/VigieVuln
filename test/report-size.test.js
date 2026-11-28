'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');
const {parseDocument}=require('htmlparser2'),dom=require('domutils');
const {generateHtmlReport,generateWordReport}=require('../lib/reports/cve-report');
test('identical HTML detail panels share storage, restore before browser actions, and keep differing fixes',()=>{
 const dep=(name)=>({ecosystem:'npm',name,artifactId:name,version:'1.0',scope:'runtime',artifactTargetId:'image',artifactPath:'app/package.json',coordKey:name});
 const match=(name,fix)=>({dep:dep(name),cve:{id:'CVE-2099-12345',severity:'HIGH',description:'UNIQUE_LONG_DESCRIPTION '+('evidence '.repeat(500)),fixVersion:fix},source:'osv'});
 const payload={cveMatches:[match('a','2.0'),match('b','2.0'),match('c','3.0')],projectInfo:{name:'size',artifacts:[{id:'image',kind:'oci',metadata:{source:'example:1'},coverage:[]}]}};
 const html=generateHtmlReport(payload),tree=parseDocument(html);
 const all=pred=>dom.findAll(pred,tree.children),refs=all(el=>el.attribs?.['data-detail-ref']);
 assert.ok(refs.length>0);
 const wrap=el=>({getAttribute:key=>el.attribs[key],get innerHTML(){return dom.getInnerHTML(el)},set innerHTML(value){el.children=parseDocument(value).children;}});
 const script=all(el=>el.name==='script').map(dom.textContent).find(s=>s.includes("querySelectorAll('[data-detail-ref]')"));
 vm.runInNewContext(script,{document:{querySelectorAll:()=>refs.map(wrap),getElementById:id=>wrap(all(el=>el.attribs?.id===id)[0])}});
 const panels=all(el=>el.attribs?.class==='detail-panel');
 assert.equal(panels.length,3);
 const text=panels.map(dom.textContent);assert.equal(text.filter(s=>s.includes('2.0')).length,2);assert.equal(text.filter(s=>s.includes('3.0')).length,1);
 const word=generateWordReport(payload);assert.doesNotMatch(word,/data-detail-ref=/);assert.equal((word.match(/UNIQUE_LONG_DESCRIPTION/g)||[]).length,6,'Word has all descriptions in rows and details');
 const next=generateHtmlReport({cveMatches:[match('z','2.0')],projectInfo:payload.projectInfo});assert.doesNotMatch(next,/data-detail-ref="/,'sharing never leaks between reports');
});
test('compact JSON retains the entire findings schema and evidence',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vv-json-size-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const payload=require('./fixtures/report-payload/full')('en');
 payload.licenseResults=null; // The report fixture contains presentation-only license entries.
 const {writeFindings,buildFindings}=require('../lib/reports/json-export'),file=path.join(dir,'findings.json');
 const expected=buildFindings(payload),written=writeFindings(payload,file),text=fs.readFileSync(file,'utf8');
 // Each build stamps generation time when the caller supplied none.
 expected.generatedAt=written.generatedAt;
 assert.deepEqual(JSON.parse(text),JSON.parse(JSON.stringify(expected)));
 assert.ok(Buffer.byteLength(text)<Buffer.byteLength(JSON.stringify(expected,null,2))*.85);
});
