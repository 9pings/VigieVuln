'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {parsePublisherRange,normalizePublisherMavenAdvisory}=require('../lib/github-publisher-maven');
const {vulnVerdict}=require('../lib/osv-db');
const advisory={ghsa_id:'GHSA-h722-h6c2-6j3c',cve_id:'CVE-2026-102467',state:'published',published_at:'2026-10-07T21:55:53Z',updated_at:'2026-10-15T13:09:33Z',html_url:'https://github.com/eclipse-vertx/vert.x/security/advisories/GHSA-h722-h6c2-6j3c',summary:'WebSocket decompression',vulnerabilities:[{package:{ecosystem:'maven',name:'io.vertx:vertx-core'},vulnerable_version_range:'>= 4.0.0, <= 4.5.34',patched_versions:'4.5.35'},{package:{ecosystem:'maven',name:'io.vertx:vertx-core'},vulnerable_version_range:'5.2.0',patched_versions:'5.2.1'}]};
const verdict=(version,value)=>vulnVerdict(version,{affected:[{...parsePublisherRange(value),package:{ecosystem:'Maven',name:'x:y'}}]},'Maven');
test('publisher intervals preserve inclusive/exclusive boundaries and independent branches',()=>{
 const x='[4.0.0,4.5.29],[5.0.0,5.1.4]';for(const v of ['4.0.0','4.5.24','4.5.29','5.1.4'])assert.equal(verdict(v,x),true,v);for(const v of ['3.9.9','4.5.30','4.9.0','5.1.5'])assert.equal(verdict(v,x),false,v);
 assert.equal(verdict('4.1.137.Final','<= 4.1.137.Final'),true);assert.equal(verdict('4.1.138.Final','<= 4.1.137.Final'),false);
 assert.equal(verdict('2.0.0','>= 1.0.0, < 2.0.0'),false);assert.equal(verdict('2.0.0','>= 1.0.0, <= 2.0.0'),true);
});
test('unrepresentable or malformed ranges remain unknown and never become a clean verdict',()=>{
 for(const x of ['> 1.0.0, < 2.0.0','(1.0,2.0]','>= 2.0, < 1.0','1.0 || 2.0','>= 1.0, banana','[1.0,2.0],']){assert.equal(parsePublisherRange(x).unsupported,true,x);assert.equal(verdict('1.5',x),null,x)}
});
test('publisher advisory binds only explicit Maven coordinates and preserves alias and source',()=>{
 const out=normalizePublisherMavenAdvisory(advisory,'eclipse-vertx/vert.x');assert.equal(out.id,'GHSA-h722-h6c2-6j3c');assert.deepEqual(out.aliases,['CVE-2026-102467']);assert.equal(out.affected[0].package.name,'io.vertx:vertx-core');assert.equal(vulnVerdict('4.5.24',out,'Maven'),true);assert.equal(vulnVerdict('4.5.35',out,'Maven'),false);assert.equal(vulnVerdict('5.2.0',out,'Maven'),true);assert.equal(vulnVerdict('5.2.1',out,'Maven'),false);assert.equal(out.references[0].url,advisory.html_url);
 const wrong={...advisory,vulnerabilities:[{package:{ecosystem:'npm',name:'vertx-core'},vulnerable_version_range:'< 3.0.0'},{package:{ecosystem:'maven',name:'other'},vulnerable_version_range:'< 3.0.0'}]};assert.deepEqual(normalizePublisherMavenAdvisory(wrong,'eclipse-vertx/vert.x').affected,[]);
 assert.throws(()=>normalizePublisherMavenAdvisory(advisory,'attacker/project'),/does not match/);
});
