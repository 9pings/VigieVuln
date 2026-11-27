'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {assessDistributionSources}=require('../lib/system-inventory/distribution-sources');
const d={id:'debian',versionId:'11',codename:'bullseye'},dep={manager:'dpkg',name:'libdemo',version:'1.0-1',architecture:'amd64',sourceName:'demo',sourceVersion:'1.0-1'},id='CVE-2099-1234';
const a=(status,overrides={})=>({dep,cveId:id,source:'freexian-tracker',status,evidence:{distribution:d,sourceName:'demo',sourceVersion:'1.0-1',sourceURL:'https://example.test/advisory',...overrides}});
const obs=()=>({dep,cveId:id,source:'debian-security-tracker-current-candidates',status:'possible',evidence:{distribution:d,releaseApplicability:'unknown'}});
const adapter=(id,response)=>({id,supports:()=>true,assess:async()=>response});
async function run(assessments,{observations=[obs()],matches=[],confirmedMatches=[]}={}){return assessDistributionSources({distribution:d,packages:[dep]},{confirmedMatches,distributionSourceAdapters:[adapter('candidate',{observations}),adapter('other',{assessments,matches})]});}
test('exact release package and installed version replace candidate state, preserving both evidence records',async()=>{
 for(const status of ['fixed','not-affected','unknown']){const result=await run([a(status)]);assert.equal(result.observations.length,1);assert.equal(result.observations[0].status,status);assert.equal(result.observations[0].evidence.reconciliation.assessments[0].status,status);assert.equal(result.observations[0].evidence.releaseApplicability,'unknown');}
});
test('different release, package or source version cannot change a candidate',async()=>{
 for(const x of [a('fixed',{sourceVersion:'2.0-1'}),a('not-affected',{sourceName:'other'}),a('fixed',{distribution:{...d,codename:'bookworm'}})]){const result=await run([x]);assert.equal(result.observations[0].status,'possible');assert.equal(result.observations[0].evidence.reconciliation,undefined);}
});
test('contradictory assessments remain unknown and never suppress independent findings',async()=>{
 const finding={dep,source:'osv',cve:{id}},result=await run([a('fixed'),a('affected')],{matches:[finding]});assert.equal(result.matches.length,1);assert.equal(result.observations[0].status,'unknown');assert.equal(result.observations[0].evidence.conflictingFinding,true);assert.equal(result.matches[0].assessmentConflicts[0].status,'fixed');
 const prior=await run([a('not-affected')],{observations:[],confirmedMatches:[finding]});assert.equal(prior.observations.length,1);assert.equal(prior.observations[0].evidence.conflictingFinding,true);assert.equal(prior.observations[0].status,'not-affected');
});
test('duplicate tracker uncertainty is retained within the reconciled evidence',async()=>{
 const tracker={dep,cveId:id,source:'freexian-tracker',status:'possible',evidence:{reason:'tracker uncertainty'}};
 const result=await run([a('unknown')],{observations:[obs(),tracker]});assert.equal(result.observations.length,1);assert.equal(result.observations[0].evidence.reconciliation.status,'unknown');
});
test('image evidence displays fixed and non-affected assessments and flags conflicting findings',async()=>{
 const {renderArtifactEvidence}=require('../lib/artifacts/report');const result=await run([a('not-affected')],{confirmedMatches:[{dep,source:'osv',cve:{id}}]});
 const html=renderArtifactEvidence({artifacts:[{id:'image-1',metadata:{},componentCount:1,advisoryObservations:result.observations}]},'fr',[]);
 assert.match(html,/Non affecté selon la source/);assert.match(html,/Une autre source signale ce paquet comme affecté/);assert.match(html,/https:\/\/example\.test\/advisory/);
});
test('optional refinement checks only exact unknown candidate tuples and retains release proof',async()=>{
 const {refineFreexianEvidence,reconcileAssessments}=require('../lib/system-inventory/distribution-sources');let calls=[];
 const unrelated={...a('unknown'),cveId:'CVE-2099-9999'},known=a('not-affected'),unknown=a('unknown');
 const result={matches:[],observations:[obs()],assessments:[unknown,unrelated,known],coverage:[],warnings:[]};
 const out=await refineFreexianEvidence(result,{distribution:d,packages:[dep]},{resolveReleaseEvidence:async input=>{calls.push(input);return {status:'not-affected',evidence:{id:input.id,sourceName:input.sourceName,sourceVersion:input.sourceVersion,distribution:input.distribution,row:'release-specific'}};}});
 assert.equal(calls.length,1);assert.equal(out.assessments[0].status,'not-affected');assert.equal(out.assessments[1].status,'unknown');assert.equal(out.assessments[0].evidence.releaseEvidence.row,'release-specific');assert.equal(out.coverage[0].resolved,1);
 const final=reconcileAssessments(result,{distribution:d});assert.equal(final.observations[0].status,'not-affected');
});
test('refinement groups one CVE per worker and never requests more than configured CVE budget',async()=>{
 const {refineFreexianEvidence}=require('../lib/system-inventory/distribution-sources');const two={...dep,sourceName:'other',name:'other'},third={...a('unknown'),cveId:'CVE-2099-9999'};
 const other={...a('unknown'),dep:two,evidence:{distribution:d,sourceName:'other',sourceVersion:dep.sourceVersion}};
 const observations=[obs(),{...obs(),dep:two},{...obs(),cveId:third.cveId}],r={observations,assessments:[a('unknown'),other,third],matches:[],coverage:[],warnings:[]};let calls=[];
 const answer=await refineFreexianEvidence(r,{distribution:d,packages:[dep,two]},{maxFreexianReleaseEvidenceCves:1,resolveReleaseEvidence:async(input,opts)=>{calls.push({input,offline:!!opts.offline});return {status:'unknown',evidence:{}};}});
 assert.equal(calls.length,2);assert.equal(calls[0].offline,false);assert.equal(calls[1].offline,true);assert.equal(answer.coverage[0].execution,'partial');assert.deepEqual(answer.warnings,[]);
});
test('generic refine runs only on active adapters and optional offline miss is not a warning',async()=>{
 let count=0;const refiner={id:'x',operatorRegion:'us',supports:()=>true,assess:async()=>({}),refine:async()=>{count++;return {};}};
 await assessDistributionSources({distribution:d,packages:[dep]},{distributionSourceRegion:'eu',distributionSourceAdapters:[refiner]});assert.equal(count,0);
 const {refineFreexianEvidence}=require('../lib/system-inventory/distribution-sources'),result={observations:[obs()],assessments:[a('unknown')]};const answer=await refineFreexianEvidence(result,{distribution:d},{offline:true,resolveReleaseEvidence:async()=>({status:'unknown',evidence:{reason:'cache absent'}})});assert.deepEqual(answer.warnings,[]);assert.equal(result.assessments[0].status,'unknown');
});
test('release proof with a mismatched CVE or source version cannot change verdict',async()=>{
 const {refineFreexianEvidence}=require('../lib/system-inventory/distribution-sources');
 for(const mismatch of [{id:'CVE-2099-0001'},{sourceVersion:'2.0-1'}]){const result={observations:[obs()],assessments:[a('unknown')]};await refineFreexianEvidence(result,{distribution:d},{resolveReleaseEvidence:async input=>({status:'not-affected',evidence:{id:input.id,sourceName:input.sourceName,sourceVersion:input.sourceVersion,distribution:d,...mismatch}})});assert.equal(result.assessments[0].status,'unknown');}
});
test('unknown evidence attaches to an exact confirmed match without a duplicate observation',async()=>{
 const finding={dep,source:'osv',cve:{id}},unknown={...obs(),source:'freexian-tracker',status:'possible',reason:'archive differs'};
 const result=await run([a('unknown')],{observations:[unknown],confirmedMatches:[finding]});assert.equal(result.observations.length,0);const proof=finding.cve.applicabilityEvidence.find(x=>x.kind==='source-observation');assert.equal(proof.evidence.reason,'archive differs');
 const different=await run([a('unknown')],{observations:[{...unknown,dep:{...dep,version:'2.0-1'}}],confirmedMatches:[finding]});assert.equal(different.observations.length,1);
});
test('refiner shares configured throttle, allows larger budgets, and preserves abort and external errors',async()=>{
 const {refineFreexianEvidence}=require('../lib/system-inventory/distribution-sources');const mk=()=>({observations:[obs()],assessments:[a('unknown')]});const limiter={request(){}};let got;
 await refineFreexianEvidence(mk(),{distribution:d},{maxFreexianReleaseEvidenceCves:2000,freexianReleaseConcurrency:1,freexianReleaseThrottle:limiter,resolveReleaseEvidence:async(_input,options)=>{got=options.freexianReleaseThrottle;return {status:'unknown',evidence:{}};}});assert.equal(got,limiter);
 const failed=await refineFreexianEvidence(mk(),{distribution:d},{resolveReleaseEvidence:async()=>({status:'unknown',evidence:{failure:'HTTP 503'}})});assert.match(failed.warnings[0].message,/HTTP 503/);
 await assert.rejects(refineFreexianEvidence(mk(),{distribution:d},{resolveReleaseEvidence:async()=>{throw Object.assign(Error('stopped'),{name:'AbortError'});}}),e=>e.name==='AbortError');
});
test('Freexian rate limit is announced once and cache-only CVEs are counted separately',async()=>{
 const second='CVE-2099-2345',notes=[];
 const result={observations:[obs(),{...obs(),cveId:second}],assessments:[a('unknown'),{...a('unknown'),cveId:second}]};
 const out=await require('../lib/system-inventory/distribution-sources').refineFreexianEvidence(result,{distribution:d},{
  lang:'fr',freexianReleaseConcurrency:1,onSourceWarning:m=>notes.push(m),
  resolveReleaseEvidence:async(input,opts)=>({status:'unknown',evidence:opts.offline?{}:{failure:'HTTP 429'}})
 });
 assert.equal(notes.length,1);assert.match(notes[0],/autres sources/);
 assert.equal(out.coverage[0].execution,'partial');assert.equal(out.coverage[0].queriedCves,1);assert.equal(out.coverage[0].cacheOnlyCves,1);
 assert.match(out.warnings[0].message,/HTTP 429.*1 CVE vérifiées uniquement/);
});
