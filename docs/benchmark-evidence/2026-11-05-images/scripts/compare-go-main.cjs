'use strict';
// node compare-go-main.cjs <original-comparison.json> <new-findings.json> <grype.json> <output.json>
// The first result uses the unchanged exact-coordinate method. The second is
// explicitly a separate same-binary equivalence, not a generic package alias.
const fs=require('node:fs'),crypto=require('node:crypto');
const [originalPath,newPath,grypePath,outPath]=process.argv.slice(2);if(!outPath)throw Error('four paths required');
const old=JSON.parse(fs.readFileSync(originalPath)),report=JSON.parse(fs.readFileSync(newPath)),grype=JSON.parse(fs.readFileSync(grypePath));
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const main=report.cve.filter(c=>c.dep?.coord==='github.com/traefik/traefik/v2' && c.dep?.version==='v2.11.0');
const proof=main[0]?.dep?.binaryEvidence;if(!proof||proof.source!=='go-vcs-and-module-proxy'||proof.binaryPath!=='usr/local/bin/traefik')throw Error('binary identity evidence missing');
const rows=main.map(c=>({id:c.id,ids:[...new Set([c.id,...(c.aliases||[]),...(c.upstream||[])])]}));
const generic=old.rows.grype.filter(x=>x.ecosystem==='binary'&&x.name==='traefik'&&x.version==='2.11.0');
for(const row of generic){const raw=grype.matches.filter(m=>m.vulnerability?.id===row.primaryId && m.artifact?.type==='binary' && m.artifact?.name===row.name && m.artifact?.version===row.version);if(!raw.length || raw.some(m=>!m.artifact.locations?.some(l=>l.path==='/'+proof.binaryPath)))throw Error(`Grype binary path not confirmed for ${row.primaryId}`);}
const matched=generic.map(g=>({observation:g.primaryId,ids:g.ids,matched:rows.filter(v=>g.ids.some(id=>v.ids.includes(id))).map(v=>v.id)}));
const original=old.pairwise.grypeAgainstVv;
const result={generatedAt:new Date().toISOString(),inputs:{baselineComparisonSha256:sha(originalPath),newFindingsSha256:sha(newPath),grypeSha256:sha(grypePath)},scope:{platformManifest:'sha256:903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111',binaryPath:proof.binaryPath,binarySha256:proof.binarySha256,goModule:'github.com/traefik/traefik/v2',version:'v2.11.0',proof},baselineExact:{observations:original.observations,matched:original.matched,missing:original.missing.length},currentExact:{grypeObservations:old.rows.grype.length,grypeMatched:old.rows.grype.filter(g=>report.cve.some(c=>{const type=c.dep?.packageType||c.dep?.ecosystem;const mapped=type==='go'?'golang':type;const version=mapped==='golang'?String(c.dep.version).replace(/^v(?=\d)/,''):c.dep?.version;return mapped===g.ecosystem&&c.dep?.coord===g.name&&version===g.version&&g.ids.some(id=>[c.id,...(c.aliases||[]),...(c.upstream||[])].includes(id));})).length},sameBinaryComparison:{grypeObservations:generic.length,mainGoFindings:main.length,matched:matched.filter(x=>x.matched.length).length,unmatched:matched.filter(x=>!x.matched.length),observations:matched},warnings:report.warnings};
fs.writeFileSync(outPath,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({currentExact:result.currentExact,sameBinary:result.sameBinaryComparison.matched,unmatched:result.sameBinaryComparison.unmatched.length}));
