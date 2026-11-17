'use strict';
// Import publisher inventories as unverified evidence; no signature tools invoked.
const fs=require('node:fs');
const {makeDepRecord}=require('../dep-record');
const MAX_BYTES=32*1024*1024, MAX_PACKAGES=250000;
const adapters=new Map([
 ['maven',p=>({ecosystem:'maven',namespace:p.namespace,name:p.name})],
 ['composer',p=>({ecosystem:'composer',namespace:p.namespace,name:p.name})],
 ...[['npm','npm'],['pypi','pypi'],['nuget','nuget'],['golang','go'],['gem','ruby']].map(([type,ecosystem])=>[type,p=>({ecosystem,name:p.namespace?`${p.namespace}/${p.name}`:p.name})]),
 ...['deb','rpm','apk'].map(type=>[type,p=>({system:true,type,name:p.name,namespace:p.namespace})]),
]);
function parsePurl(value) {
 if(typeof value!=='string'||!value.startsWith('pkg:'))return null;
 try {let s=value.slice(4).split('#',1)[0];const q=s.indexOf('?'),query=q<0?'':s.slice(q+1);if(q>=0)s=s.slice(0,q);const slash=s.indexOf('/');if(slash<1)return null;const type=s.slice(0,slash).toLowerCase();s=s.slice(slash+1);const at=s.lastIndexOf('@');const version=at>=0?decodeURIComponent(s.slice(at+1)):null;if(at>=0)s=s.slice(0,at);const parts=s.split('/').map(decodeURIComponent);const name=parts.pop();if(!name)return null;const qualifiers={};for(const [k,v] of new URLSearchParams(query))qualifiers[k.toLowerCase()]=v;return {type,namespace:parts.join('/'),name,version,qualifiers};}catch{return null}
}
// Evidence adapters accept only explicit publisher distribution declarations.
const distributionAdapters = [
 {id:'purl-distro', extract({purl}) {const value=purl?.qualifiers?.distro;if(!value)return null;const m=/^([a-z][a-z0-9._-]*)-([0-9][a-z0-9._+-]*)$/i.exec(value);return m?{id:m[1].toLowerCase(),versionId:m[2],evidence:{type:'purl-distro',value}}:null;}},
 {id:'purl-os-qualifiers', extract({purl}) {const id=purl?.qualifiers?.os_name, versionId=purl?.qualifiers?.os_version;if(!id||!versionId)return null;return {id:id.toLowerCase(),versionId,evidence:{type:'purl-os-qualifiers',osName:id,osVersion:versionId}};}},
 {id:'cyclonedx-os', extract({component,format}) {if(format!=='cyclonedx' || component?.type!=='operating-system' || typeof component.name!=='string' || typeof component.version!=='string')return null;const id=component.name.toLowerCase(), versionId=component.version;if(!/^[a-z][a-z0-9._-]*$/.test(id)||!/^[0-9][a-z0-9._+-]*$/i.test(versionId))return null;return {id,versionId,evidence:{type:'cyclonedx-operating-system',name:component.name,version:versionId}};}},
];
function readSbom(input,opts={}) {
 const max=opts.maxBytes??MAX_BYTES,warnings=[],deps=new Map(),systemPackages=[];let doc=input;
 const activeAdapters=opts.purlAdapters || adapters;
 const scopes=opts.distributionAdapters || distributionAdapters;if(!Array.isArray(scopes) || scopes.some(a=>!a || typeof a.id!=='string' || typeof a.extract!=='function'))throw Error('Invalid SBOM distribution adapter registry');if(!(activeAdapters instanceof Map) || [...activeAdapters].some(([key,fn])=>typeof key!=='string'||typeof fn!=='function'))throw Error('Invalid SBOM adapter registry');
 const warn=(reason,message)=>warnings.push({type:'dependency-coverage',reason,message});
 if(typeof input==='string'){const st=fs.statSync(input);if(st.size>max)throw Error('SBOM exceeds size limit');doc=JSON.parse(fs.readFileSync(input,'utf8'));}
 if(!doc || typeof doc!=='object' || Array.isArray(doc))throw Error('Invalid SBOM document');
 if(Buffer.byteLength(JSON.stringify(doc))>max)throw Error('SBOM exceeds size limit');
 let subjectDigests=[], platform=null, wrapper=false;
 if(typeof doc.payload==='string' && Array.isArray(doc.signatures)) {if(doc.payload.length>Math.ceil(max*4/3)+8 || !/^[A-Za-z0-9+/]*={0,2}$/.test(doc.payload))throw Error('Invalid or oversized DSSE payload');const b=Buffer.from(doc.payload,'base64');if(b.length>max)throw Error('DSSE payload exceeds limit');doc=JSON.parse(b.toString('utf8'));wrapper=true;}
 if(Array.isArray(doc.subject) && doc.predicate && typeof doc.predicate==='object') {wrapper=true;for(const subject of doc.subject)for(const [alg,value] of Object.entries(subject.digest||{}))if(typeof value==='string')subjectDigests.push(`${alg.toLowerCase()}:${value.toLowerCase()}`);doc=doc.predicate;}
 const expected=opts.expectedDigest?.toLowerCase();
 let externalBinding=null;
 if(opts.boundSubjectDigest!==undefined || opts.boundSubjectEvidence!==undefined) {
  const digest=String(opts.boundSubjectDigest||'').toLowerCase(), evidence=opts.boundSubjectEvidence;
  if(!/^sha256:[0-9a-f]{64}$/.test(digest) || !evidence || evidence.type!=='oci-manifest-subject' || typeof evidence.manifestDigest!=='string' || !/^sha256:[0-9a-f]{64}$/i.test(evidence.manifestDigest))throw Error('Invalid external SBOM subject binding');
  if(subjectDigests.length && !subjectDigests.includes(digest))throw Error('SBOM subject conflicts with OCI manifest subject');
  externalBinding={digest,...evidence};if(!subjectDigests.includes(digest))subjectDigests.push(digest);
 }
 if(expected && subjectDigests.length && !subjectDigests.includes(expected))throw Error('SBOM subject digest does not match expected artifact');
 if(!subjectDigests.length)warn('sbom-unattached','SBOM has no artifact subject digest; its association with this artifact is unverified.');
 warn('sbom-unverified','SBOM publisher identity and signatures were not verified.');
 let format,packages,root=null;
 if(typeof doc.spdxVersion==='string'&&doc.spdxVersion.startsWith('SPDX-2.')){format='spdx2';packages=doc.packages||[];const described=(doc.relationships||[]).filter(r=>r.relationshipType==='DESCRIBES' && (!doc.SPDXID || r.spdxElementId===doc.SPDXID)).map(r=>r.relatedSpdxElement);root=packages.find(p=>described.includes(p.SPDXID))||null;}
 else if(doc.bomFormat==='CycloneDX'){format='cyclonedx';packages=doc.components||[];root=doc.metadata?.component||null;}
 else throw Error('Unsupported SBOM format');
 if(!Array.isArray(packages)||packages.length> (opts.maxPackages??MAX_PACKAGES))throw Error('Invalid or oversized SBOM package list');
 const source=typeof input==='string'?input:(opts.source||'(SBOM)');
 function purls(p){if(format==='cyclonedx')return p.purl?[p.purl]:[];return (p.externalRefs||[]).filter(x=>String(x.referenceType||'').toLowerCase().endsWith('purl')).map(x=>x.referenceLocator);}
 const rootComponent=root?{name:root.name||null,version:root.versionInfo||root.version||null,purl:purls(root)[0]||null}:null;
 const rootPurl=parsePurl(rootComponent?.purl);if(rootPurl?.qualifiers?.arch)platform={architecture:rootPurl.qualifiers.arch};
 const candidates=[];
 function collectScope(component,purl){for(const adapter of scopes){const value=adapter.extract({component,purl,format});if(!value)continue;if(typeof value.id!=='string' || !/^[a-z][a-z0-9._-]*$/.test(value.id) || typeof value.versionId!=='string' || !/^[0-9][a-z0-9._+-]*$/i.test(value.versionId))throw Error('Invalid SBOM distribution evidence');candidates.push(value);}}
 if(root)collectScope(root,rootPurl);
 for(const [i,p] of packages.entries()) {const ps=purls(p), parsed=ps.map(parsePurl).find(Boolean);collectScope(p,parsed);if(!parsed && p===root)continue;if(!parsed){warn('sbom-package-unidentified',`SBOM package ${i+1} has no supported package URL.`);continue;}const adapter=activeAdapters.get(parsed.type);if(!adapter){warn('sbom-package-unsupported',`SBOM package URL type ${parsed.type} is unsupported.`);continue;}const item=adapter(parsed),version=parsed.version;if(!item || typeof item.name!=='string' || !item.name || (!item.system && typeof item.ecosystem!=='string')){warn('sbom-adapter-invalid',`SBOM adapter ${parsed.type} did not provide a valid identity.`);continue;}if(!version){warn('sbom-version-unknown',`SBOM package ${parsed.name} has no version in its package URL.`);continue;}
  const evidence={source,purl:ps.find(x=>parsePurl(x)?.type===parsed.type),qualifiers:parsed.qualifiers,verification:'unverified'};
  if(item.system){systemPackages.push({name:item.name,version,architecture:parsed.qualifiers.arch || null,sourceName:null,sourceVersion:null,manager:item.type,manifestPath:source,ecosystem:'system',provenance:'sbom',distribution:null,qualifiers:parsed.qualifiers,evidence});continue;}
  const dep=makeDepRecord({...item,version,manifestPath:source,provenance:'sbom',scope:'transitive'});dep.coordKey=`sbom:${source}:${i}:${parsed.type}:${parsed.namespace}/${parsed.name}@${version}`;dep.sbomEvidence=evidence;deps.set(dep.coordKey,dep);
 }
 const unique=new Map(candidates.map(c=>[`${c.id}\0${c.versionId}`,c]));let distribution=null;
 if(unique.size===1)distribution=[...unique.values()][0];else if(unique.size>1)warn('sbom-distribution-conflict','SBOM declares conflicting distribution identities; no common advisory scope can be selected.');else if(systemPackages.length)warn('sbom-distribution-unknown','SBOM system packages have no explicit distribution identity; advisory scope is unknown.');
 const missingSource=systemPackages.filter(pkg=>!pkg.sourceName || !pkg.sourceVersion).length;
 if(missingSource)warn('sbom-system-source-unknown',`${missingSource} system packages lack source package name or version; distro advisory assessment may be incomplete.`);
 for(const pkg of systemPackages)pkg.distribution=distribution;
 return {deps,systemPackages,distribution,metadata:{format,subjectDigests,externalBinding,platform,rootComponent,verification:'unverified',wrapper,coverage:{packages:packages.length,dependencies:deps.size,systemPackages:systemPackages.length,warnings:warnings.length}},warnings};
}
module.exports={readSbom,parsePurl,adapters,distributionAdapters,MAX_BYTES,MAX_PACKAGES};
