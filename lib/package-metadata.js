'use strict';
// Validation shared by durable public-registry capture and offline seed import.
// A dependency descriptor is evidence, not proof that its transitive graph is complete.
const path = require('node:path');
// Use the same SAX dependency that xml2js itself requires, including nested installs.
const sax = require(require.resolve('sax', {paths:[path.dirname(require.resolve('xml2js/package.json'))]}));
const MAX_BYTES = 4 * 1024 * 1024;
const NPM_FIELDS = Object.freeze(['name','version','dependencies','devDependencies','optionalDependencies','peerDependencies',
 'peerDependenciesMeta','bundledDependencies','bundleDependencies','engines','os','cpu','libc','license','licenses']);
const npmName = n => typeof n === 'string' && n.length <= 214 && /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/.test(n) && !['.','..'].includes(n);
const releaseVersion = v => typeof v === 'string' && v.length <= 256 && /^[0-9][A-Za-z0-9._+-]*$/.test(v) && !/snapshot/i.test(v);
const plain = o => o !== null && typeof o === 'object' && !Array.isArray(o);
const secretKey = k => /(?:^|[._-])(?:password|passphrase|secret|token|api[_-]?key|authorization|access[_-]?key|private[_-]?key)$/i.test(String(k));
function assertNoCredentials(value) {
 if(typeof value!=='string')return;
 if(/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(value))throw Error('credential material in public metadata');
 // SCM links legitimately carry queries (e.g. gitweb ?p=project.git). Credential
 // parameters and userinfo are refused without altering the original evidence.
 const credentialParam=k=>/(?:token|secret|password|passwd|passphrase|apikey|accesskey|privatekey|signature|credential|authorization|session)$/.test(k.toLowerCase().replace(/[^a-z0-9]/g,'')) || /^(?:auth|key|sig|code)$/i.test(k);
 for(const match of value.matchAll(/(?:https?|ssh|git):\/\/[^\s<>"']+/gi)) {
  let u;try{u=new URL(match[0].replace(/&amp;/g,'&'));}catch{throw Error('ambiguous dependency URL');}
  if(u.username || u.password || [...u.searchParams.keys()].some(credentialParam) ||
     (u.hash && /(?:token|secret|password|key)=/i.test(u.hash)))throw Error('credential-bearing dependency URL');
 }
 if(/(?:[?&]|&amp;)(?:[^=\s]*token|password|secret|api[_-]?key|access[_-]?key)=/i.test(value))throw Error('credential-bearing dependency declaration');
}

function canonicalJson(value) {
 const walk = (v, depth = 0) => {
  if (depth > 24) throw Error('metadata nesting exceeds limit');
  if (typeof v === 'string') {assertNoCredentials(v);return v;}
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (Array.isArray(v)) {if(v.length>10000)throw Error('metadata array exceeds limit');return v.map(x=>walk(x,depth+1));}
  if (!plain(v) || Object.keys(v).length > 10000) throw Error('invalid metadata object');
  return Object.fromEntries(Object.keys(v).sort().map(k=>[k,walk(v[k],depth+1)]));
 };
 const body = JSON.stringify(walk(value));
 if (Buffer.byteLength(body) > MAX_BYTES) throw Error('dependency metadata exceeds size limit');
 return body;
}

function npmManifest(raw, name, version) {
 if (!npmName(name) || !releaseVersion(version) || !plain(raw) ||
     (raw.name !== undefined && raw.name !== name) || (raw.version !== undefined && raw.version !== version)) throw Error('npm manifest identity mismatch');
 const out = {name,version};
 for (const key of NPM_FIELDS.slice(2)) if (raw[key] !== undefined) out[key]=raw[key];
 for (const key of ['dependencies','devDependencies','optionalDependencies','peerDependencies','engines']) {
  if (out[key] === undefined) continue;
  if (!plain(out[key]) || Object.keys(out[key]).length > 10000) throw Error('invalid npm dependency map');
  for (const [n,r] of Object.entries(out[key])) if (!(key === 'engines' ? /^[A-Za-z0-9._-]{1,214}$/.test(n) : npmName(n)) ||
      typeof r !== 'string' || r.length > 8192 || /[\u0000-\u001f]/.test(r)) throw Error('invalid npm dependency declaration');
 }
 for (const key of ['bundledDependencies','bundleDependencies','os','cpu','libc']) {
  const value=out[key];if(value === undefined)continue;
  if (key.startsWith('bundle') && typeof value === 'boolean') continue;
  if (!Array.isArray(value) || value.length > 10000 || value.some(x=>typeof x !== 'string' || x.length>214 || /[\u0000-\u001f]/.test(x))) throw Error('invalid npm platform or bundled dependencies');
 }
 if (out.peerDependenciesMeta !== undefined) {
  if (!plain(out.peerDependenciesMeta)) throw Error('invalid npm peer dependency metadata');
  for(const [n,v] of Object.entries(out.peerDependenciesMeta)) if(!npmName(n) || !plain(v) || Object.keys(v).some(k=>k!=='optional') ||
      (v.optional !== undefined && typeof v.optional!=='boolean')) throw Error('invalid npm peer dependency metadata');
 }
 const license=value=>{
  if(typeof value==='string')return;
  if(!plain(value) || Object.keys(value).some(k=>!['type','url'].includes(k)) || Object.values(value).some(v=>typeof v!=='string'))throw Error('invalid npm licence metadata');
 };
 if(out.license!==undefined)license(out.license);
 if(out.licenses!==undefined){if(!Array.isArray(out.licenses) || out.licenses.length>100)throw Error('invalid npm licences');out.licenses.forEach(license);}
 return canonicalJson(out);
}

function validateNpmManifest(body,name,version) {
 if (typeof body !== 'string' || Buffer.byteLength(body)>MAX_BYTES) throw Error('invalid npm manifest size');
 const raw=JSON.parse(body);
 if (!plain(raw) || raw.name!==name || raw.version!==version || Object.keys(raw).some(k=>!NPM_FIELDS.includes(k))) throw Error('invalid immutable npm manifest fields');
 // Reject rather than truncate, and canonicalise only for comparison (hash covers bytes).
 npmManifest(raw,name,version);
 return raw;
}

function validateMavenPom(body,name,version) {
 if(typeof body!=='string' || Buffer.byteLength(body)>MAX_BYTES || /<!DOCTYPE|<!ENTITY/i.test(body) || !releaseVersion(version) ||
    typeof name!=='string' || !/^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/.test(name)) throw Error('invalid immutable Maven descriptor');
 assertNoCredentials(body);
 const expected=name.split(':'), stack=[], texts=[], values=Object.create(null), properties=Object.create(null);
 let roots=0, parentCount=0, propertyBlocks=0, namespace='';
 const parser=sax.parser(true,{trim:false,normalize:false,xmlns:true});
 parser.ondoctype=()=>{throw Error('Maven DTD is forbidden');};
 parser.onopentag=tag=>{
  if(stack.length>=128)throw Error('Maven XML nesting exceeds limit');
  const local=tag.local || tag.name;
  if(!stack.length){
   if(++roots!==1 || local!=='project' || !['','http://maven.apache.org/POM/4.0.0'].includes(tag.uri||''))throw Error('Maven XML root must be project');
   namespace=tag.uri||'';
  }
  const parentPath=stack.join('/');
  if(/^project\/(?:parent\/)?(?:groupId|artifactId|version)$/.test(parentPath) || /^project\/properties\/[^/]+$/.test(parentPath))throw Error('nested Maven identity value');
  if(secretKey(local))throw Error('credential field in public Maven metadata');
  for(const attribute of Object.values(tag.attributes || {})){
   if(secretKey(attribute.local || attribute.name))throw Error('credential attribute in public Maven metadata');
   assertNoCredentials(attribute.value);
  }
  stack.push(local);texts.push('');
  const p=stack.join('/');
  if((/^project\/(?:parent\/)?(?:groupId|artifactId|version)$/.test(p) || /^project\/properties(?:\/[^/]+)?$/.test(p)) && (tag.uri||'')!==namespace)throw Error('ambiguous Maven coordinate namespace');
  if(p==='project/parent' && ++parentCount>1)throw Error('ambiguous Maven parent');
  if(p==='project/properties' && ++propertyBlocks>1)throw Error('ambiguous Maven properties');
 };
 const append=t=>{if(texts.length){texts[texts.length-1]+=t;if(texts[texts.length-1].length>65536)throw Error('Maven XML value exceeds limit');}};
 parser.ontext=append;parser.oncdata=append;
 parser.onclosetag=()=>{
  const p=stack.join('/'), text=texts.pop().trim();stack.pop();assertNoCredentials(text);
  if(/^project\/(?:parent\/)?(?:groupId|artifactId|version)$/.test(p)) {
   if(Object.hasOwn(values,p))throw Error('ambiguous Maven coordinate');values[p]=text;
  }
  if(/^project\/properties\/[^/]+$/.test(p)) {
   const k=p.slice('project/properties/'.length);
   if(Object.hasOwn(properties,k))throw Error('ambiguous Maven property');properties[k]=text;
  }
 };
 parser.write(body).close();
 if(roots!==1)throw Error('missing Maven project');
 const group=values['project/groupId'] || values['project/parent/groupId'];
 const ver=values['project/version'] || values['project/parent/version'];
 const builtins={'project.groupId':group,'pom.groupId':group,'project.version':ver,'pom.version':ver,
  'project.artifactId':values['project/artifactId'],'pom.artifactId':values['project/artifactId']};
 for(const k of ['groupId','artifactId','version']) for(const prefix of ['project.parent.','pom.parent.','parent.'])builtins[prefix+k]=values['project/parent/'+k];
 const resolve=(s,trail=[])=>{
  if(typeof s!=='string' || trail.length>20)throw Error('unresolved Maven identity');
  const out=s.replace(/\$\{([^}]+)\}/g,(_,key)=>{
   if(trail.includes(key))throw Error('cyclic Maven identity');
   return resolve(Object.hasOwn(builtins,key)?builtins[key]:properties[key],[...trail,key]);
  });
  if(out.includes('${') || out.length>256)throw Error('unresolved Maven identity');return out;
 };
 if(resolve(group)!==expected[0] || resolve(values['project/artifactId'])!==expected[1] || resolve(ver)!==version) throw Error('Maven POM identity mismatch');
 return {groupId:expected[0],artifactId:expected[1],version};
}

module.exports={MAX_BYTES,NPM_FIELDS,npmName,releaseVersion,canonicalJson,npmManifest,validateNpmManifest,validateMavenPom,assertNoCredentials};
