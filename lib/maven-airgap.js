'use strict';

// Reconstruct Maven's per-module resolution without exporting project paths,
// POMs, arbitrary properties or application source.
const {coord}=require('./core');
const {resolveDepVersion}=require('./cve-match');
const {localChain,chainPropertyOverrides}=require('./maven-reactor');
const {cleanVersion,filterVersionProperties}=require('./deps-descriptor');
const IDENT=/^[A-Za-z0-9_.-]+$/;
const EXCLUSION=/^[A-Za-z0-9_.*-]+$/;
const SCOPES=new Set(['compile','runtime','provided','test','system','import']);
const text=x=>typeof x==='string'&&x.length<=4096?x:null;
const ident=x=>{x=text(x);return x&&IDENT.test(x)?x:null};
const version=x=>{x=text(x);return x?cleanVersion(x):null};
const nodeValue=(node,key,props)=>resolveDepVersion(coord(node?.[key]?.[0])||'',props)||null;

function nodeHint(node,props,exclude){
 const groupId=ident(nodeValue(node,'groupId',props)),artifactId=ident(nodeValue(node,'artifactId',props));
 if(!groupId||!artifactId||(exclude&&exclude.test(groupId)))return null;
 const scope=coord(node.scope?.[0])||null,type=ident(nodeValue(node,'type',props)),classifier=ident(nodeValue(node,'classifier',props));
 const exclusions=[];
 for(const x of node.exclusions?.[0]?.exclusion||[]){
  const g=text(nodeValue(x,'groupId',props)||'*'),a=text(nodeValue(x,'artifactId',props)||'*');
  if(g&&a&&EXCLUSION.test(g)&&EXCLUSION.test(a))exclusions.push({groupId:g,artifactId:a});
 }
 return {groupId,artifactId,version:version(nodeValue(node,'version',props)),
  ...(scope&&SCOPES.has(scope)?{scope}:{}),...(type?{type}:{}),...(classifier?{classifier}:{}),
  ...(coord(node.optional?.[0])==='true'?{optional:true}:{}),...(exclusions.length?{exclusions}:{})};
}

function buildReactorHints({store,propsByPom},{exclude,versionPropertyNames=[]}={}){
 if(!store||!propsByPom)return null;
 const modules=[];
 for(const pom of Object.keys(propsByPom)){
  if(!store.byPath[pom])continue;
  const {chain,externalParent}=localChain(pom,store),props=propsByPom[pom]?.properties||{},dependencies=[],management=[];
  for(const member of chain){
   const entry=propsByPom[member]||{};
   for(const node of entry.dependencies||[]){const h=nodeHint(node,props,exclude);if(h)dependencies.push(h)}
   for(const node of entry.dependencyManagement||[]){
    const h=nodeHint(node,entry.properties||{},exclude);if(!h)continue;
    if(h.scope==='import'&&((h.version&&store.byId[`${h.groupId}:${h.artifactId}:${h.version}`])||store.byId[`${h.groupId}:${h.artifactId}`]))continue;
    management.push(h);
   }
  }
  const parent=externalParent&&ident(externalParent.groupId)&&ident(externalParent.artifactId)&&version(externalParent.version)
   ? {groupId:externalParent.groupId,artifactId:externalParent.artifactId,version:version(externalParent.version)} : null;
  modules.push({dependencies,management,...(parent&&!(exclude&&exclude.test(parent.groupId))?{parent}:{}),
   overrides:filterVersionProperties(chainPropertyOverrides(chain,store),versionPropertyNames)});
 }
 return modules.length?{schema:1,modules}:null;
}

function restoreReactorHints(hints){
 if(!hints||hints.schema!==1||!Array.isArray(hints.modules)||hints.modules.length>5000)throw Error('invalid Maven reactor hints');
 const store={byPath:{},byId:{},excludedById:{},missingById:{},anyMissingById:{}},propsByPom={};let total=0;
 const readNode=x=>{
  if(!x||!ident(x.groupId)||!ident(x.artifactId)||x.version!=null&&!version(x.version)||x.scope!=null&&!SCOPES.has(x.scope)||x.type!=null&&!ident(x.type)||x.classifier!=null&&!ident(x.classifier)||x.optional!=null&&typeof x.optional!=='boolean'||x.exclusions!=null&&!Array.isArray(x.exclusions))throw Error('invalid Maven reactor dependency');
  const n={groupId:[x.groupId],artifactId:[x.artifactId]};
  for(const k of ['version','scope','type','classifier'])if(x[k])n[k]=[x[k]];
  if(x.optional)n.optional=['true'];
  if(x.exclusions?.length){if(x.exclusions.length>1000)throw Error('too many Maven exclusions');n.exclusions=[{exclusion:x.exclusions.map(e=>{
   if(!e||!text(e.groupId)||!EXCLUSION.test(e.groupId)||!text(e.artifactId)||!EXCLUSION.test(e.artifactId))throw Error('invalid Maven exclusion');
   return {groupId:[e.groupId],artifactId:[e.artifactId]};})}];}
  return n;
 };
 for(const [i,m] of hints.modules.entries()){
  if(!m||!Array.isArray(m.dependencies)||!Array.isArray(m.management)||!m.overrides||typeof m.overrides!=='object'||Array.isArray(m.overrides))throw Error('invalid Maven reactor module');
  total+=m.dependencies.length+m.management.length;if(total>100000)throw Error('too many Maven reactor entries');
  const overrides=filterVersionProperties(m.overrides,Object.keys(m.overrides));
  if(Object.keys(overrides).length!==Object.keys(m.overrides).length)throw Error('invalid Maven version overrides');
  let parent=null;
  if(m.parent){if(!ident(m.parent.groupId)||!ident(m.parent.artifactId)||!version(m.parent.version))throw Error('invalid Maven reactor parent');parent={groupId:m.parent.groupId,artifactId:m.parent.artifactId,version:m.parent.version};}
  const id=`@module-${i}`;
  store.byPath[id]={pomPath:id,parentInfo:parent,properties:overrides};
  propsByPom[id]={properties:{},dependencies:m.dependencies.map(readNode),dependencyManagement:m.management.map(readNode)};
 }
 return {store,propsByPom};
}
module.exports={buildReactorHints,restoreReactorHints};
