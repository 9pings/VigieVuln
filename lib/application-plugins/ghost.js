'use strict';
const path=require('node:path').posix;
function manifest(ctx,dir){
 const file=path.join(dir,'package.json');
 try{return JSON.parse(ctx.readText(file,1024*1024));}catch{return null;}
}
module.exports={
 id:'ghost',apiVersion:1,version:'1.0.0',label:'Ghost',supportedLayouts:['installation','source'],
 requiredCodecs:['npm'],providerIds:[],capabilities:{inventory:'qualified'},
 discover(ctx){
  return ctx.index.directories.filter(dir=>ctx.index.hasFile(path.join(dir,'core/boot.js')) &&
   ctx.index.hasFile(path.join(dir,'index.js')) && manifest(ctx,dir)?.name==='ghost')
   .map(root=>({root,evidence:[{path:path.join(root,'package.json'),field:'name'},{path:path.join(root,'core/boot.js')}]}));
 },
 collect(app,ctx){
  const data=manifest(ctx,app.root);
  const components=[{id:app.id+':core',applicationId:app.id,kind:'core',name:'Ghost',coord:'ghost',
   version:data?.version || null,visibility:'public',path:app.root,
   evidence:[{path:path.join(app.root,'package.json'),field:'version'}]}];
  const themes=path.join(app.root,'content/themes');
  for(const dir of ctx.index.directories){
   if(path.dirname(dir)!==themes || !ctx.index.hasFile(path.join(dir,'package.json')))continue;
   const theme=manifest(ctx,dir);
   if(!theme?.name || !theme.engines?.ghost)continue;
   const repository = typeof theme.repository === 'string' ? theme.repository : theme.repository?.url;
   const repo = /^https:\/\/github\.com\/TryGhost\/(Casper|Source)(?:\.git)?\/?$/i.exec(repository || '')?.[1]?.toLowerCase();
   const official = repo && repo === String(theme.name).toLowerCase() && !ctx.isPrivatePath(dir);
   components.push({...(official ? {releaseRepository:'TryGhost/'+(repo==='casper'?'Casper':'Source')} : {}),id:app.id+':theme:'+path.basename(dir),applicationId:app.id,kind:'theme',name:theme.name,coord:theme.name,
    version:theme.version || null,path:dir,visibility:ctx.isPrivatePath(dir)?'private':official?'public':'unknown',activation:'unknown',
    evidence:[{path:path.join(dir,'package.json'),field:'version'}]});
  }
  return {components,coverage:[{applicationId:app.id,capability:'inventory',execution:'completed',result:'not-applicable',
   expected:components.length,executed:components.length}],diagnostics:[]};
 },
 assess(){return [];},remediation(){return null;},
};
