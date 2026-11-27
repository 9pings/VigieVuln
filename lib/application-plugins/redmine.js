'use strict';
const path=require('node:path').posix;
const versionFile='lib/redmine/version.rb';
function versionFrom(text){
 if(!/^\s*module Redmine\s*$/m.test(text) || !/^\s*module VERSION\s*$/m.test(text))return null;
 const values=['MAJOR','MINOR','TINY'].map(key=>new RegExp('^\\s*'+key+'\\s*=\\s*(\\d+)\\s*$','m').exec(text)?.[1]);
 return values.every(Boolean)?values.join('.'):null;
}
module.exports={
 id:'redmine',apiVersion:1,version:'1.0.0',label:'Redmine',supportedLayouts:['installation','source'],
 requiredCodecs:[],providerIds:[],capabilities:{inventory:'qualified'},upstreamCpe:'redmine:redmine',
 discover(ctx){
  return ctx.index.directories.filter(root=>[versionFile,'config/application.rb','Gemfile'].every(file=>ctx.index.hasFile(path.join(root,file))) &&
   versionFrom(ctx.readText(path.join(root,versionFile),256*1024)))
   .map(root=>({root,evidence:[{path:path.join(root,versionFile),field:'Redmine::VERSION'},{path:path.join(root,'config/application.rb')}]}));
 },
 collect(app,ctx){
  const file=path.join(app.root,versionFile),version=versionFrom(ctx.readText(file,256*1024));
  return {components:[{id:app.id+':core',applicationId:app.id,kind:'core',name:'Redmine',coord:'redmine',version,
   visibility:'public',path:app.root,evidence:[{path:file,field:'Redmine::VERSION (MAJOR, MINOR, TINY)'}]}],
   coverage:[{applicationId:app.id,capability:'inventory',execution:'completed',result:'not-applicable',expected:1,executed:1}],diagnostics:[]};
 },
 assess(){return [];},remediation(){return null;},
};
