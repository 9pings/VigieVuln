'use strict';
const adapters=Object.freeze([{id:'github-go-publisher',operatorRegion:'us',assess:(deps,options)=>require('./go-publisher-advisories').assessGoPublisherAdvisories(deps,options)}]);
async function assessPublisherAdvisories(deps,options={}){
 if(options.publisherAdvisories===false)return {matches:[],warnings:[],coverage:[{collector:'publisher-advisories',execution:'not-applicable',result:'not-consulted',expected:false,reason:'Publisher advisory source excluded by configuration.'}]};
 const selected=options.publisherAdvisoryAdapters||adapters;if(!Array.isArray(selected)||selected.some(a=>!a||typeof a.id!=='string'||typeof a.assess!=='function'))throw Error('Invalid publisher advisory adapter registry');
 const result={matches:[],warnings:[],coverage:[]},region=options.publisherSourceRegion||options.sourceProfile;
 for(const adapter of selected){
  if(['eu','us'].includes(region)&&adapter.operatorRegion!==region){result.coverage.push({collector:adapter.id,execution:'not-applicable',result:'not-consulted',expected:false,reason:'Source operator is outside the selected region or its region is not established.'});continue;}
  try{const response=await adapter.assess(deps,options);for(const name of Object.keys(result)){if(!Array.isArray(response?.[name]))throw Error(`Invalid publisher ${name}`);result[name].push(...response[name]);}}catch(error){result.warnings.push({type:'source-unavailable',source:adapter.id,message:`${adapter.id}: ${error.message}`});result.coverage.push({collector:adapter.id,execution:'failed',result:'indeterminate',reason:error.message});}
 }return result;
}
module.exports={adapters,assessPublisherAdvisories};
