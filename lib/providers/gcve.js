'use strict';

// Fixed publisher URLs only. The client verifies the signed directory before
// requesting a GNA dump; the proxy cannot be used as an arbitrary URL fetcher.
module.exports={
 id:'gcve',ttlMs:6*3600*1000,
 build(type,params){
  if(type==='directory')return {url:'https://gcve.eu/dist/gcve.json'};
  if(type==='signature')return {url:'https://gcve.eu/dist/gcve.json.sigsha512'};
  if(type==='gna-dump'){
   const gna=params?.gna;
   if(!Number.isSafeInteger(gna)||gna<1||gna>1000000)throw Error('invalid GCVE GNA identifier');
   return {url:`https://vulnerability.circl.lu/dumps/gna-${gna}.ndjson`};
  }
  throw Error('invalid GCVE request');
 }
};
