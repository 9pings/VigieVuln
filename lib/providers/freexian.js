'use strict';
module.exports={id:'freexian',ttlMs:86400000,snapshotProjection(type,params){
 if(type!=='tracker')return null;
 const parse=(body,p)=>require('../system-inventory/freexian-tracker').parseTrackerBytes(body,p);
 return {id:'tracker-v1',sourceParams:{},maxSourceBytes:256*1024*1024,ttlMs:4*3600*1000,contentType:'application/json',async validate(body){await parse(body,{packages:[]});},async project(body,requestParams){const result=await parse(body,requestParams);return Buffer.from(JSON.stringify({packages:result.packages}));}};
},build(type,params){
 const base='https://www.freexian.com/lts/extended/updates/';
 if(type==='vulnerability' && Object.keys(params||{}).length===1 && typeof params.id==='string' && /^CVE-\d{4}-\d{4,7}$/i.test(params.id))return {url:`https://deb.freexian.com/extended-lts/tracker/${params.id.toUpperCase()}`};
 if(type==='tracker' && Object.keys(params||{}).length===1 && Array.isArray(params.packages) && params.packages.length>0 && params.packages.length<=1000 && params.packages.every(p=>typeof p==='string' && /^[a-z0-9][a-z0-9+.-]{0,199}$/.test(p)))return {url:'https://deb.freexian.com/extended-lts/tracker/data/json'};
 if(type==='index'&&Number.isSafeInteger(params?.page)&&params.page>0&&params.page<=10000&&Object.keys(params).length===1)return {url:params.page===1?base:`${base}page/${params.page}/`};
 if(type==='advisory'&&typeof params?.slug==='string'&&/^ela-\d+-\d+-[a-z0-9][a-z0-9.+-]*$/.test(params.slug)&&Object.keys(params).length===1)return {url:`${base}${params.slug}/`};
 throw Error('invalid Freexian advisory request');
}};
