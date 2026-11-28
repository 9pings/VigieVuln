'use strict';
// Explain the observed transport failure without treating a proxy refusal as an
// upstream outage. Never render response bodies, URLs or arbitrary header text.
function responseFailure(response, { viaProxy = false, now = Date.now() } = {}) {
 const status=Number(response?.status)||null,tag=response?.headers?.get?.('x-fad-proxy');
 const proxy=viaProxy||!!tag;
 const raw=response?.headers?.get?.('retry-after');
 const date=raw ? Date.parse(raw) : NaN;
 const seconds=raw && /^\d+$/.test(raw)?Number(raw):Number.isFinite(date)?Math.max(0,Math.ceil((date-now)/1000)):null;
 const retryAfterSeconds=Number.isSafeInteger(seconds)&&seconds>=0?seconds:null;
 const budget=tag==='denied';
 const origin=budget?'proxy request budget exhausted':proxy&&tag!=='pass'&&tag!=='negative'?'proxy request failed':'source request failed';
 return {code:budget?'proxy-budget-exhausted':proxy&&tag!=='pass'&&tag!=='negative'?'proxy-request-failed':'source-request-failed',
  status,layer:budget||proxy&&tag!=='pass'&&tag!=='negative'?'proxy':'source',
  ...(retryAfterSeconds!==null?{retryAfterSeconds}:{}),
  reason:`${origin} (HTTP ${status??'unknown'})${retryAfterSeconds!==null?`; retry after ${retryAfterSeconds}s`:''}`};
}
function responseError(label,response,options){
 const failure=responseFailure(response,options),error=Error(`${label}: ${failure.reason}`);
 Object.assign(error,failure);return error;
}
module.exports={responseFailure,responseError};
