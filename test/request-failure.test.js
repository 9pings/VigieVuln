'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {responseFailure,responseError}=require('../lib/providers/request-failure');
test('proxy admission refusal is distinguished from upstream failure without reflecting untrusted text',()=>{
 const denied=responseFailure(new Response(null,{status:503,headers:{'x-fad-proxy':'denied','retry-after':'30'}}));
 assert.equal(denied.layer,'proxy');assert.equal(denied.code,'proxy-budget-exhausted');assert.equal(denied.retryAfterSeconds,30);
 const upstream=responseFailure(new Response(null,{status:403,headers:{'x-fad-proxy':'pass'}}),{viaProxy:true});
 assert.equal(upstream.layer,'source');assert.match(upstream.reason,/HTTP 403/);
 const unknown=responseError('EUVD detail',new Response(null,{status:503,headers:{'retry-after':'<script>secret</script>'}}),{viaProxy:true});
 assert.equal(unknown.layer,'proxy');assert.equal(unknown.code,'proxy-request-failed');assert.doesNotMatch(unknown.message,/secret|script|budget/);
 const direct=responseFailure(new Response(null,{status:503}));assert.equal(direct.layer,'source');
});
test('retry date uses observed response semantics, never a fabricated retry deadline',()=>{
 const failure=responseFailure(new Response(null,{status:429,headers:{'retry-after':'Thu, 05 Nov 2026 12:00:10 GMT'}}),{now:Date.parse('2026-11-05T12:00:00Z')});
 assert.equal(failure.retryAfterSeconds,10);
 assert.equal(responseFailure(new Response(null,{status:503})).retryAfterSeconds,undefined);
});
