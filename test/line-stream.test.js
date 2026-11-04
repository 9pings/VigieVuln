'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {Readable}=require('node:stream');
const {readTextLines}=require('../lib/line-stream');
test('JSONL separates only LF, retaining Unicode separators and chunk-split UTF-8',async()=>{
 const values=[{text:'left\u2028middle\u2029right😀'},{text:'other'}],raw=Buffer.from(values.map(x=>JSON.stringify(x)).join('\n'));
 const chunks=[];for(let i=0;i<raw.length;i+=2)chunks.push(raw.subarray(i,i+2));
 const lines=[];for await(const s of readTextLines(Readable.from(chunks)))lines.push(JSON.parse(s));
 assert.deepEqual(lines,values);
});
test('line reader bounds records even when no LF arrives',async()=>{
 await assert.rejects(async()=>{for await(const x of readTextLines(Readable.from([Buffer.from('abcdef')]),{maxBytes:4}))void x},/size limit/);
});
