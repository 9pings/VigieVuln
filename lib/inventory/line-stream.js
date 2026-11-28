'use strict';
const {StringDecoder}=require('node:string_decoder');

// JSONL is delimited by LF, not the additional Unicode separators that the
// readline module treats as line endings. Decode incrementally across chunks.
async function* readTextLines(stream,{maxBytes=16*1024*1024}={}) {
 const decoder=new StringDecoder('utf8');let pending='';
 try {
  for await(const chunk of stream) {
   pending+=typeof chunk==='string'?chunk:decoder.write(chunk);let at;
   while((at=pending.indexOf('\n'))!==-1) {
    const line=pending.slice(0,at);pending=pending.slice(at+1);
    if(Buffer.byteLength(line)>maxBytes)throw Error('line exceeds size limit');
    yield line;
   }
   if(pending.length>maxBytes)throw Error('line exceeds size limit');
  }
  pending+=decoder.end();
  if(Buffer.byteLength(pending)>maxBytes)throw Error('line exceeds size limit');
  if(pending)yield pending;
 } finally {stream.destroy();}
}
module.exports={readTextLines};
