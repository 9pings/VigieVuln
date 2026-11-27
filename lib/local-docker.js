'use strict';
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const {pipeline} = require('node:stream/promises');
const {Transform} = require('node:stream');

function get(socketPath, resource) {
  return new Promise((resolve,reject) => {
    const req = http.get({socketPath, path:resource, agent:false}, res => {
      if (res.statusCode === 200) return resolve(res);
      res.destroy();
      reject(Object.assign(Error('Docker Engine returned HTTP ' + res.statusCode),{status:res.statusCode}));
    });
    req.on('error',reject);
    req.setTimeout(120000, () => req.destroy(Error('Docker Engine stopped responding')));
  });
}

async function openImage(reference,socketPath='/var/run/docker.sock'){
 let image;
 try{
  const response=await get(socketPath,'/images/'+encodeURIComponent(reference)+'/json');
  const chunks=[];let bytes=0;
  for await(const part of response){bytes+=part.length;if(bytes>16*1024*1024)throw Error('Docker metadata exceeds size limit');chunks.push(part);}
  image=JSON.parse(Buffer.concat(chunks));
 }catch(error){if(error.status===404 || ['ENOENT','ECONNREFUSED'].includes(error.code))return null;throw error;}
 if(!/^sha256:[a-f0-9]{64}$/.test(image.Id||''))throw Error('Invalid Docker image identity');
 const dir=await fs.promises.mkdtemp(path.join(os.tmpdir(),'vigievuln-docker-')),file=path.join(dir,'image.tar');
 const cleanup=()=>fs.promises.rm(dir,{recursive:true,force:true});
 try{
  let size=0;
  const limit=new Transform({transform(chunk,encoding,done){size+=chunk.length;done(size>20*1024**3?Error('Docker archive exceeds size limit'):null,chunk);}});
  await pipeline(await get(socketPath,'/images/'+encodeURIComponent(image.Id)+'/get'),limit,fs.createWriteStream(file,{flags:'wx',mode:0o600}));
  return {path:file,metadata:{id:image.Id,tags:image.RepoTags||[],repoDigests:image.RepoDigests||[]},cleanup};
 }catch(error){await cleanup();throw error;}
}
async function collectImages(socketPath, addImage, failed, selected = () => true) {
  if (!path.isAbsolute(socketPath)) throw Error('a local absolute Docker socket path is required');
  const response = await get(socketPath, '/images/json?all=1');
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response) {
    bytes += chunk.length;
    if (bytes > 32 * 1024 * 1024) throw Error('Docker image list exceeds size limit');
    chunks.push(chunk);
  }
  const images = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!Array.isArray(images)) throw Error('invalid Docker image list');
  const seen = new Set();
  for (const image of images) {
    if (!selected(image)) continue;
    if (!/^sha256:[a-f0-9]{64}$/.test(image.Id)) throw Error('invalid local image ID');
    if (seen.has(image.Id)) continue;
    seen.add(image.Id);
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(),'vigievuln-docker-'));
    try {
      const file = path.join(dir, 'image.tar');
      let size = 0;
      const limit = new Transform({transform(chunk, encoding, cb) {
        size += chunk.length;
        cb(size > 20 * 1024 ** 3 ? Error('Docker archive exceeds size limit') : null, chunk);
      }});
      const stream = await get(socketPath, '/images/' + encodeURIComponent(image.Id) + '/get');
      await pipeline(stream,limit,fs.createWriteStream(file,{flags:'wx',mode:0o600}));
      await addImage(file, image.Id, {id:image.Id, tags:image.RepoTags || [], repoDigests:image.RepoDigests || []});
    } catch (error) {failed(image.Id, error);}
    finally {await fs.promises.rm(dir,{recursive:true,force:true});}
  }
}
module.exports = {collectImages,openImage};
