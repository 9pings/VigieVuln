'use strict';

const path = require('node:path');
const {createCacheRepository} = require('./cache-repository');

function slot(file) {
  const dir=path.dirname(file);
  return {cacheDir:path.basename(dir)==='poms-cache'?path.dirname(dir):dir,
    key:path.basename(file),namespace:file.endsWith('.pom')?'maven-pom':'maven-metadata'};
}
function read(file) {
  const {cacheDir,key,namespace}=slot(file);
  try { return createCacheRepository(cacheDir).get(namespace,key); }
  catch { return null; }
}
function write(file,value) {
  const {cacheDir,key,namespace}=slot(file);
  try { createCacheRepository(cacheDir).put(namespace,key,value); }
  catch { /* Optional cache. */ }
}
module.exports={read,write};
