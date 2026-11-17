'use strict';
const fs=require('fs'),crypto=require('crypto'),path=require('path'),base='/tmp/vv-elts-20261106',cli='/mnt/wsl/WipDrive/_libs/VigieVuln/cli';
const proof=JSON.parse(fs.readFileSync(cli+'/docs/benchmark-evidence/2026-11-05-images/image-updates/registry-reference-verification.json'));const {createCacheRepository}=require(cli+'/lib/cache-repository');
for(const p of ['nginx','traefik']){
 const original=JSON.parse(fs.readFileSync(`${base}/${p}/inventory.json`)),old=JSON.parse(fs.readFileSync(`/tmp/vv-image-updates-20261105/${p}/inventory.json`)),target=original.targets[0],binding=old.targets[0].metadata.registryReference,match=proof.find(x=>x.reference===binding.reference);
 if(!match||target.metadata.digest!==binding.platformDigest||!match.linuxAmd64.includes(binding.platformDigest)||match.indexDigest!==binding.indexDigest||match.observedAt!==binding.verifiedAt||target.metadata.platform?.os!=='linux'||target.metadata.platform?.architecture!=='amd64')throw Error('registry binding does not match immutable verification');
 target.metadata.registryReference=binding;const {integrity,...content}=original;original.integrity={algorithm:'sha256',digest:crypto.createHash('sha256').update(JSON.stringify(content)).digest('hex')};
 fs.writeFileSync(`${base}/${p}/inventory-published.json`,JSON.stringify(original,null,2)+'\n');
 const key='image-tags-'+crypto.createHash('sha256').update(`registry-1.docker.io/library/${p}`).digest('hex'),oldCache=createCacheRepository(`/tmp/vv-image-updates-20261105/${p}/cache`),cacheDir=p==='nginx'?`${base}/nginx/cache`:`/tmp/vv-reduction-20261105/traefik/cache`,newCache=createCacheRepository(cacheDir),entry=oldCache.get('catalogue',key);
 if(!entry||entry.value.registry!=='registry-1.docker.io'||entry.value.repository!==`library/${p}`)throw Error('registry cache scope mismatch');
 const expected=JSON.parse(fs.readFileSync(`${cli}/docs/benchmark-evidence/2026-11-05-images/image-updates/${p}-update.json`));if(entry.value.observedAt!==expected.observedAt)throw Error('registry cache observation timestamp mismatch');
 newCache.put('catalogue',key,entry.value,{fetchedAt:entry.fetchedAt,expiresAt:entry.expiresAt,stale:entry.stale,metadata:entry.metadata});
 console.log(JSON.stringify({project:p,inventory:`${base}/${p}/inventory-published.json`,cacheDir,cacheKey:key,reference:binding.reference,platformDigest:binding.platformDigest,observedAt:entry.value.observedAt}));
}
require(cli+'/lib/cache-db').closeCacheDbs();
