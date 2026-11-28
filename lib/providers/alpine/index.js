'use strict';
module.exports={id:'alpine',ttlMs:86400000,build(type,params){
 const base='https://security.alpinelinux.org';let url;
 if(type==='package'){const name=params?.name;if(typeof name!=='string'||!/^[a-z0-9][a-z0-9+_.-]*$/.test(name))throw Error('invalid Alpine source package');url=`${base}/srcpkg/${encodeURIComponent(name)}`;}
 else if(type==='vulnerability'){const id=params?.id;if(typeof id!=='string'||!/^CVE-\d{4}-\d{4,}$/.test(id))throw Error('invalid Alpine vulnerability ID');url=`${base}/vuln/${id}`;}
 else throw Error('invalid Alpine tracker request');
 return {url,init:{headers:{accept:'application/json'}}};
}};
