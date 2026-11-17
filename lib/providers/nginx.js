'use strict';
module.exports={id:'nginx',ttlMs:86400000,build(type,params){
 if(type!=='advisories'||!params||Object.keys(params).length)throw Error('invalid NGINX advisory request');
 return {url:'https://raw.githubusercontent.com/nginx/nginx.org/master/xml/en/security_advisories.xml',init:{headers:{accept:'application/xml,text/xml'}}};
}};
