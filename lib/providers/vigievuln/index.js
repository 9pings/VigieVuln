'use strict';
// Our reviewed records are served only by the configured proxy, never by a
// caller-supplied URL or a third-party origin.
module.exports={id:'vigievuln',ttlMs:12*3600000,build(type){
 if(type==='advisories')return {url:'https://api.vigievuln.fr/v1/resource',proxyOnly:true};
 throw Error('invalid VigieVuln request');
}};
