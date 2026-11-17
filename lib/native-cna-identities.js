'use strict';
// CVE Record provider organization IDs, not CVE or product allowlists.
// Debian's CNA ID is corroborated by CVEProject's published Debian records.
const cnaIdentities=Object.freeze([{orgId:'79363d38-fa19-49d1-9214-5f28da3f3ac5',vendor:'debian',ecosystem:'system:deb:debian:*',manager:'deb',distribution:'debian',versionType:'dpkg'}]);
function cnaSystemPackage(affected,context={},registry=cnaIdentities){
 const raw=context.record,container=context.container;if(context.source!=='cveproject'||container!==raw?.containers?.cna)return null;
 const org=container?.providerMetadata?.orgId;if(typeof org!=='string'||org!==raw?.cveMetadata?.assignerOrgId)return null;
 const item=registry.find(r=>r.orgId===org&&String(affected?.vendor||'').toLowerCase()===r.vendor);if(!item)return null;
 const name=affected.packageName;if(typeof name!=='string'||!/^[a-z0-9][a-z0-9+.-]*$/.test(name)||!Array.isArray(affected.versions)||!affected.versions.some(v=>String(v?.versionType||'').toLowerCase()===item.versionType))return null;
 return {ecosystem:item.ecosystem,name,manager:item.manager,distribution:item.distribution,release:null,arch:'source'};
}
module.exports={cnaIdentities,cnaSystemPackage};
