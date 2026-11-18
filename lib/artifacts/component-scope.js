'use strict';

const IMAGE_COMPONENT_SCOPE='image-components/1';
const parts=value=>String(value||'').replace(/\\/g,'/').split('/').filter(Boolean);
const stores=new Set(['node_modules','vendor','site-packages','dist-packages','specifications','__pypackages__','.cache','.npm','.yarn','.m2','.gradle','.nuget']);
// Installed metadata is authoritative inside package stores; source manifests
// bundled there can be examples or fixtures belonging to the enclosing library.
const isProjectDescriptor=value=>!parts(value).some(n=>stores.has(n));

// Only a package root describes an installed npm component. Files such as
// pkg/dist/mjs/package.json set module-loading rules, not another package.
function isNpmPackageDescriptor(value) {
 const names=parts(value);
 if(names.at(-1)!=='package.json')return false;
 const index=names.lastIndexOf('node_modules');
 if(index<0)return true;
 const tail=names.slice(index+1);
 return tail[0]?.startsWith('@') ? tail.length===3 : tail.length===2 && !tail[0]?.startsWith('.');
}

function imageComponentRole(dep={}) {
 if(dep.ecosystem==='system' || dep.ecosystem==='binary')return 'direct';
 const source=dep.installEvidence?.source;
 if(['pypi','composer','composer-php','ruby','nuget'].includes(source))return 'transitive';
 if(dep.provenance==='binary-module')return dep.binaryEvidence?.original?.kind==='mod'?'direct':'transitive';
 const paths=[dep.artifactPath,dep.installEvidence?.path,...(dep.manifestPaths||[])].filter(Boolean);
 if(paths.some(p=>String(p).includes('!/') || parts(p).some(n=>stores.has(n)) || String(p).replace(/\\/g,'/').includes('usr/share/nodejs/')))return 'transitive';
 return 'direct';
}

module.exports={IMAGE_COMPONENT_SCOPE,isNpmPackageDescriptor,isProjectDescriptor,imageComponentRole};
