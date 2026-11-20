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
 if(imageComponentSource(dep).category==='global')return 'direct';
 if(dep.ecosystem==='system' || dep.ecosystem==='binary')return 'direct';
 const source=dep.installEvidence?.source;
 if(['pypi','composer','composer-php','ruby','nuget','retire'].includes(source))return 'transitive';
 if(dep.provenance==='binary-module')return dep.binaryEvidence?.original?.kind==='mod'?'direct':'transitive';
 const paths=[dep.artifactPath,dep.installEvidence?.path,...(dep.manifestPaths||[])].filter(Boolean);
 if(paths.some(p=>String(p).includes('!/') || parts(p).some(n=>stores.has(n)) || String(p).replace(/\\/g,'/').includes('usr/share/nodejs/')))return 'transitive';
 return 'direct';
}

// Paths here are relative to the image, never the temporary extraction directory.
// A package store is not evidence of a global install unless its prefix is known.
function imageComponentSource(dep={}) {
 const p=String(dep.artifactPath || dep.installEvidence?.path || dep.manifestPaths?.[0] || '').replace(/\\/g,'/').replace(/^\/+/, '');
 const source=dep.installEvidence?.source;
 const os=dep.ecosystem==='system' ? dep : dep.osPackageOwners?.[0];
 if(os)return {category:'system',manager:os.manager || os.packageType || 'system'};
 if(source==='retire' || dep.ecosystemType==='retire')return {category:'vendored',manager:'retirejs'};
 const npm=/^((?:(?:usr(?:\/local)?|opt\/[^/]+)\/lib|(?:root|home\/[^/]+)\/(?:\.npm-global\/lib|\.nvm\/versions\/node\/[^/]+\/lib))\/node_modules)\/(?:@[^/]+\/)?[^/]+\/package\.json$/.exec(p);
 if(dep.ecosystem==='npm' && npm)return {category:'global',manager:'npm',root:npm[1]};
 const python=/^((?:usr(?:\/local)?\/lib(?:64)?\/python[^/]+|(?:root|home\/[^/]+)\/\.local\/lib\/python[^/]+)\/(?:site|dist)-packages)\//.exec(p);
 if(dep.ecosystem==='pypi' && python)return {category:'global',manager:'python',root:python[1]};
 const ruby=/^((?:usr(?:\/local)?\/(?:lib\/ruby\/gems|share\/gems)|var\/lib\/gems|(?:root|home\/[^/]+)\/\.gem\/ruby)(?:\/[^/]+)?)\/specifications\//.exec(p);
 if(dep.ecosystem==='ruby' && ruby)return {category:'global',manager:'ruby',root:ruby[1]};
 const composer=/^((?:root|home\/[^/]+)\/(?:\.composer|\.config\/composer))\/vendor\/composer\/installed\.(?:json|php)$/.exec(p);
 if(dep.ecosystem==='composer' && composer)return {category:'global',manager:'composer',root:composer[1]};
 if(p && !p.includes('!/') && isProjectDescriptor(p) && !p.startsWith('usr/share/nodejs/') &&
   (['composer-project','pypi-project','maven-project'].includes(source) || dep.ecosystem==='npm' && /(?:^|\/)package\.json$/.test(p)))
  return {category:'project',manager:dep.ecosystem,root:p.includes('/')?p.slice(0,p.lastIndexOf('/')):'.'};
 return {category:'other',manager:dep.ecosystem || 'unknown'};
}

module.exports={IMAGE_COMPONENT_SCOPE,isNpmPackageDescriptor,isProjectDescriptor,imageComponentRole,imageComponentSource};
