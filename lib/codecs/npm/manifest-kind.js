'use strict';

// Legacy clib descriptors also use package.json. Their repo/src/development
// fields describe C sources and GitHub coordinates, not npm packages.
function isClibManifest(value) {
 if (!value || typeof value !== 'object' || Array.isArray(value) ||
     typeof value.repo !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value.repo) ||
     !Array.isArray(value.src) || !value.src.length ||
     !value.src.every(p=>typeof p==='string' && /\.(?:c|h|cc|cpp|hpp)$/i.test(p))) return false;
 if (['main','exports','bin','scripts','types','typings','workspaces','devDependencies','peerDependencies','optionalDependencies','packageManager'].some(k=>Object.hasOwn(value,k)) || value.engines?.node) return false;
 const declarations = [value.dependencies, value.development].filter(v=>v!==undefined);
 return declarations.every(v=>v && typeof v==='object' && !Array.isArray(v) &&
   Object.keys(v).every(name=>/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(name)));
}

module.exports={isClibManifest};
