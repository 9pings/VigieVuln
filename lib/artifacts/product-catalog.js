'use strict';

// Program names identify candidates for presentation. Only product-specific version
// evidence can authorize upstream matching. Package aliases refer to installed
// binary packages, never arbitrary npm, PyPI or Composer project names.
const fingerprints = require('../../data/fingerprints');
const catalog = new Map();
for (const rule of fingerprints) {
  if (
    rule.schemaVersion !== 1 ||
    !/^[a-z][a-z0-9-]*$/.test(rule.id) ||
    catalog.has(rule.id) ||
    !['interpreter', 'service'].includes(rule.category)
  )
    throw Error('Invalid image fingerprint ' + rule.id);
  catalog.set(rule.id, {
    ...rule,
    executable: new RegExp(rule.executable),
    pkg: new RegExp(rule.osPackage),
    library: rule.elfLibrary ? new RegExp(rule.elfLibrary) : null,
    banner: rule.elfBanner ? new RegExp(rule.elfBanner, 'g') : null
  });
}

function binaryProduct(name) {
  if (typeof name !== 'string') return null;
  if (/\.exe$/i.test(name)) name = name.slice(0, -4).toLowerCase();
  for (const product of catalog.values())
    if (product.executable.test(name) && name !== 'master') return product;
  return null;
}

const goServices = new Map(
  [...catalog.values()].filter((p) => p.goMainModule).map((p) => [p.goMainModule, p.id])
);
function imageProduct(dep) {
  if (dep.ecosystem === 'image-product') return catalog.get(dep.name);
  if (dep.ecosystem === 'system') {
    for (const product of catalog.values()) if (product.pkg.test(dep.name)) return product;
  }
  if (dep.ecosystem === 'binary') {
    const proof = catalog.get(dep.binaryEvidence?.product);
    if (proof) return proof;
    for (const owner of dep.osPackageOwners || []) {
      for (const product of catalog.values())
        if (
          product.pkg.test(owner.name) &&
          (product.executable.test(dep.name) || ['smtpd', 'master'].includes(dep.name))
        )
          return product;
    }
    return binaryProduct(dep.name);
  }
  if (
    dep.ecosystem === 'go' &&
    (dep.binaryEvidence?.original?.kind === 'mod' || dep.binaryEvidence?.source === 'go-vcs-and-module-proxy')
  ) {
    return catalog.get(goServices.get(String(dep.name).replace(/\/v\d+$/, '')));
  }
  return null;
}
// Application plugin identities are independent of executable/package-name heuristics.
const upstreamProducts = new Map(catalog);
for (const plugin of require('../application-plugins').allApplicationPlugins()) {
  if (plugin.upstreamCpe) upstreamProducts.set(plugin.id,{id:plugin.id,cpe:plugin.upstreamCpe});
}
module.exports = { upstreamProducts, catalog, binaryProduct, imageProduct };
