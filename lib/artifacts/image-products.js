'use strict';

const { makeDepRecord } = require('../dep-record');
const { catalog, binaryProduct, imageProduct } = require('./product-catalog');

function describe(dep) {
  const product = imageProduct(dep);
  return product ? { id: product.id, label: product.label, category: product.category } : null;
}

function applyProductVersions(deps) {
  const binaries = deps.filter((d) => d.ecosystem === 'binary');
  const libraries = new Map(),
    additions = [],
    linkedFiles = new Set();
  for (const dep of binaries) {
    const meta = dep.binaryMetadata,
      name = meta?.soname || dep.name;
    if (!name.startsWith('lib')) continue;
    const list = libraries.get(name) || [];
    list.push(dep);
    libraries.set(name, list);
  }
  for (const dep of binaries) {
    const meta = dep.binaryMetadata;
    if (!['elf', 'pe'].includes(meta?.format) || meta.status === 'unavailable') continue;
    const product = binaryProduct(dep.name);
    const evidence = (meta.products || []).map((item) => ({ item, provider: dep }));
    if (product && !evidence.some(({ item }) => item.id === product.id)) {
      const candidates = (meta.needed || [])
        .flatMap((name) => libraries.get(name) || [])
        .filter((lib) => lib.binaryMetadata?.machine === meta.machine && lib.binaryMetadata.bits === meta.bits);
      for (const provider of candidates) {
        const item = provider.binaryMetadata.products?.find((item) => item.id === product.id);
        const soname = provider.binaryMetadata.soname || provider.name;
        if (
          item &&
          candidates.filter((lib) => (lib.binaryMetadata?.soname || lib.name) === soname).length === 1
        )
          evidence.push({ item, provider });
      }
    }
    for (const { item, provider } of evidence) {
      if (provider !== dep) linkedFiles.add(JSON.stringify([provider.artifactPath, item.id]));
      if (
        evidence.filter((e) => e.item.id === item.id && e.item.resourceOffset === item.resourceOffset)
          .length !== 1
      )
        continue;
      const proof = {
        product: item.id,
        source: item.source,
        binaryPath: dep.artifactPath,
        versionPath: item.path || provider.artifactPath,
        ...(item.resourceOffset !== undefined
          ? { resourceId: item.resourceId, resourceOffset: item.resourceOffset }
          : {})
      };
      if (item.resourceOffset !== undefined || item.id !== product?.id) {
        const embedded = makeDepRecord({
          ecosystem: 'image-product',
          name: item.id,
          version: item.version,
          manifestPath: dep.artifactPath,
          scope: 'runtime',
          provenance: 'embedded-runtime'
        });
        additions.push({
          ...embedded,
          artifactPath: dep.artifactPath,
          artifactTargetId: dep.artifactTargetId,
          coordKey:
            dep.coordKey +
            ':embedded:' +
            item.id +
            (item.resourceOffset !== undefined ? ':' + item.resourceOffset : ''),
          binaryEvidence: proof,
          osPackageOwners: dep.osPackageOwners
        });
      } else {
        dep.version = item.version;
        dep.versions = item.version ? [item.version] : [];
        dep.versionPaths = item.version ? { [item.version]: [dep.artifactPath] } : {};
        dep.binaryEvidence = proof;
        if (provider.osPackageOwners?.length) dep.osPackageOwners = provider.osPackageOwners;
      }
    }
  }
  deps.push(...additions.filter((d) => !linkedFiles.has(JSON.stringify([d.artifactPath, d.name]))));
}

function productCoverage(target, checks, assessedPackages, matches) {
  const affected = new Set(
    matches.filter((m) => m.dep?.artifactTargetId === target.id).map((m) => m.dep.coordKey)
  );
  const affectedPackages = new Set(
    matches
      .filter((m) => m.dep?.artifactTargetId === target.id && m.dep.ecosystem === 'system')
      .map((m) => m.dep.manager + ':' + m.dep.name + '@' + m.dep.version)
  );
  const entries = [],
    links = [];
  const libraryProduct = require('./elf-product').libraryProduct;
  const present = new Set(
    target.deps
      .filter((d) => d.ecosystem === 'binary')
      .flatMap((d) => [d.name, d.binaryMetadata?.soname].filter(Boolean))
  );
  for (const dep of target.deps) {
    for (const name of dep.binaryMetadata?.needed || []) {
      const linked = libraryProduct(name) || binaryProduct(name);
      if (linked)
        links.push({
          id: linked.id,
          product: linked.label,
          requiredBy: dep.artifactPath,
          library: name,
          fileObserved: present.has(name)
        });
    }
    const product = describe(dep);
    if (!product) continue;
    const system = dep.ecosystem === 'system' || !!dep.osPackageOwners?.length;
    const relevant = system ? [] : checks.filter((c) => c.product === product.id && c.version === dep.version);
    const owners = dep.ecosystem === 'system' ? [dep] : dep.osPackageOwners || [];
    const keys = owners.map((o) => o.manager + ':' + o.name + '@' + o.version);
    const version = dep.version || (owners.length === 1 ? owners[0].version : null);
    let advisoryCheck = 'indeterminate',
      reason = relevant.find((c) => c.reason)?.reason;
    if (affected.has(dep.coordKey) || keys.some((k) => affectedPackages.has(k))) advisoryCheck = 'affected';
    else if (system) {
      advisoryCheck =
        keys.length && keys.every((k) => assessedPackages.has(k))
          ? 'distribution-no-match'
          : 'distribution-incomplete';
    } else if (relevant.length && relevant.every((c) => c.execution === 'completed'))
      advisoryCheck = 'no-match';
    else if (relevant.length && relevant.every((c) => c.execution === 'not-applicable'))
      advisoryCheck = 'disabled';
    else if (dep.ecosystem === 'go') advisoryCheck = 'go-module';
    else if (!version) reason = 'version-unknown';
    else if (!relevant.length) reason = 'no-upstream-check';
    entries.push({
      ...product,
      name: dep.name,
      path: dep.artifactPath,
      version,
      versionSource: dep.binaryEvidence?.source || (system ? 'system-package' : null),
      evidencePath: dep.binaryEvidence?.versionPath || dep.artifactPath,
      resourceOffset: dep.binaryEvidence?.resourceOffset,
      advisoryCheck,
      reason
    });
  }
  const recognizedPaths = new Set(entries.filter((e) => e.version).map((e) => e.evidencePath));
  const unidentified = target.deps
    .filter(
      (d) =>
        d.ecosystem === 'binary' &&
        !d.osPackageOwners?.length &&
        !describe(d) &&
        !recognizedPaths.has(d.artifactPath) &&
        !d.binaryMetadata?.go?.modules?.some((m) => m.kind === 'mod' && m.version && m.version !== '(devel)')
    )
    .map((d) => ({ path: d.artifactPath, format: d.binaryMetadata?.format || 'unknown' }));
  const seen = new Set([...entries, ...links].map((e) => e.id));
  return {
    entries,
    links,
    unidentified,
    scope:
      target.kind === 'sbom'
        ? 'publisher-sbom'
        : target.metadata?.componentScope === require('./component-scope').IMAGE_COMPONENT_SCOPE
          ? 'image-files'
          : 'older-inventory',
    unobserved: [...catalog.values()].filter((p) => !seen.has(p.id)).map((p) => p.label)
  };
}
module.exports = { describe, applyProductVersions, productCoverage };
