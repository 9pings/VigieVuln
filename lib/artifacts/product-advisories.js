'use strict';

const { imageProduct } = require('./product-catalog');
const { createCacheRepository } = require('../cache-repository');
const { extractFromNvdRecord } = require('../nvd');
const { getResource } = require('../providers');
const { validateResourceJson, DEFAULT_MAX_BODY_BYTES } = require('../resource-cache/engine');
const { fresh } = require('../cache-policy');

const VERSION = /^\d{1,8}(?:\.\d{1,8}){1,3}$/;
const bounds = ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'];
function compare(a, b) {
  const x = a.split('.').map(Number),
    y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

// Only an independently sufficient configuration can confirm the finding. An
// AND with hardware/OS constraints or an unmodelled version remains unknown.
function evaluateConfiguration(node, product, version) {
  if (!node || node.negate || !['OR', 'AND', undefined].includes(node.operator)) return null;
  const values = [];
  for (const leaf of node.cpeMatch || []) {
    const fields = String(leaf.criteria).split(':');
    if (
      fields.length !== 13 ||
      fields.slice(0, 5).join(':') !== 'cpe:2.3:a:' + product ||
      leaf.vulnerable !== true
    ) {
      values.push(null);
      continue;
    }
    const pin = fields[5];
    if (
      !fields.slice(6).every((value) => value === '*' || value === '-') ||
      (pin !== '*' && !VERSION.test(pin)) ||
      bounds.some((k) => leaf[k] != null && !VERSION.test(leaf[k]))
    ) {
      values.push(null);
      continue;
    }
    values.push(
      (pin === '*' || compare(version, pin) === 0) &&
        (!leaf.versionStartIncluding || compare(version, leaf.versionStartIncluding) >= 0) &&
        (!leaf.versionStartExcluding || compare(version, leaf.versionStartExcluding) > 0) &&
        (!leaf.versionEndIncluding || compare(version, leaf.versionEndIncluding) <= 0) &&
        (!leaf.versionEndExcluding || compare(version, leaf.versionEndExcluding) < 0)
    );
  }
  for (const child of [...(node.nodes || []), ...(node.children || [])])
    values.push(evaluateConfiguration(child, product, version));
  if (!values.length) return null;
  if (node.operator === 'AND') return values.includes(false) ? false : values.includes(null) ? null : true;
  return values.includes(true) ? true : values.includes(null) ? null : false;
}

async function assessProductAdvisories(target, options) {
  const matches = [],
    coverage = [],
    groups = new Map();
  for (const dep of target.deps) {
    const product = imageProduct(dep);
    if (
      !product ||
      !dep.binaryEvidence?.product ||
      dep.binaryEvidence.product !== product.id ||
      dep.osPackageOwners?.length
    )
      continue;
    // Slimmed distro images may discard dpkg .list files. When the matching
    // system package exists, never apply upstream rules to a system-prefix binary.
    if (
      /^(?:usr\/)?(?:s?bin|lib(?:32|64)?)\//.test(dep.artifactPath || '') &&
      target.packages.some((pkg) => product.pkg.test(pkg.name))
    )
      continue;
    if (!product.cpe || !VERSION.test(dep.version)) {
      coverage.push({
        collector: 'image-product-applicability',
        product: product.id,
        version: dep.version,
        execution: 'partial',
        result: 'indeterminate',
        reason: dep.version
          ? 'No supported upstream CPE/version comparison.'
          : 'No exact runtime version was identified.'
      });
      continue;
    }
    for (const cpe of [product.cpe, ...(product.cpeAliases || [])]) {
      const key = JSON.stringify([product.id, dep.version, cpe]);
      const items = groups.get(key) || [];
      items.push(dep);
      groups.set(key, items);
    }
  }
  for (const [key, items] of groups) {
    const [id, version, cpe] = JSON.parse(key);
    const check = {
      collector: 'nvd-image-product',
      product: id,
      version,
      cpe,
      scope: 'upstream-cpe-version',
      count: 0
    };
    coverage.push(check);
    if (options.nvd === false || options.sourceProfile === 'eu') {
      Object.assign(check, {
        execution: 'not-applicable',
        result: 'not-consulted',
        expected: false,
        reason: 'NVD excluded by configuration.'
      });
      continue;
    }
    try {
      const repo = createCacheRepository(options.cacheDir);
      const ns = 'image-product-nvd/1',
        cacheKey = JSON.stringify([cpe, version]);
      let saved = repo.get(ns, cacheKey),
        error;
      if (!options.offline && (!saved || saved.stale || !fresh(saved.fetchedAt) || options.forceUpdate)) {
        try {
          const params = { product: id, version, cpe };
          const response = await getResource('nvd', 'image-product', params, {
            fetcher: options.fetcher,
            signal: AbortSignal.timeout(30000),
            forceRefresh: options.forceUpdate
          });
          if (!response.ok) throw Error('NVD HTTP ' + response.status);
          const chunks = [];
          let bytes = 0;
          for await (const part of response.body) {
            bytes += part.length;
            if (bytes > DEFAULT_MAX_BODY_BYTES) throw Error('NVD product response exceeds the metadata budget');
            chunks.push(Buffer.from(part));
          }
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          validateResourceJson({ provider: 'nvd', type: 'image-product', params }, body);
          if (body.totalResults !== body.vulnerabilities.length || body.startIndex !== 0)
            throw Error('Incomplete NVD product response');
          const records = [],
            unknown = [];
          for (const { cve } of body.vulnerabilities) {
            if (cve.vulnStatus === 'Rejected') continue;
            const verdict = evaluateConfiguration({ nodes: cve.configurations }, cpe, version);
            if (verdict === true) records.push(extractFromNvdRecord(cve));
            if (verdict === null) unknown.push(cve.id);
          }
          const stamp = response.headers.get('x-fad-proxy-fetched-at');
          const fetchedAt = stamp ? Date.parse(stamp) : Date.now();
          if (
            (require('../providers').hasProxyRoute() && !stamp) ||
            !Number.isFinite(fetchedAt) ||
            fetchedAt <= 0 ||
            fetchedAt > Date.now() + 300000
          )
            throw Error('Invalid NVD observation timestamp');
          const stale = response.headers.get('x-fad-proxy') === 'stale';
          repo.put(ns, cacheKey, { records, unknown }, { fetchedAt, stale });
          saved = { value: { records, unknown }, fetchedAt, stale };
        } catch (e) {
          error = e.message;
        }
      }
      if (!saved) throw Error(error || 'No cached NVD consultation for this product/version.');
      const { records, unknown } = saved.value;
      const stale = saved.stale || (!fresh(saved.fetchedAt) && !options.forceUpdate);
      for (const dep of items)
        for (const record of records)
          matches.push({
            dep,
            source: 'nvd',
            confidence: 'probable',
            cve: {
              ...record,
              fixVersion: null,
              identityEvidence: dep.binaryEvidence,
              advisorySource: 'https://nvd.nist.gov/vuln/detail/' + record.id
            }
          });
      Object.assign(check, {
        execution: error || stale || unknown.length ? 'partial' : 'completed',
        result: records.length ? 'affected' : error || stale || unknown.length ? 'indeterminate' : 'no-match',
        fetchedAt: saved.fetchedAt,
        count: records.length,
        unknown: unknown.length,
        reason:
          error ||
          (stale
            ? 'Saved NVD consultation is stale.'
            : unknown.length
              ? 'Some CPE configuration conditions could not be established.'
              : undefined)
      });
    } catch (e) {
      Object.assign(check, { execution: 'not-run', result: 'indeterminate', reason: e.message });
    }
  }
  return { matches, coverage };
}
module.exports = { assessProductAdvisories, evaluateConfiguration, VERSION };
