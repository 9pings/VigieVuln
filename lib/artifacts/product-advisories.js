'use strict';

const { imageProduct } = require('./product-catalog');
const { getApplicationPlugin } = require('../applications/plugins');
const { makeDepRecord } = require('../inventory/dep-record');
const { createCacheRepository } = require('../cache/repository');
const { extractFromNvdRecord } = require('../providers/nvd/enrich');
const { getResource } = require('../providers');
const { validateResourceJson, DEFAULT_MAX_BODY_BYTES } = require('../cache/resource/engine');
const { fresh } = require('../cache/policy');

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

// Product/version applicability is independent of deployment prerequisites.
// Platform and build-environment restrictions remain in the source advisory.
function evaluateConfiguration(node, product, version) {
  return require('../providers/nvd/cpe').evaluateProductConfiguration(node,
    leaf => String(leaf.criteria).split(':').slice(0,5).join(':') === 'cpe:2.3:a:' + product,
    leaf => {
      const fields=String(leaf.criteria).split(':'),pin=fields[5];
      // CPE update identifies the release itself (for example alpha1).
      if(fields.length!==13 || !['*','-'].includes(fields[6]) ||
         (pin!=='*' && !VERSION.test(pin)) || bounds.some(k=>leaf[k]!=null && !VERSION.test(leaf[k])))return null;
      return (pin==='*' || compare(version,pin)===0) &&
        (!leaf.versionStartIncluding || compare(version,leaf.versionStartIncluding)>=0) &&
        (!leaf.versionStartExcluding || compare(version,leaf.versionStartExcluding)>0) &&
        (!leaf.versionEndIncluding || compare(version,leaf.versionEndIncluding)<=0) &&
        (!leaf.versionEndExcluding || compare(version,leaf.versionEndExcluding)<0);
    });
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
        affectsCompleteness:false,
        product: product.id,
        version: dep.version,
        execution: 'not-applicable',
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
  const applications = target.metadata?.systemApplications;
  for (const app of applications?.applications || []) {
    const plugin = getApplicationPlugin(app.pluginId);
    if (!plugin?.upstreamCpe || app.type !== plugin.id) continue;
    const core = applications.inventory.find(c => c.applicationId === app.id && c.kind === 'core');
    const file = core?.evidence?.[0]?.path;
    if (!file || !VERSION.test(core.version)) continue;
    const dep = makeDepRecord({
      ecosystem: 'application', name: plugin.id, version: core.version, manifestPath: file,
      scope: 'prod', provenance: 'application'
    });
    Object.assign(dep, {
      coordKey: JSON.stringify([target.id, app.id, 'core']), artifactTargetId: target.id, artifactPath: file,
      systemSection: 'project', systemApplicationIds: [app.id], applicationEvidence: core.evidence
    });
    const key = JSON.stringify([plugin.id, core.version, plugin.upstreamCpe]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(dep);
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
      const ns = 'image-product-nvd/2',
        cacheKey = JSON.stringify([cpe, version]);
      let saved = repo.get(ns, cacheKey),
        error;
      if (!options.offline && (!saved || saved.stale || !fresh(saved.fetchedAt) || options.forceUpdate)) {
        try {
          const params = { product: id, version, cpe };
          const apiKey = !require('../providers').hasProxyRoute() && require('../config').getNvdApiKey();
          const response = await getResource('nvd', 'image-product', params, {
            ...(apiKey ? {headers:{apiKey}} : {}),
            fetcher: options.fetcher,
            requestTimeoutMs: 30000,
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
      const stale = saved.stale || (!options.offline && !fresh(saved.fetchedAt) && !options.forceUpdate);
      for (const dep of items)
        for (const record of records)
          matches.push({
            dep,
            source: 'nvd',
            confidence: 'probable',
            cve: {
              ...record,
              nvdRecordEvidence: { status: 'available', fetchedAt: saved.fetchedAt, stale: !!stale },
              fixVersion: null,
              identityEvidence: dep.binaryEvidence || dep.applicationEvidence,
              advisorySource: 'https://nvd.nist.gov/vuln/detail/' + record.id
            }
          });
      Object.assign(check, {
        execution: error || stale ? 'partial' : 'completed',
        result: records.length ? 'affected' : error || stale || unknown.length ? 'indeterminate' : 'no-match',
        fetchedAt: saved.fetchedAt,
        count: records.length,
        unknown: unknown.length,
        ...(unknown.length ? { undecidableIds: unknown, affectsAssessment: true } : {}),
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
