'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Command, InvalidArgumentError } = require('commander');
const { acquireInventories, assessInventories, writeSnapshot, incompleteCapabilities } = require('./artifacts/scan');

const REPORTS = Object.freeze({
  json: { name: 'findings.json', write: (p, f) => require('./json-export').writeFindings(p, f) },
  html: { name: 'cve-report.html', write: (p, f) => fs.writeFileSync(f, require('./cve-report').generateHtmlReport(p)) },
  doc: { name: 'cve-report.doc', write: (p, f) => fs.writeFileSync(f, require('./cve-report').generateWordReport(p)) },
  sbom: { name: 'sbom.cdx.json', write: (p, f) => require('./sbom-export').writeCycloneDx(p.resolvedDeps, p.cveMatches, f, { projectInfo: p.projectInfo, toolVersion: p.toolVersion }) },
  csaf: { name: 'vex.csaf.json', write: (p, f) => require('./csaf-export').writeCsaf(p.resolvedDeps, p.cveMatches, f, { projectInfo: p.projectInfo, toolVersion: p.toolVersion }) },
  sarif: { name: 'findings.sarif.json', write: (p, f) => require('./sarif-export').writeSarif(p.cveMatches, f, { projectInfo: p.projectInfo, toolVersion: p.toolVersion }) },
  xlsx: { name: 'report.xlsx', write: (p, f) => require('./xlsx-export').writeXlsx(p, f) },
});

function jsonFile(file) {
  if (fs.statSync(file).size > 1024 * 1024) throw Error('configuration file is too large');
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('configuration must be a JSON object');
  return value;
}
function distribution(value) {
  const match = /^([a-z][a-z0-9_-]*):([^\s:]+)$/.exec(value);
  if (!match) throw new InvalidArgumentError('expected distribution-id:release, e.g. debian:12');
  return { id: match[1], versionId: match[2] };
}
// Compare existing files by inode and resolve parent symlinks for new outputs.
function canonicalFile(file) {
  const absolute = path.resolve(file); let current = absolute, suffix = [];
  while (!fs.existsSync(current)) { const parent = path.dirname(current); if (parent === current) break; suffix.unshift(path.basename(current)); current = parent; }
  try { current = fs.realpathSync(current); } catch { /* unresolved path */ }
  return path.join(current, ...suffix);
}
function sameFile(a,b) {
  if (canonicalFile(a) === canonicalFile(b)) return true;
  try { const x=fs.statSync(a),y=fs.statSync(b); return x.dev===y.dev && x.ino===y.ino; } catch { return false; }
}
function reportFiles(opts) {
  if (opts.report === false) return [];
  const explicit=Object.keys(REPORTS).filter(format=>opts['report'+format[0].toUpperCase()+format.slice(1)]!==undefined);
  const selected=opts.reports?opts.reports.split(',').map(s=>s.trim()):explicit.length?explicit:['html','json'];
  const formats=[...new Set([...selected,...explicit])];
  if(formats.some(format=>!REPORTS[format]))throw Error('unknown report format');
  return formats.map(format=>{const specified=opts['report'+format[0].toUpperCase()+format.slice(1)];return {format,file:path.resolve(typeof specified==='string'?specified:path.join(opts.reportOutput,REPORTS[format].name))};});
}
function makeCommand() {
  const command = new Command().name('vigievuln image').description('Native image, rootfs and publisher-inventory audit. No Docker or package-manager execution.')
    .argument('[input]', 'Docker/OCI/rootfs archive, directory, registry reference or inventory')
    .option('--config <file>', 'read scan configuration from a JSON file')
    .option('--source-profile <profile>', 'advisory operator scope: all, us, eu or proxy')
    .option('--proxy <url>', 'corporate forward proxy for outbound connections')
    .option('--proxy-cache <url|vigievuln|default>', 'use a shared advisory proxy')
    .option('--proxy-rate-limit-wait-ms <milliseconds>', 'maximum proxy retry wait per request (default: 45000)', Number)
    .option('--reuse-stable-advisories', 'reuse cached individual advisories unchanged for at least the configured age', true)
    .option('--no-reuse-stable-advisories', 'refresh older individual advisories using normal cache lifetimes')
    .option('--stable-advisory-age-days <days>', 'minimum unchanged advisory age for reuse (default: 365)', Number)
    .option('--force-update', 'revalidate consulted online sources, retaining cached data on failure')
    .option('--proxy-cache-token <token>', 'shared advisory proxy authentication token')
    .option('--vigievuln-proxy [domain]', 'use the hosted VigieVuln proxy, fr or com')
    .option('--allow-insecure-http', 'allow HTTP to the configured advisory proxy for this invocation')
    .option('--registry', 'obtain input directly from an OCI registry; offline uses a prepared cached inventory')
    .option('--platform <os/arch[/variant]>', 'select an image platform; otherwise inspect all available platforms')
    .option('--no-image-retire', 'disable RetireJS inspection of image contents')
    .option('--image-retire', 'scan bundled JavaScript in image contents with RetireJS (excludes package stores)', false)
    .option('--prefer-sbom', 'prefer publisher SBOMs when associated with the selected images; signatures remain unverified')
    .option('--registry-auth <file>', 'JSON credentials {username,password,token,authOrigins}; never invokes credential helpers')
    .option('--insecure', 'allow HTTP registry endpoints explicitly')
    .option('--inventory', 'input is an exported VigieVuln artifact inventory')
    .option('--sbom', 'input is a CycloneDX/SPDX or attestation JSON document')
    .option('--expected-digest <digest>', 'require a supplied SBOM subject to agree with this image digest')
    .option('--advisory-config <file>', 'JSON custom distribution advisory scope and optional source URL')
    .option('--distribution <id:release>', 'explicit distribution scope for imported advisories or SBOM', distribution)
    .option('--offline', 'zero network access; use imported advisory snapshots and cached inventories')
    .option('--enrich <sources>', 'enrichment sources: nvd,kev,epss,gcve,euvd,certfr or none', value => value === 'none' ? [] : value.split(',').map(s => s.trim()), ['nvd', 'kev', 'epss', 'gcve', 'euvd', 'certfr'])
    .option('--no-osv', 'exclude OSV advisory matching')
    .option('--no-distro-advisories', 'exclude independent distribution tracker consultations')
    .option('--no-publisher-advisories', 'exclude publisher advisory feeds')
    .option('--no-nvd', 'exclude NVD enrichment and image product CVE checks')
    .option('--no-kev', 'exclude CISA KEV enrichment')
    .option('--no-epss', 'exclude EPSS enrichment')
    .option('--no-gcve', 'exclude native GCVE advisory matching and derived aliases')
    .option('--no-euvd', 'exclude ENISA EUVD enrichment')
    .option('--no-certfr', 'exclude CERT-FR enrichment')
    .option('--cache-dir <directory>', 'cache directory containing prepared vulnerability data')
    .option('--prepare-cache <file>', 'warm and export advisory cache for an inventory')
    .option('--definitions <directory>', 'find image declarations in source; only explicit matching digests bind to scanned images')
    .option('--export-inventory <file>', 'save portable inventory independently of image contents')
    .option('--import-advisories <file>', 'import a native OSV JSON/JSONL/ZIP dataset for --distribution')
    .option('--snapshot-complete', 'declare imported dataset complete for the stated distribution release')
    .option('--sync-advisories', 'prepare a distribution advisory snapshot online; requires --distribution when no image is supplied')
    .option('--limits <file>', 'JSON resource policy {artifactLimits,registryLimits,maxMetadataBytes,...}')
    .option('--report-output <directory>', 'report directory', './vigievuln-report')
    .option('-r, --reports <formats>', 'comma-separated report formats: ' + Object.keys(REPORTS).join(','))
    .option('--no-report', 'write no reports; inventory export and CI gates remain active')
    .option('--fail-on <severity>', 'fail with exit 1 for matching findings: low,medium,high,critical,kev', 'none')
    .option('--fail-on-incomplete [capabilities]', 'exit 2 for incomplete inventory/advisories/sources', false)
    .option('--lang <language>', 'report language: en or fr', 'en');
  for (const format of Object.keys(REPORTS)) command.option(`--report-${format} [file]`, `write ${format} report`);
  return command;
}

async function run(args, injected = {}) {
  const command = makeCommand();
  command.parse(args, { from: 'user' });
  const setup = require('./image-network').configureImageNetwork(command, injected);
  try {
  const opts = setup.options, input = command.args[0];
  for (const warning of setup.warnings) console.warn(`⚠ ${warning}`);
  if (![opts.registry, opts.inventory, opts.sbom].filter(Boolean).length) opts.mode = 'artifact';
  if ([opts.registry, opts.inventory, opts.sbom].filter(Boolean).length > 1) throw Error('--registry, --inventory and --sbom are mutually exclusive');
  if (opts.preferSbom && !opts.registry) throw Error('--prefer-sbom requires --registry');
  if (opts.prepareCache && (!opts.inventory || opts.offline)) throw Error('--prepare-cache requires an inventory and online mode');
  if (!['en', 'fr'].includes(opts.lang)) throw Error('--lang must be en or fr');
  if (!['none', 'low', 'medium', 'high', 'critical', 'kev'].includes(opts.failOn)) throw Error('invalid --fail-on severity');
  const required = opts.failOnIncomplete ? (opts.failOnIncomplete === true ? 'inventory,advisories,sources' : opts.failOnIncomplete).split(',').map(x => x.trim()) : [];
  if (required.some(x => !['inventory', 'advisories', 'sources'].includes(x))) throw Error('invalid --fail-on-incomplete capability');
  const cacheDir = opts.cacheDir;
  const policy = opts.limits ? jsonFile(opts.limits) : {};
  const credentials = opts.registryAuth ? jsonFile(opts.registryAuth) : {
    token: process.env.VIGIEVULN_REGISTRY_TOKEN, username: process.env.VIGIEVULN_REGISTRY_USER, password: process.env.VIGIEVULN_REGISTRY_PASSWORD,
  };
  const options = { ...policy, ...opts, cacheDir, credentials, authOrigins: credentials.authOrigins || [],
    ...(opts.advisoryConfig ? { advisoryConfig: typeof opts.advisoryConfig === 'string' ? jsonFile(opts.advisoryConfig) : opts.advisoryConfig } : {}) };
  if (opts.osv === false && (opts.importAdvisories || opts.syncAdvisories)) throw Error('OSV advisories are excluded by the selected source profile');
  if (opts.importAdvisories) {
    if (!opts.distribution) throw Error('--import-advisories requires --distribution');
    const imported = await require('./system-inventory').importSystemAdvisories(opts.importAdvisories, { ...options, complete: !!opts.snapshotComplete });
    console.log(`Imported ${imported.recordCount} advisory records for ${imported.ecosystem}.`);
  }
  if (!input) {
    if (opts.syncAdvisories) {
      if (!opts.distribution) throw Error('--sync-advisories requires --distribution when no image is supplied');
      const synced = await require('./system-inventory').syncSystemAdvisories(opts.distribution, options);
      console.log(`Prepared ${synced.recordCount} advisory records for ${synced.ecosystem}.`);
      return { synced };
    }
    if (opts.importAdvisories) return {};
    throw Error('an image/archive/rootfs/inventory input is required; see vigievuln image --help');
  }
  const reports = reportFiles(opts);
  const outputs = [...(opts.exportInventory ? [{label:'inventory',file:path.resolve(opts.exportInventory)}] : []), ...(opts.prepareCache ? [{label:'cache',file:path.resolve(opts.prepareCache)}] : []), ...reports.map(r => ({label:r.format,file:r.file}))];
  if (reports.length) outputs.push({label:'checksums',file:path.join(path.dirname(reports[0].file),'SHA256SUMS')});
  for (let i=0;i<outputs.length;i++) {
    if (fs.existsSync(input) && sameFile(input,outputs[i].file)) throw Error(`${outputs[i].label} output must not overwrite the input artifact`);
    for(let j=0;j<i;j++) if(sameFile(outputs[i].file,outputs[j].file)) throw Error('output paths must be distinct');
  }
  const targets = await acquireInventories(input, options);
  const savedReferences = new Map();
  for (const target of targets) for (const ref of target.metadata?.declarations || []) if (ref?.id && !savedReferences.has(ref.id)) savedReferences.set(ref.id, ref);
  let imageReferences = [...savedReferences.values()];
  if (opts.definitions) {
    const discovery = require('./image-references').discoverImageReferences(path.resolve(opts.definitions));
    imageReferences = require('./image-references').bindImageDefinitions(targets, discovery.references);
    for (const target of targets) target.metadata.definitionDiscovery = { status: discovery.warnings.length ? 'incomplete' : target.metadata.definitions.length ? 'matched' : 'no-match', source: path.basename(path.resolve(opts.definitions)) };
    if (discovery.warnings.length) for (const target of targets) target.warnings.push(...discovery.warnings.map(w => ({ ...w, capability: 'inventory' })));
  }
  if (opts.exportInventory) await writeSnapshot(opts.exportInventory, targets);
  const result = await assessInventories(targets, options);
  result.warnings.push(...require('./image-references').unpinnedImageWarnings([
    ...imageReferences,...(options.registry?[{reference:input}]:[]),
  ]));
  if (opts.prepareCache) {
    const gaps = incompleteCapabilities(result, ['advisories', 'sources']);
    if (gaps.length) console.warn('⚠ Prepared cache has incomplete advisory or source coverage; review the scan notices.');
    const prepared = await require('./cache-archive-sqlite').exportCache(opts.prepareCache, { sourceDir: cacheDir,
      proxyOrigin: options.proxyCache ? require('./proxy-scope').proxyOrigin(options.proxyCache) : undefined });
    console.log(`Prepared cache: ${prepared.path}`);
  }
  const toolVersion = require('../package.json').version;
  const payload = { ...result, toolVersion, locale: opts.lang,
    projectInfo: { name: path.basename(input), src: '(artifact inventory)', toolVersion, generatedAt: new Date().toISOString(),
      artifacts: result.artifacts, ...(imageReferences.length ? { imageReferences } : {}), provenance: { mode: opts.offline ? 'offline' : 'online',notices:[...(setup.notices||[]),...(result.notices||[])],
        dataSources: result.artifacts.flatMap(a => a.coverage.filter(c => c.capability === 'advisories' || c.capability === 'sources').map(c => ({
          label: c.ecosystem || c.source || c.collector, status: c.execution === 'not-applicable' ? 'disabled' : c.execution === 'completed' ? 'cached' : 'missing',
          asOf: c.fetchedAt ? new Date(c.fetchedAt).toISOString() : null, detail: c.reason || c.execution }))) } } };
  let written = [];
  if (opts.report !== false) {
    for (const { format, file } of reports) {
      await fs.promises.mkdir(path.dirname(file), { recursive: true });
      await REPORTS[format].write(payload, file);
      written.push(file);
    }
    if (written.length) {
      const checksum = path.join(path.dirname(written[0]), 'SHA256SUMS');
      require('./report-integrity').writeChecksums(written, checksum, { baseDir: path.dirname(checksum) });
    }
  }
  const gate = require('./gate').evaluateGate(result.cveMatches, opts.failOn);
  const gaps = incompleteCapabilities(result, required);
  if (opts.failOn === 'kev') {
    gaps.push(...incompleteCapabilities(result, ['advisories']));
    for (const artifact of result.artifacts) {
      const hasCve = result.cveMatches.some(m => m.dep.artifactTargetId === artifact.id);
      const kev = artifact.coverage.find(c => c.capability === 'sources' && c.collector === 'kev');
      if (hasCve && (!kev || kev.execution !== 'completed')) gaps.push({ target: artifact.id, capability: 'kev' });
    }
  }
  const malicious = result.cveMatches.some(m => m.malicious && !m.suppressed);
  const exitCode = gaps.length ? 2 : gate.failed || malicious ? 1 : 0;
  process.exitCode = exitCode;
  console.log(`${result.artifacts.length} artifact(s), ${result.resolvedDeps.size} components, ${result.cveMatches.length} findings, ${result.warnings.length} warning(s).`);
  for (const warning of result.warnings) console.warn(`⚠ ${warning.message}`);
  for (const file of written) console.log(file);
  if (gaps.length) console.warn(`Required coverage incomplete: ${[...new Set(gaps.map(g => g.capability))].join(', ')}.`);
  return { ...result, written, exitCode };
  } finally { setup.restore(); }
}

module.exports = { run, makeCommand, REPORTS };
