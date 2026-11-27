'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const yaml = require('js-yaml');
const { makeDirFilter } = require('./path-filter');

function resolveVariables(value, variables) {
  const unresolved = new Set();
  const resolved = String(value).replace(/\$\$|\$\{([A-Za-z_][\w]*)(?:(:-|-)([^}]*))?\}|\$([A-Za-z_][\w]*)/g,
    (whole, brace, operator, fallback, bare) => {
      if (whole === '$$') return '$';
      const name = brace || bare, present = Object.hasOwn(variables, name), current = variables[name];
      if (present && !(operator === ':-' && current === '')) return String(current);
      if (operator) return fallback;
      unresolved.add(name); return whole;
    });
  return { reference: resolved, unresolved: [...unresolved] };
}

function classifyImageReference(item) {
  if (item.localBuild) return {...item, classification:'local-build',scanEligible:false,blockReason:'local-build'};
  if (item.unresolved?.length || /\$[{A-Za-z_]/.test(item.reference || '')) return {...item,classification:'unresolved',scanEligible:false,blockReason:'unresolved-variables'};
  if (item.platformInvalid || (item.platform != null && !/^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)?$/.test(item.platform))) return {...item,classification:'non-scannable',scanEligible:false,blockReason:'invalid-platform'};
  if (!item.reference || item.reason) return {...item,classification:'non-scannable',scanEligible:false,blockReason:item.reason||'missing-reference'};
  try { require('./image-registry').parseReference(item.reference); return {...item,classification:'registry',scanEligible:true,blockReason:null}; }
  catch { return {...item,classification:'non-scannable',scanEligible:false,blockReason:'invalid-reference'}; }
}

function scalarVariables(value) {
  const out={};if(!value || typeof value!=='object' || Array.isArray(value))return out;
  for(const [name,raw] of Object.entries(value)){const v=raw && typeof raw==='object' && !Array.isArray(raw)?raw.value:raw;if(typeof v==='string'||typeof v==='number'||typeof v==='boolean')out[name]=String(v);}
  return out;
}
function resolveExpanded(value, variables) {
  let reference=String(value);for(let i=0;i<16;i++){const next=resolveVariables(reference,variables);if(next.reference===reference)return next;reference=next.reference;}
  const result=resolveVariables(reference,variables);if(result.reference!==reference)return {reference,unresolved:['recursive-variable']};return result;
}

function dockerfileReferences(text, context = {}) {
  const out = [], variables = { ...(context.variables || {}) }, stages = new Set();
  let stage = -1, pending = '', start = 0, escaped = '\\', heredocs = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (heredocs.length) {
      const current = heredocs[0], candidate = current.stripTabs ? line.replace(/^\t+/, '') : line;
      if (candidate === current.delimiter) heredocs.shift();
      continue;
    }
    const directive = /^\s*#\s*escape\s*=\s*([`\\])\s*$/i.exec(line);
    if (directive && stage < 0 && !pending) { escaped = directive[1]; continue; }
    if (/^\s*#/.test(line)) continue;
    if (!pending) start = i + 1;
    const trimmed = line.trimEnd(), continued = trimmed.endsWith(escaped);
    pending += (continued ? trimmed.slice(0, -1) : line) + ' ';
    if (continued) continue;
    const instruction = /^\s*(\w+)\s+([\s\S]*?)\s*$/.exec(pending); pending = '';
    if (!instruction) continue;
    const command = instruction[1].toUpperCase(), body = instruction[2];
    if (['RUN', 'COPY', 'ADD'].includes(command)) {
      for (const match of body.matchAll(/<<(-?)\s*(['"]?)([A-Za-z_][\w.-]*)\2/g)) heredocs.push({ delimiter: match[3], stripTabs: !!match[1] });
    }
    if (command === 'ARG' && stage < 0) {
      const arg = /^([A-Za-z_]\w*)(?:=(.*))?$/.exec(body);
      if (arg && !Object.hasOwn(variables, arg[1]) && arg[2] !== undefined) variables[arg[1]] = arg[2].replace(/^(['"])(.*)\1$/, '$2');
    }
    if (command !== 'FROM') continue;
    const from = /^(?:--platform=(\S+)\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/i.exec(body);
    if (!from) { out.push(classifyImageReference({ role: 'base', line: start, declared: body, reference: null, unresolved: [], reason: 'unparsed-from' })); continue; }
    stage++;
    const resolved = resolveExpanded(from[2], variables), localStage = stages.has(resolved.reference.toLowerCase());
    const platform = from[1] ? resolveExpanded(from[1], variables) : null;
    if (!localStage && resolved.reference.toLowerCase() !== 'scratch') out.push(classifyImageReference({ ...resolved, declared: from[2], line: start,
      platform: platform?.reference || null, unresolved: [...new Set([...resolved.unresolved, ...(platform?.unresolved || [])])],
      stage, stageName: from[3] || null, role: 'base', finalStage: false }));
    stages.add(String(stage));
    if (from[3]) stages.add(from[3].toLowerCase());
  }
  if (heredocs.length) throw Error('unterminated Dockerfile heredoc');
  for (const item of out) item.finalStage = item.stage === stage;
  return out;
}

function yamlReferences(text, context = {}) {
  const out = [], visited = new WeakSet();
  const maxNodes = context.maxNodes ?? 100000;
  let nodes = 0;
  const file=String(context.filePath||'').replace(/\\/g,'/');
  const ci=context.ci === true || /(^|\/)\.gitlab-ci\.ya?ml$/i.test(file) || /(^|\/)\.gitlab\/.*\.ya?ml$/i.test(file) || /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(file);
  // Whole filesystems contain translation catalogues, package locks and test
  // data. Only parse YAML as an image definition when the file or deployment
  // keys provide evidence. Project scans retain their generic extractor.
  if (context.deploymentYamlOnly && !ci &&
      !/(?:^|\/)(?:docker-)?compose(?:[.-][^/]*)?\.ya?ml$/i.test(file) &&
      !/(?:^|[\n{,])\s*['"]?(?:services|containers|initContainers|ephemeralContainers|jobs|docker|apiVersion)['"]?\s*:/m.test(text)) return [];
  const documents = yaml.loadAll(text, undefined, {schema:yaml.JSON_SCHEMA,json:false});
  function walk(value, parts, variables, localImages) {
    if (!value || typeof value !== 'object' || visited.has(value)) return;
    if (++nodes > maxNodes || parts.length > 128) throw Error('YAML image discovery exceeds configured traversal limits');
    visited.add(value);
    const scoped=ci && value.variables ? {...variables,...scalarVariables(value.variables),...(context.variables||{})}:variables;
    for (const [key, child] of Object.entries(value)) {
      if(ci && key==='services' && Array.isArray(child)){
        for(let i=0;i<child.length;i++)if(typeof child[i]==='string'){const declared=child[i],resolved=resolveExpanded(declared,scoped);out.push(classifyImageReference({...resolved,declared,location:[...parts,key,String(i)].join('.'),role:'ci',line:null}));}else walk(child[i],[...parts,key,String(i)],scoped,localImages);
        continue;
      }
      const serviceName=ci && key==='name' && parts.includes('services') && typeof child==='string';
      const declared=key==='image'?(typeof child==='string'?child:ci&&child&&typeof child.name==='string'?child.name:null):serviceName?child:null;
      if (declared!==null) {
        const resolved = resolveExpanded(declared, scoped);
        const localBuild=(!ci && Object.hasOwn(value,'build')) || localImages.has(resolved.reference);
        const hasPlatform=!ci && Object.hasOwn(value,'platform'),platform=hasPlatform && typeof value.platform==='string'?resolveExpanded(value.platform,scoped):null;
        out.push(classifyImageReference({ ...resolved, ...(hasPlatform?{platform:platform?.reference ?? null,platformInvalid:!platform,unresolved:[...new Set([...resolved.unresolved,...(platform?.unresolved||[])])]}:{}), declared, location: [...parts, key].join('.'), role: ci?'ci':'deployment', line: null, ...(localBuild?{localBuild:true}:{}) }));
      } else if(key!=='variables') walk(child, [...parts, key],scoped,localImages);
    }
  }
  documents.forEach((doc, index) => {
    const variables={...scalarVariables(ci?doc?.variables:null),...(context.variables||{})},localImages=new Set();
    if(!ci && doc?.services && typeof doc.services==='object')for(const service of Object.values(doc.services))if(service && typeof service==='object' && Object.hasOwn(service,'build') && typeof service.image==='string'){const r=resolveExpanded(service.image,variables);if(!r.unresolved.length)localImages.add(r.reference);}
    walk(doc, [String(index)],variables,localImages);
  });
  return out;
}

const DEFAULT_EXTRACTORS = Object.freeze([
  { id: 'dockerfile', accepts: name => /^(?:dockerfile|containerfile)(?:\..+)?$/i.test(name) || /\.(?:dockerfile|containerfile)$/i.test(name), extract: dockerfileReferences },
  { id: 'yaml-image', accepts: name => /\.ya?ml$/i.test(name), extract: yamlReferences },
]);

function discoverImageReferences(root, options = {}) {
  const extractors = options.extractors || DEFAULT_EXTRACTORS;
  const ids = new Set();
  for (const extractor of extractors) {
    if (!extractor?.id || ids.has(extractor.id) || typeof extractor.accepts !== 'function' || typeof extractor.extract !== 'function') throw Error('invalid or duplicate image reference extractor');
    ids.add(extractor.id);
  }
  const references = [], warnings = [], stack = [path.resolve(root)];
  const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set(['.git', 'node_modules', '.venv', 'vendor']),
    excludePath: options.excludePath, useDefaults: options.defaultExcludes !== false });
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (error) { warnings.push({ type: 'dependency-coverage', reason: 'image-reference-read-error', message: `Cannot inspect image declarations: ${error.message}` }); continue; }
    for (const entry of entries) {
      const file = path.join(dir, entry.name), relative = path.relative(root, file).split(path.sep).join('/');
      if (entry.isDirectory()) { if (!skip(file, entry.name) && !options.skipInventoryDir?.(file)) stack.push(file); continue; }
      if (!entry.isFile()) continue;
      for (const extractor of extractors) {
        if (!extractor.accepts(entry.name, relative)) continue;
        try {
          if (fs.statSync(file).size > (options.maxFileBytes ?? 8 * 1024 * 1024)) throw Error('declaration exceeds configured size limit');
          const items = extractor.extract(fs.readFileSync(file, 'utf8'), {...options,filePath:relative});
          for (const item of items) {
            const id = 'image-reference:' + crypto.createHash('sha256').update(JSON.stringify([relative, extractor.id, item.line, item.location, item.declared])).digest('hex');
            const ref = classifyImageReference(item);
            if (options.redactParseErrors && (!ref.reference || ref.blockReason === 'invalid-reference' ||
              [ref.declared, ref.reference, ref.platform].some(v=>v && (v.length > 1024 || /[\s?#]|:\/\//.test(v))))) {
              ref.declared = '[unparsed image reference]';
              ref.reference = null;
              ref.platform = null;
              ref.scanEligible = false;
              ref.contentVerified = false;
            }
            references.push({ ...ref, id, path: relative, extractor: extractor.id, evidence: 'reference-only', contentVerified: false });
          }
        } catch (error) {
          warnings.push({ type: 'dependency-coverage', reason: 'image-reference-parse-error', manifestPath: relative,
            message: options.redactParseErrors ? `Image references could not be fully parsed in ${relative}` : `Image references could not be fully parsed in ${relative}: ${error.message}` });
        }
      }
    }
  }
  return { references: references.sort((a, b) => a.path.localeCompare(b.path) || (a.line || 0) - (b.line || 0)), warnings };
}

// A mutable tag or a matching file name is not evidence of which image was
// scanned. Explicit digest references may bind to a selected manifest or its
// acquired index; keep Dockerfile base-stage role intact.
function bindImageDefinitions(targets, references) {
  const declarations = references.map(ref => ({ ...ref, boundArtifactIds: [] }));
  for (const target of targets) {
    target.metadata ||= {};
    const previous = Array.isArray(target.metadata.definitions) ? target.metadata.definitions : [];
    const definitions = [...previous];
    const digest = target.metadata.digest;
    const indexDigest = target.metadata.registryEvidence?.digest;
    for (const ref of declarations) {
      if (ref.unresolved?.length || typeof ref.reference !== 'string') continue;
      const match = /@([a-z][a-z0-9]*:[a-f0-9]+)$/.exec(ref.reference);
      if (!match) continue;
      const exact = match[1], binding = exact === digest ? 'manifest-digest' : exact === indexDigest ? 'index-digest' : null;
      if (!binding) continue;
      ref.boundArtifactIds.push(target.id);
      if (!definitions.some(item => item.id === ref.id && item.digest === exact)) definitions.push({
        id: ref.id, path: ref.path, line: ref.line ?? null, location: ref.location ?? null,
        declared: ref.declared, reference: ref.reference, role: ref.role,
        stage: ref.stage ?? null, stageName: ref.stageName ?? null, finalStage: ref.finalStage ?? null,
        digest: exact, binding,
      });
    }
    target.metadata.definitions = definitions;
  }
  for (const target of targets) target.metadata.declarations = declarations.map(ref => ({ ...ref, boundArtifactIds: [...ref.boundArtifactIds] }));
  return declarations;
}

function referenceWarnings(references) {
  return references.map(reference => ({ type: 'dependency-coverage', reason: 'image-content-unverified', severity: 'info',
    capability: 'inventory', artifactId: reference.id, manifestPath: reference.path,
    message: `${reference.path}${reference.line ? ':' + reference.line : ''}: image ${reference.declared} — reference only; image content not verified.` +
      (reference.unresolved?.length ? ` Unresolved variables: ${reference.unresolved.join(', ')}.` : '') +
      (reference.role === 'base' ? ' A Dockerfile base is not evidence of the final built image.' : '') }));
}

// Pinning is a property of the declaration, never of the digest resolved during
// a scan. Even numeric version tags can be reassigned by a registry publisher.
const UNPINNED_IMAGE_MESSAGE='Image references without a digest use mutable tags, including version tags and implicit latest. Their content can change between the scan, build and deployment. Pin each reference with @sha256:<digest>; the digest observed during a scan does not pin the declaration.';
function unpinnedImageWarnings(references=[]) {
  const items=[],seen=new Set();
  for(const ref of references){
    if(ref.localBuild || ref.classification==='local-build' || !ref.reference)continue;
    // Invalid or unresolved references cannot establish whether a pin is valid.
    let parsed;try{parsed=require('./image-registry').parseReference(ref.reference);}catch{continue;}
    if(parsed.reference.includes(':'))continue;
    const key=JSON.stringify([ref.reference,ref.path,ref.line,ref.location]);if(seen.has(key))continue;seen.add(key);
    const location=ref.path ? `${ref.path}${ref.line?':'+ref.line:''}${ref.location?' ('+ref.location+')':''}` : null;
    items.push({id:ref.reference,reference:ref.reference,...(ref.declaredInTargetId && {declaredInTargetId:ref.declaredInTargetId}),declared:ref.declared||ref.reference,
      ...(ref.path?{manifestPaths:[ref.path]}:{}),...(ref.line?{line:ref.line}:{}),...(ref.location?{location:ref.location}:{}),
      ...(location?{detail:location}:{})});
  }
  return items.length ? [{type:'image-unpinned',reason:'mutable-image-reference',severity:'warning',affectsCompleteness:false,
    count:items.length,items,message:UNPINNED_IMAGE_MESSAGE,_groupedDiagnostics:true}] : [];
}

module.exports = { unpinnedImageWarnings, UNPINNED_IMAGE_MESSAGE, discoverImageReferences, referenceWarnings, bindImageDefinitions, dockerfileReferences, yamlReferences, resolveVariables, classifyImageReference, DEFAULT_EXTRACTORS };
