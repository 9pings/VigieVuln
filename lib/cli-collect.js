'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {Command} = require('commander');
const {inventoryTarget, writeSnapshot} = require('./artifacts/scan');
const {openArtifact} = require('./artifacts');
const {discoverImageReferences, bindImageDefinitions} = require('./image-references');

// A regular SQLite read-only connection can create WAL shared-memory files.
// Immutable mode cannot consult outstanding journals, so report those as incomplete.
function openRpmSqlite(file) {
  for (const suffix of ['-wal', '-journal']) {
    if (fs.statSync(file + suffix, {throwIfNoEntry:false})?.size > 0)
      throw Error('RPM database has an outstanding journal; use a consistent snapshot');
  }
  return require('./sqlite-driver').openSqlite(file, {readonly:true, immutable:true});
}

// Kernel and virtual filesystems expose files whose read blocks forever (/proc/kmsg,
// debugfs event streams); network and user-space mounts are not this system's own content.
const SKIPPED_MOUNT_TYPES = /^(?:proc|sysfs|devtmpfs|devpts|cgroup2?|securityfs|debugfs|tracefs|autofs|overlay|nsfs|mqueue|fusectl|rpc_pipefs|bpf|pstore|configfs|hugetlbfs|binfmt_misc|efivarfs|selinuxfs|nfs4?|nfsd|cifs|smb3?|9p|ceph|glusterfs|lustre|afs|fuse(?:\.\S+)?) /;
function hostExclusions(root, extra = []) {
  const excluded = new Set(['proc', 'sys', 'dev', 'run', 'var/lib/docker', 'var/lib/containerd', 'var/lib/containers/storage']
    .map(p => path.join(root, p)));
  // --exclude-path: absolute, or relative to the collected root.
  for (const p of extra || []) excluded.add(path.isAbsolute(p) ? path.resolve(p) : path.resolve(root, p));
  if (process.platform === 'linux') {
    // Also prune bind-mounted virtual filesystems and nested overlay mounts.
    const mountInfo = fs.readFileSync('/proc/self/mountinfo', 'utf8');
    for (const line of mountInfo.split('\n')) {
      const [mount, info] = line.split(' - ');
      if (!info || !SKIPPED_MOUNT_TYPES.test(info)) continue;
      const dir = mount.split(' ')[4].replace(/\\([0-7]{3})/g, (_, n) => String.fromCharCode(parseInt(n, 8)));
      if (dir !== root && !path.relative(root, dir).startsWith('..')) excluded.add(dir);
    }
  }
  return excluded;
}

const lockParsers = {
  'composer.lock': ['composer', file => require('./codecs/composer/parse').parseComposerLock(file)],
  'package-lock.json': ['npm', file => require('./codecs/npm/parse').parsePackageLock(file)],
  'npm-shrinkwrap.json': ['npm', file => require('./codecs/npm/parse').parsePackageLock(file)],
  'pnpm-lock.yaml': ['npm', file => require('./codecs/npm/parse').parsePnpmLock(file)],
  'yarn.lock': ['npm', file => require('./codecs/npm/parse').parseYarnLockV1(file)],
  'Gemfile.lock': ['ruby', file => require('./codecs/ruby/parse').parseGemfileLockFile(file)],
  'poetry.lock': ['pypi', file => require('./codecs/pypi/parse').parsePoetryLock(file)],
  'uv.lock': ['pypi', file => require('./codecs/pypi/parse').parseUvLock(file)],
  'pdm.lock': ['pypi', file => require('./codecs/pypi/parse').parsePdmLock(file)],
  'Pipfile.lock': ['pypi', file => require('./codecs/pypi/parse').parsePipfileLock(file)],
  'gradle.lockfile': ['maven', file => require('./codecs/gradle/parse').parseGradleLockfile(fs.readFileSync(file,'utf8'))],
  'packages.lock.json': ['nuget', file => require('./codecs/nuget/parse').parsePackagesLockJson(file)],
};
const projectManifests = new Set(['package.json','composer.json','pyproject.toml','pom.xml','go.mod',
  'Gemfile','build.gradle','build.gradle.kts','Pipfile','requirements.txt']);

const progress = { files: 0, last: '' };
async function collectTarget(target, options) {
  const warnings = [], descriptors = [], certificateFiles = [];
  let incomplete = false, count = 0;
  const result = await inventoryTarget(target, {...options, openRpmSqlite, redactParseErrors:true, async onInventoryFile(file, name, deps) {
    progress.files++; progress.last = path.dirname(file);
    if (require('./certs/sniff').isCandidate(name)) certificateFiles.push(file);
    const isLock = Object.hasOwn(lockParsers, name);
    if (!isLock && !projectManifests.has(name) && !/\.(?:cs|fs|vb)proj$/i.test(name)) return;
    const relative = path.relative(target.root, file).split(path.sep).join('/');
    if (!require('./artifacts/component-scope').isSystemProjectPath(relative)) return;
    descriptors.push(relative);
    if (!isLock) return;
    try {
      if (fs.statSync(file).size > 64 * 1024 * 1024) throw Error('lockfile exceeds size limit');
      const [ecosystem, parse] = lockParsers[name];
      for (const item of (await parse(file)).deps) {
        const version = require('./deps-descriptor').cleanVersion(ecosystem === 'npm'
          ? require('./codecs/npm/parse').normaliseNpmVersion(item.version) : item.version);
        if (!version || !item.name) { incomplete = true; continue; }
        const dep = require('./dep-record').makeDepRecord({
          ecosystem, namespace:item.vendor || item.group, name:ecosystem === 'composer' ? item.pkg : item.name,
          version, isDev:item.isDev, scope:item.scope, provenance:'lockfile', manifestPath:relative,
        });
        if (item.managerRelations?.length === 1) dep.managerRelation = item.managerRelations[0];
        else if (ecosystem === 'npm' && Object.hasOwn(item,'depth'))
          dep.managerRelation = item.depth === 0 ? 'direct' : item.depth > 0 ? 'transitive' : 'unknown';
        dep.coordKey = JSON.stringify(['lockfile', relative, dep.ecosystem, dep.namespace, dep.name, version, dep.isDev]);
        if (!deps.has(dep.coordKey)) count++;
        deps.set(dep.coordKey, dep);
      }
    } catch (error) {
      incomplete = true;
      // Parser errors can quote source lines. Return only a bounded category.
      const cause = error.code === 'EACCES' ? 'permission denied' :
        error.message === 'lockfile exceeds size limit' ? 'file exceeds 64 MiB' :
        /pnpm-lock parse failed/.test(error.message) ? 'invalid pnpm YAML' :
        /JSON|package-lock parse failed/.test(error.message) ? 'invalid JSON' : 'unrecognized lockfile contents';
      warnings.push({type:'dependency-coverage', capability:'inventory', manifestPath:relative,
        message:'Could not inventory lockfile (' + cause + '): ' + relative});
    }
  }});
  result.metadata.projectDescriptors = descriptors.sort();
  await require('./artifacts/system-apps').inventoryApplications(target.root, result, descriptors, options.skipInventoryDir);
  const projectRoots = new Set(result.metadata.systemApplications.applications.map(app=>app.root));
  const certs = [], failures = [];
  for (const file of certificateFiles) {
    const relative = path.relative(target.root,file).split(path.sep).join('/');
    if (!require('./artifacts/component-scope').isSystemProjectPath(relative)) continue;
    let dir = path.posix.dirname(relative);
    while (dir !== '.' && !projectRoots.has(dir)) dir = path.posix.dirname(dir);
    if (!projectRoots.has(dir)) continue;
    try { certs.push(...require('./certs/scan').inspectCertificateFile(file,path.basename(file),relative)); }
    catch { failures.push(relative); }
  }
  result.metadata.projectCertificates = certs;
  result.coverage.push({artifactTargetId:result.id,capability:'inventory',collector:'project-certificates',
    execution:failures.length ? 'partial' : 'completed',result:'inventoried',count:certs.length,
    ...(failures.length ? {reason:failures.length+' unreadable certificate/key candidate(s)'} : {})});
  result.warnings = require('./artifacts/access-warnings').foldAccessWarnings([...result.warnings, ...warnings]);
  result.coverage.push({artifactTargetId:result.id, capability:'inventory', collector:'project-lockfiles',
    execution:incomplete ? 'partial' : 'completed', result:incomplete ? 'indeterminate' : 'inventoried', count});
  return result;
}

async function run(args) {
  const command = new Command('vigievuln system collect')
    .description('Collect a local filesystem and optional local images. Write a portable inventory for auditor-side assessment.')
    .argument('[input]', 'Linux filesystem root, local Docker/OCI archive or VM disk', '/')
    .option('--images', 'inspect locally available images declared by the collected projects')
    .requiredOption('-o, --output <file>', 'destination inventory JSON')
    .option('--docker', 'collect every image in the local Docker Engine cache')
    .option('--docker-socket <path>', 'Docker Engine Unix socket', '/var/run/docker.sock')
    .option('--image <path...>', 'additional local image archives, OCI layouts or extracted directories')
    .option('--projects <directory>', 'limit Dockerfile and YAML image declaration discovery to this directory')
    .option('--exclude-path <path...>', 'directories to leave out, absolute or relative to the collected root (the collection kit itself, a data volume)');
  command.parse(args, {from:'user'});
  const opts = command.opts(), input = fs.realpathSync(command.args[0] || '/'), output = path.resolve(opts.output);
  // A collection that runs for more than 30 s says so on stderr, so a caller can tell a
  // long inventory from a hung one.
  const startedAt = Date.now();
  const heartbeat = setInterval(() => console.error(`· collecting: ${Math.round((Date.now() - startedAt) / 1000)} s, ${progress.files} file(s) examined${progress.last ? ', in ' + progress.last : ''}`), 30000);
  heartbeat.unref();
  const images = [...new Set((opts.image || []).map(p => path.resolve(p)))];
  const existing = fs.statSync(output, {throwIfNoEntry:false});
  if (existing && (!existing.isFile() || [input,...images].some(p => {
    const stat=fs.statSync(p,{throwIfNoEntry:false});
    return stat && stat.dev===existing.dev && stat.ino===existing.ino;
  }))) throw Error('output must be a separate inventory file');

  const targets = new Map(), references = [];
  let partial = false;
  async function addInput(file, source, primary, engineImage) {
    const directory = fs.statSync(file).isDirectory();
    const plain = directory && !fs.existsSync(path.join(file,'oci-layout'));
    const disk = require('./artifacts/disk');
    const opened = plain ? {targets:[{root:fs.realpathSync(file),kind:'rootfs',metadata:{format:'directory',source}}],cleanup() {}}
      : !directory && disk.isDisk(file) ? await disk.openDisk(file) : await openArtifact(file);
    try {
      for (const target of opened.targets) {
        if (target.id && targets.has(target.id)) {
          const meta=targets.get(target.id).metadata;
          (meta.localSources ||= []).push(source);
          if (engineImage) meta.localDocker=engineImage;
          continue;
        }
        const excluded=hostExclusions(target.root, opts.excludePath);
        if (plain && primary) for (const image of images) {
          if (fs.statSync(image,{throwIfNoEntry:false})?.isDirectory()) excluded.add(fs.realpathSync(image));
        }
        const skipInventoryDir = dir => excluded.has(dir);
        const inventory=primary
          ? await collectTarget(target,{source,systemSource:[source,target.metadata.partition],skipInventoryDir})
          : await inventoryTarget(target,{source,openRpmSqlite,redactParseErrors:true,skipInventoryDir});
        if (target.metadata.diskFormat && target.metadata.warnings.length) partial = true;
        targets.set(inventory.id,inventory);
        inventory.metadata.localSources=[source];
        if(primary && plain && fs.realpathSync(target.root)==='/')inventory.metadata.hostname=require('node:os').hostname();
        if (engineImage) inventory.metadata.localDocker=engineImage;
        if (!primary) continue;
        inventory.metadata.inspectLocalImages = Boolean(opts.images || opts.docker || images.length);
        let projects=target.root;
        if (opts.projects) {
          projects=fs.realpathSync(plain ? opts.projects : path.join(target.root,opts.projects));
          const relative=path.relative(target.root,projects);
          if (relative==='..' || relative.startsWith('..'+path.sep) || !fs.statSync(projects).isDirectory())
            throw Error('--projects must be a directory within the collected root');
        }
        const prefix=path.relative(target.root,projects);
        const discovery=discoverImageReferences(projects,{
          skipInventoryDir:dir=>skipInventoryDir(dir) || !require('./artifacts/component-scope').isSystemProjectPath(path.relative(target.root,dir)),
          deploymentYamlOnly:true, redactParseErrors:true
        });
        for (const ref of discovery.references) references.push({...ref, id:inventory.id+'/'+ref.id,
          declaredInTargetId:inventory.id, path:path.join(prefix,ref.path).split(path.sep).join('/')});
        inventory.metadata.excludedDirectories=[...excluded].map(dir=>path.relative(target.root,dir)).sort();
        inventory.metadata.definitionDiscovery={source:prefix || '.',status:discovery.warnings.length?'incomplete':'no-match'};
        inventory.warnings = require('./artifacts/access-warnings').foldAccessWarnings([...inventory.warnings, ...discovery.warnings.map(w=>({...w,capability:'inventory'}))]);
      }
    } finally {await opened.cleanup();}
  }
  await addInput(input,input,true);
  const host=targets.values().next().value;
  let missingImage=false;
  function failed(source,error) {
    partial=true;
    missingImage=true;
    host.warnings.push({type:'dependency-coverage',capability:'inventory',message:source+': '+error.message});
  }
  for (const image of images) {
    try {await addInput(image,image,false);} catch(error) {failed(image,error);}
  }
  function normalized(ref) {
    try {
      const {registry,repository,reference}=require('./image-registry').parseReference(ref);
      return JSON.stringify([registry,repository,reference]);
    } catch {return null;}
  }
  function localNames() {
    const result=new Map();
    for (const target of targets.values()) {
      const meta=target.metadata;
      for (const ref of [...(meta.tags || []),...(meta.localDocker?.tags || []),...(meta.localDocker?.repoDigests || [])]) {
        const key=normalized(ref);
        if (!key) continue;
        if (!result.has(key)) result.set(key,new Set());
        result.get(key).add(target.id);
      }
    }
    return result;
  }
  const known=localNames();
  const wanted=new Set(references.filter(r=>!r.unresolved?.length).map(r=>normalized(r.reference)).filter(k=>k && !known.has(k)));
  if (opts.docker || (opts.images && wanted.size)) {
    const selected=image=>opts.docker || [...(image.RepoTags || []),...(image.RepoDigests || [])].some(r=>wanted.has(normalized(r)));
    try {await require('./local-docker').collectImages(opts.dockerSocket,(f,s,m)=>addInput(f,s,false,m),failed,selected);}
    catch(error) {failed('Local Docker Engine',error);}
  }
  const all=[...targets.values()], names=localNames();
  for (const ref of references) ref.localImageCandidates=[...(names.get(normalized(ref.reference)) || [])];
  const declarations=bindImageDefinitions(all,references);
  for (const target of all) {
    const owned=declarations.filter(ref=>ref.declaredInTargetId===target.id);
    if (owned.length) target.metadata.declarations=owned;
    else delete target.metadata.declarations;
    if (target.metadata.definitions?.length && target.metadata.definitionDiscovery?.status!=='incomplete')
      target.metadata.definitionDiscovery={...target.metadata.definitionDiscovery,status:'matched'};
    if (opts.images) for (const ref of owned) {
      if (!ref.boundArtifactIds.length && !ref.localImageCandidates.length)
        failed(ref.path,Error('Declared image unavailable locally: '+ref.declared));
    }
  }
  if (missingImage) host.coverage.push({artifactTargetId:host.id,capability:'inventory',collector:'local-images',execution:'partial',result:'indeterminate'});
  await writeSnapshot(output, all, {compact:true, validate:true});
  console.log(`Inventory: ${output} (${all.length} target(s))`);
  const filename = './' + path.basename(output);
  const argument = /^[a-zA-Z0-9_./-]+$/.test(filename) ? filename : "'" + filename.replaceAll("'", "'\\''") + "'";
  console.log('On the auditor machine: vigievuln system scan ' + argument + ' --report-output ./rapport');
  if (partial) {for (const w of host.warnings) console.error(w.message); process.exitCode = 2;}
}
async function collectSystemTarget(target,options={}) {
 const excluded=hostExclusions(target.root,options.excludePath);
 return collectTarget(target,{...options,systemSource:[options.source||target.metadata.source,target.metadata.partition],skipInventoryDir:dir=>excluded.has(dir)});
}
module.exports = {run,collectSystemTarget};
