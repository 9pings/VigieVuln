'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { Command } = require('commander');
const { buildProjectDescriptor } = require('./project-descriptor');
const { sanitizeDescriptor, projectRequest, createProject, updateProject } = require('./project-client');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function watchCommand() {
  return new Command('vigievuln watch').usage('<dir> (--name <name> | --id <id> | --export <file>) [options]')
    .description('Collect dependency manifests locally, then upload once for server-side monitoring. No vulnerability scan or network resolution.')
    .argument('<dir>', 'project directory')
    .option('--name <name>', 'create a project, or update the unique project with exactly this name')
    .option('--id <id>', 'update this project explicitly, with revision checking; does not rename it')
    .option('--export <file>', 'write a new local descriptor only; no login, upload or network; refuses overwrite')
    .option('-e, --exclude <regex>', 'exclude dependency coordinates before export/upload')
    .option('--exclude-path <glob...>', 'exclude source sub-paths from collection')
    .option('--ecosystem <list>', 'auto, all, or comma-separated codec names', 'auto')
    .option('--no-default-excludes', 'include normally skipped dependency/build directories')
    .option('--ignore-test', 'exclude test dependencies during collection')
    .allowExcessArguments(false)
    .addHelpText('after', `
Privacy: watch uploads coordinates and versions, which may reveal private package names.
No source code, paths or credentials are included. Use --export to review first,
then project push --file <file> --name <name> (or --id <id>) for an explicit upload.
Upload requires login; a terminal can prompt when necessary. Export never signs in.
A different existing project is never replaced by name: use --id explicitly.
Updates use the current revision (CAS); conflicts are reported without retrying.
This is one upload, not a filesystem watcher; rerun to send changed dependencies.
Free account: 1 project, 100 distinct direct coordinates; multiple versions count once.
Unknown relations are excluded from monitoring and reported; unresolved versions stay unknown.
Legacy -s <dir> --prepare-project <file> and project push remain available.`);
}

async function collectDescriptor(root, opts, warn) {
  const srcRoot = fs.realpathSync(path.resolve(root));
  if (!fs.statSync(srcRoot).isDirectory()) throw new Error('watch requires an existing project directory');
  const { detectCodecs, allCodecs, getCodec } = require('./codecs');
  const { resolveActiveCodecs } = require('./codecs/select');
  const eco = opts.ecosystem.toLowerCase();
  const known = allCodecs().map(c => c.id);
  if (!['auto', 'all', 'both'].includes(eco) && eco.split(',').some(id => !known.includes(id.trim())))
    throw new Error('unknown ecosystem; expected auto, all, or registered codec names');
  const walkOpts = { srcRoot, excludePath: opts.excludePath || [], defaultExcludes: opts.defaultExcludes !== false };
  const excluded = opts.exclude ? new RegExp(opts.exclude) : null;
  const candidates = eco === 'auto' ? (await detectCodecs(srcRoot, walkOpts)).map(c => c.id) : known;
  const resolved = new Map();
  for (const id of new Set(resolveActiveCodecs(eco, candidates).map(id => id === 'yarn' ? 'npm' : id))) {
    // npm.collect also reads yarn.lock; collect a shared npm/yarn tree only once.
    // collect is a local parser. Do not call checkRegistry, transitive resolvers,
    // native scanners or application assessment as part of watch.
    const collected = await getCodec(id).collect(srcRoot, { ...walkOpts, offline: true,
      ignoreTest: !!opts.ignoreTest, deps2Exclude: excluded, scanJars: true });
    for (const [key, dep] of collected.deps) resolved.set(`${id}:${key}`, dep);
    for (const warning of collected.warnings || []) warn(warning.message);
  }
  const descriptor = sanitizeDescriptor(buildProjectDescriptor(resolved));
  // Also apply exclusions centrally: not every codec consumes deps2Exclude.
  if (excluded) descriptor.deps = descriptor.deps.filter(d => !excluded.test(d.namespace ? `${d.namespace}:${d.name}` : d.name));
  const unknown = descriptor.deps.filter(d => d.relation === 'unknown').length;
  if (unknown) warn(`${unknown} dependency version(s) have unknown relations and are excluded from monitoring.`);
  return descriptor;
}

async function runWatch(args, { ensureSession, log = console.log, warn = console.error } = {}) {
  const command = watchCommand().exitOverride();
  try { command.parse(args, { from: 'user' }); }
  catch (error) { if (error.code === 'commander.helpDisplayed') return; throw error; }
  const opts = command.opts();
  if (opts.export ? !!opts.id : (!!opts.name === !!opts.id))
    throw new Error('watch requires --name or --id for upload; --export cannot be combined with --id');
  if (opts.name !== undefined && (!opts.name.trim() || opts.name.trim().length > 120)) throw new Error('project name must contain 1 to 120 characters');
  if (opts.id && !UUID.test(opts.id)) throw new Error('invalid project id');
  const descriptor = await collectDescriptor(command.args[0], opts, warn);
  if (opts.export) {
    fs.writeFileSync(opts.export, JSON.stringify(descriptor, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    log(`Project descriptor exported locally to ${opts.export}. Nothing uploaded.`);
    warn('Review coordinates before sharing: private package names and versions can identify your project.');
    return;
  }
  if (!descriptor.deps.length) throw new Error('no dependencies collected; refusing to upload an empty project inventory');
  const session = await ensureSession();
  let current;
  const validateProject = p => p && UUID.test(p.id) && typeof p.name === 'string' && Number.isSafeInteger(p.revision) && p.revision > 0;
  if (opts.id) {
    const data = await projectRequest(`/v1/projects/${opts.id}`, { session: session.token });
    if (!validateProject(data.project) || data.project.id.toLowerCase() !== opts.id.toLowerCase()) throw new Error('invalid project service response');
    current = data.project;
  } else {
    const data = await projectRequest('/v1/projects', { session: session.token });
    if (!Array.isArray(data.projects) || !data.projects.every(validateProject)) throw new Error('invalid project service response');
    const matches = data.projects.filter(p => p.name === opts.name.trim());
    if (matches.length > 1) throw new Error('project name is ambiguous; use --id explicitly (see project status)');
    if (!matches.length && data.projects.length) throw new Error('another project already occupies a slot; use --id explicitly to replace its inventory (see project status)');
    current = matches[0];
  }
  warn('Project coordinates and versions will be stored on the service and may reveal private package names. No source code, paths or credentials are uploaded. Use --export to review and --exclude/--exclude-path to omit private dependencies.');
  let result;
  try {
    result = current ? await updateProject({ session: session.token, id: current.id, revision: current.revision, descriptor })
      : await createProject({ session: session.token, name: opts.name.trim(), descriptor });
  } catch (error) {
    if (error.code === 'REVISION_CONFLICT') throw new Error('project changed concurrently; review project status before retrying (revision conflict)');
    if (error.code === 'UNAUTHORIZED') throw new Error('session rejected; run vigievuln login before retrying');
    throw error;
  }
  if (!validateProject(result?.project) || (current && result.project.id !== current.id)) throw new Error('invalid project service response');
  log(`Project ${result.project.id} saved (revision ${result.project.revision}). Rerun watch to upload later dependency changes.`);
}
module.exports = { runWatch, collectDescriptor, watchCommand };
