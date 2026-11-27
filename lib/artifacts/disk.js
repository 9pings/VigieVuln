'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const {DEFAULT_LIMITS} = require('./index');

const isDisk = file => /\.(?:raw|img|qcow2|vhdx?|vmdk|vdi)$/i.test(file);
const maxEntries = DEFAULT_LIMITS.maxEntries;
const maxFile = 512 * 1024 ** 2;

// Give the decoder one seekable, read-only descriptor. Backing-file names
// supplied in disk metadata cannot open another file on the host.
async function engine({fd,size,start}, filename, print) {
  const wasm = process.versions.bun ? (await import('./disk-wasm.mjs')).default : require.resolve('7z-wasm/7zz.wasm');
  const z = await require('7z-wasm')({wasmBinary:fs.readFileSync(wasm), print, printErr:print});
  const FS = z.FS;
  const node = FS.create('/' + filename, 0o444);
  node.usedBytes = size;
  node.stream_ops = {...node.stream_ops, read(stream, buffer, offset, length, position) {
    if (!Number.isSafeInteger(position) || position < 0) throw Error('Invalid disk read offset');
    if (position >= size) return 0;
    return fs.readSync(fd, buffer, offset, Math.min(length,size-position), start+position);
  }};
  return z;
}

function safePath(file) {
  if (!file || file.length > 4096 || /[\\\x00-\x1f\x7f]/.test(file)) return false;
  return file.split('/').every(p => p && p !== '.' && p !== '..' && (process.platform !== 'win32' ||
    (!/[<>:"|?*]|[. ]$/.test(p) && !/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p))));
}

async function list(source, filename) {
  let outerType, type, entries = 0, entry, bytes = 0;
  const files = [];
  let skipped = 0;
  function finish() {
    if (!entry) return;
    if (!entry.path || !safePath(entry.path)) throw Error('Invalid disk member path');
    if (!entry.folder && !entry.special) {
      if (!Number.isSafeInteger(entry.size) || entry.size < 0) throw Error('Invalid disk member size');
      if (entry.size > maxFile && !['GPT','MBR'].includes(type)) skipped++;
      else files.push({path:entry.path,size:entry.size,offset:entry.offset});
    }
    entry = null;
  }
  let listing = false;
  const z = await engine(source, filename, line => {
    bytes += Buffer.byteLength(line);
    if (bytes > 256 * 1024 ** 2) throw Error('Disk listing exceeds metadata budget');
    if (!listing) {
      if (line.startsWith('Type = ')) { type = line.slice(7); outerType ??= type; }
      if (line === '----------') listing = true;
    } else if (line.startsWith('Path = ')) {
      finish();
      if (++entries > maxEntries) throw Error('Disk entry limit exceeded');
      entry = {path:line.slice(7)};
    } else if (entry) {
      if (line.startsWith('Size = ')) entry.size = Number(line.slice(7));
      if (line.startsWith('Offset = ')) entry.offset = Number(line.slice(9));
      if (line === 'Folder = +') entry.folder = true;
      // 7-Zip lists trailing unallocated MBR space as a file with no type.
      if (type === 'MBR' && line === 'File System = ') entry.special = true;
      if (/^Mode = [^d-]|^(?:Symbolic Link|Hard Link|Reparse) = .+/.test(line)) entry.special = true;
    }
  });
  if (z.callMain(['l','-slt','/' + filename]) !== 0 || !listing) throw Object.assign(Error('Cannot inspect this disk or filesystem'), {code:'UNRECOGNIZED_DISK'});
  finish();
  return {files,outerType,type,skipped};
}

async function extract(source, filename, destination, files, budget) {
  if (!files.length) return;
  let total = 0;
  for (const member of files) total += member.size;
  if (!Number.isSafeInteger(total) || total > budget.bytes) throw Error('Disk expansion exceeds available space or collection budget');
  budget.bytes -= total;
  const z = await engine(source,filename,()=>{});
  const {FS, NODEFS} = z;
  FS.mkdir('/out');
  // Only known, listed files may be written. Directory creation uses this
  // private initially empty tree. Never recreate symlinks, devices or hardlinks.
  const allowed = new Map(files.map(f=>[path.join(destination,f.path),f.size]));
  const dirs = new Set([destination]);
  for (const file of allowed.keys()) {
    let dir = path.dirname(file);
    while (!dirs.has(dir)) {dirs.add(dir); dir=path.dirname(dir);}
  }
  const mknod = NODEFS.node_ops.mknod;
  NODEFS.node_ops.mknod = (parent,name,mode,dev) => {
    const dest = path.join(NODEFS.realPath(parent),name);
    const dir = FS.isDir(mode);
    if (!safePath(name) || !(dir ? dirs.has(dest) : FS.isFile(mode) && allowed.has(dest))) throw Error('Unexpected disk extraction path');
    return mknod(parent,name,dir ? 0o40700 : 0o100600,dev);
  };
  NODEFS.node_ops.symlink = NODEFS.node_ops.rename = () => {throw Error('Disk links and renames are disabled');};
  const checkSize = (node,end) => {
    const limit = allowed.get(NODEFS.realPath(node));
    if (limit === undefined || !Number.isSafeInteger(end) || end < 0 || end > limit) throw Error('Disk member exceeded its declared size');
  };
  NODEFS.node_ops.setattr = (node, attr) => {
    if (attr.size !== undefined) {checkSize(node,attr.size); fs.truncateSync(NODEFS.realPath(node),attr.size);}
  };
  const write = NODEFS.stream_ops.write;
  NODEFS.stream_ops.write = (stream,buf,off,len,pos) => {
    checkSize(stream.node,pos+len);
    return write(stream,buf,off,len,pos);
  };
  FS.mount(NODEFS,{root:destination},'/out');
  FS.writeFile('/selected',files.map(f=>f.path).join('\n')+'\n');
  if (z.callMain(['x','-y','-spd','-ssc','-scsUTF-8','-i@/selected','-o/out','/'+filename]) !== 0) throw Error('Disk extraction failed');
  for (const [file,expected] of allowed) {
    const st=fs.lstatSync(file);
    if (!st.isFile() || st.size!==expected) throw Error('Disk member failed verification');
  }
}

async function readDisk(input, temp) {
  const stat = fs.statfsSync(temp);
  const budget = {bytes:Math.min(DEFAULT_LIMITS.maxBytes, Math.floor(stat.bavail * stat.bsize * 0.8))};
  const targets=[];
  let skippedPartitions = 0;
  async function visitFile(file, label) {
    const handle = await fs.promises.open(file,'r');
    try {
      const {size} = await handle.stat();
      if (!Number.isSafeInteger(size)) throw Error('Invalid disk size');
      await visit({fd:handle.fd,start:0,size},label);
    } finally {await handle.close();}
  }
  async function visit(source, label) {
    const filename = 'input' + (label ? '.img' : path.extname(input).toLowerCase());
    let listing;
    try { listing = await list(source,filename); }
    catch (error) {
      if (label && error.code === 'UNRECOGNIZED_DISK') { skippedPartitions++; return; }
      throw error;
    }
    if (!label && ['GPT','MBR'].includes(listing.type)) {
      if (listing.files.length > 128) throw Error('Disk partition limit exceeded');
      for (const part of listing.files) {
        if (listing.outerType === listing.type && Number.isSafeInteger(part.offset)) {
          // A raw partition can be scanned through a bounded window on the same fd.
          if (part.offset < 0 || part.offset > source.size-part.size) throw Error('Invalid partition bounds');
          await visit({fd:source.fd,start:part.offset,size:part.size},part.path);
        } else {
          const stage=fs.mkdtempSync(path.join(temp,'part-'));
          try {
            await extract(source,filename,stage,[part],budget);
            await visitFile(path.join(stage,part.path),part.path);
          } finally {fs.rmSync(stage,{recursive:true,force:true});}
        }
      }
    } else if (listing.type === 'Ext') {
      const root=fs.mkdtempSync(path.join(temp,'root-'));
      await extract(source,filename,root,listing.files,budget);
      targets.push({root,partition:label,skipped:listing.skipped});
    } else if (label) skippedPartitions++;
    else throw Error('Unsupported disk filesystem: '+ (listing.type || 'unrecognized'));
  }
  await visitFile(input,null);
  if (!targets.length) throw Error('No readable ext filesystem found in disk');
  // Emscripten sets the worker exit code on unsuccessful format probes.
  // The parent receives skipped-partition coverage alongside the usable roots.
  process.exitCode = 0;
  console.log(JSON.stringify({targets,skippedPartitions}));
}

async function openDisk(file) {
  const temp=await fs.promises.mkdtemp(path.join(os.tmpdir(),'vigievuln-disk-'));
  const cleanup=()=>fs.promises.rm(temp,{recursive:true,force:true});
  try {
    const compiled=process.versions.bun && /(?:^|[\\/])\$bunfs[\\/]/.test(process.argv[1]);
    const args=compiled ? [] : [path.resolve(__dirname,'../../vigievuln.js')];
    const {stdout}=await promisify(execFile)(process.execPath,[...args,'__read-system-disk',file,temp],
      {timeout:15*60*1000,killSignal:'SIGKILL',maxBuffer:1024*1024});
    const {targets,skippedPartitions}=JSON.parse(stdout);
    return {cleanup,targets:targets.map(({root,partition,skipped})=>({
      root,kind:'rootfs',metadata:{format:'directory',diskFormat:path.extname(file).slice(1),source:file,partition,
        warnings:[...(skipped?[`${skipped} files exceed the per-file disk limit`]:[]),
          ...(skippedPartitions?[`${skippedPartitions} partitions use unsupported filesystems`]:[])]},
    }))};
  } catch(error) {await cleanup();throw Error(error.stderr?.trim() || error.message);}
}
module.exports={isDisk,openDisk,readDisk};
