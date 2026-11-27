'use strict';

const path = require('node:path').posix;

// Inventory files are relative to the target root. Resolve only the outer
// filesystem path. An archive member after "!/" has its own namespace.
function targetPath(file) {
  if (typeof file !== 'string' || !file) return file;
  const member = file.indexOf('!/');
  const outer = member < 0 ? file : file.slice(0,member);
  return path.resolve('/',outer) + (member < 0 ? '' : file.slice(member));
}

// The namespaced IDs stay in the inventory. Human-facing diagnostics identify
// the instance by its installed root and locate the evidence within that root.
function targetWarningMessage(w,formatPath=targetPath,applicationLabel) {
  let message=w.message;
  if (typeof message!=='string') return message;
  if (applicationLabel && w.applicationId && message.startsWith(w.applicationId+':'))
    message=applicationLabel+message.slice(w.applicationId.length);
  const file=w.manifestPath || w.path;
  if (file && message.endsWith(' '+file)) return message.slice(0,-file.length)+formatPath(file);
  if (w.type==='embedded-jar') return message.replace(
    /^(embedded archive with no resolvable Maven coordinate \(not scanned\): )(.+)$/,
    (_,label,path)=>label+formatPath(path));
  return message;
}

module.exports = {targetPath,targetWarningMessage};
