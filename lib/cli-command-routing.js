'use strict';

const COMMAND_HELP = `
Commands:
  scan <path|zip|descriptor.json>      scan project sources or offline extracts
  system collect [root] -o <file>     collect a local system inventory (default root: /)
  system scan <json|path|image|archive|disk>  assess a system or image
  watch <dir> --name <name>|--id <id>  collect and upload a project
  watch <dir> --export <file>           export descriptor locally
  login | logout | whoami              aliases of auth login | logout | status
  setup | config show                  configure or inspect sources
  cache export|import <file>           transfer the complete local cache
  cache prepare <descriptor|inventory> --output <file>  prepare an offline archive online
  watch --help: privacy, safe updates; free account: 1 project, 100 distinct direct coordinates (versions count once).`;

function routeArguments(input) {
  const args = [...input], command = args[0];
  const auth = { login: 'login', logout: 'logout', whoami: 'status' };
  if (Object.hasOwn(auth, command)) return { args: ['auth', auth[command], ...args.slice(1)] };
  if (['collect','analyse','image'].includes(command))
    throw Error(command+' has been removed. Use vigievuln system '+(command==='collect'?'collect':'scan')+'.');
  if(args.some(a=>/^(?:-s|--src|--source)(?:=|$)/.test(a)))
    throw Error('Source flags have been removed. Use vigievuln scan <input>.');
  if(command==='system'){
    if(args.length===1 || ['--help','-h'].includes(args[1]))return {help:'Usage: vigievuln system collect [root] -o collect.json\n       vigievuln system scan <json|path|image|archive|disk> [options]'};
    if(!['collect','scan'].includes(args[1]))throw Error('system expects collect or scan');
    return {args};
  }
  if (command === 'scan') {
    const rest = args.slice(1);
    if(rest[0] && !rest[0].startsWith('-')){
      const source=rest.shift();
      if(rest.some(a=>/^--(?:import-anonymized|prepare-offline)(?:=|$)/.test(a)))throw Error('scan input conflicts with an explicitly selected descriptor');
      let descriptor=false;
      if(/\.json$/i.test(source) && require('node:fs').existsSync(source)){
        const fs=require('node:fs');
        if(fs.statSync(source).size>128*1024*1024)throw Error('Source descriptor exceeds size limit');
        const document=JSON.parse(fs.readFileSync(source,'utf8'));
        if(document.schema==='vigievuln-artifact-inventory/1' || document.bomFormat || document.spdxVersion)
          throw Error('System inventories and SBOMs use vigievuln system scan <input>.');
        if(document.schema!=='fad-deps/1')throw Error('Unknown project descriptor schema. Scan the containing source directory for manifest files.');
        descriptor=true;
      }
      return {args:[descriptor?'--import-anonymized':'--src',source,...rest],sourceInput:source,descriptorScan:descriptor};
    }
    return {args:rest.length?rest:['--help']};
  }
  if (command === 'config') {
    if (args.length === 1 || args.some(a => a === '--help' || a === '-h'))
      return { help: 'Usage: vigievuln config show\nShow configuration with stored credentials masked (alias of --show-config).' };
    if (args.length !== 2 || args[1] !== 'show') throw new Error('usage: vigievuln config show');
    return { args: ['--show-config'] };
  }
  if (command === 'cache') {
    if (args.length === 1 || args.some(a => a === '--help' || a === '-h'))
      return { help: 'Usage: vigievuln cache prepare <descriptor-or-inventory.json> --output <archive.tar.gz> [source options]\n       vigievuln cache export <file> [--verbose] [source options]\n       vigievuln cache import <file> [--replace] [--force] [--verbose] [source options]\nPrepare warms the source descriptor or artifact inventory and writes an offline archive. Export copies the complete local cache.' };
    const [, operation, file, ...rest] = args;
    if (operation === 'prepare') {
      if (!file || file.startsWith('-')) throw new Error('usage: vigievuln cache prepare <descriptor.json> --output <archive.tar.gz>');
      if (rest.some(a=>/^--(?:export-cache|import-cache|prepare-offline|import-anonymized)(?:=|$)/.test(a))) throw new Error('cache prepare cannot be combined with another cache or descriptor command');
      let artifact=false;
      try {
        const fs=require('node:fs'),stat=fs.statSync(file);
        if(stat.isFile() && stat.size<=128*1024*1024)artifact=JSON.parse(fs.readFileSync(file,'utf8'))?.schema==='vigievuln-artifact-inventory/1';
      } catch { /* Descriptor parsing reports invalid inputs in the regular path. */ }
      if(artifact){
        const args=[],outputs=[];
        for(let i=0;i<rest.length;i++){
          if(rest[i]==='--output'){if(!rest[i+1]||rest[i+1].startsWith('-'))throw Error('--output requires a value');outputs.push(rest[++i]);}
          else if(rest[i].startsWith('--output='))outputs.push(rest[i].slice('--output='.length));
          else args.push(rest[i]);
        }
        if(outputs.length!==1 || !outputs[0])throw Error('cache prepare requires exactly one --output');
        return {args:['system','scan','--inventory',file,'--no-report','--prepare-cache',outputs[0],...args]};
      }
      return {args:['--prepare-offline',file,...rest]};
    }
    if (!['export', 'import'].includes(operation) || !file || file.startsWith('-'))
      throw new Error('usage: vigievuln cache export|import <file> [options]');
    const allowed = operation === 'export' ? ['--include-config', '--verbose'] : ['--force', '--replace', '--verbose'];
    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (allowed.includes(arg)) continue;
      const match = /^(--config|--source-profile|--proxy-cache|--cache-dir)(?:=(.*))?$/.exec(arg);
      if (match) {
        const value = match[2] === undefined ? rest[++i] : match[2];
        if (!value || value.startsWith('-')) throw new Error(`${match[1]} requires a value`);
        continue;
      }
      if (arg === '--vigievuln-proxy') {
        if (rest[i + 1] && !rest[i + 1].startsWith('-')) {
          if (!['fr', 'com'].includes(rest[++i])) throw new Error('--vigievuln-proxy accepts fr or com');
        }
        continue;
      }
      if (/^--vigievuln-proxy=(fr|com)$/.test(arg)) continue;
      throw new Error('unexpected cache option; see vigievuln cache --help');
    }
    return { args: [`--${operation}-cache`, file, ...rest] };
  }
  return { args };
}
module.exports = { routeArguments, COMMAND_HELP };
