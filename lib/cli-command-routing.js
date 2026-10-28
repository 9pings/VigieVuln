'use strict';

const COMMAND_HELP = `
Commands:
  scan <dir> [options]                  scan a source tree (alias of -s <dir>)
  watch <dir> --name <name>             collect locally and upload a monitored project
  watch <dir> --id <id>                 update an explicitly selected project
  watch <dir> --export <file>           local descriptor only; no login or network
  login | logout | whoami              aliases of auth login | logout | status
  config show                         show masked configuration
  cache export <file> [options]        alias of --export-cache
  cache import <file> [options]        alias of --import-cache

  watch --help: privacy, safe updates; free account: 1 project,
  100 distinct direct coordinates (versions count once). Legacy commands remain supported.`;

function routeArguments(input) {
  const args = [...input], command = args[0];
  const auth = { login: 'login', logout: 'logout', whoami: 'status' };
  if (Object.hasOwn(auth, command)) return { args: ['auth', auth[command], ...args.slice(1)] };
  if (command === 'scan') {
    const rest = args.slice(1);
    if (rest[0] && !rest[0].startsWith('-')) {
      const source = rest.shift();
      if (rest.some(a => /^(--src|--source)(=|$)|^-s/.test(a)))
        throw new Error('scan accepts either <dir> or --src/--source, not both');
      return { args: ['--src', source, ...rest] };
    }
    return { args: rest.length ? rest : ['--help'] };
  }
  if (command === 'config') {
    if (args.length === 1 || args.some(a => a === '--help' || a === '-h'))
      return { help: 'Usage: vigievuln config show\nShow configuration with stored credentials masked (alias of --show-config).' };
    if (args.length !== 2 || args[1] !== 'show') throw new Error('usage: vigievuln config show');
    return { args: ['--show-config'] };
  }
  if (command === 'cache') {
    if (args.length === 1 || args.some(a => a === '--help' || a === '-h'))
      return { help: 'Usage: vigievuln cache export <file> [--include-config] [--verbose]\n       vigievuln cache import <file> [--replace] [--force] [--verbose]\nAliases of --export-cache and --import-cache; the existing archive safeguards apply.' };
    const [, operation, file, ...rest] = args;
    if (!['export', 'import'].includes(operation) || !file || file.startsWith('-'))
      throw new Error('usage: vigievuln cache export|import <file> [options]');
    const allowed = operation === 'export' ? ['--include-config', '--verbose'] : ['--force', '--replace', '--verbose'];
    if (rest.some(arg => !allowed.includes(arg))) throw new Error('unexpected cache option; see vigievuln cache --help');
    return { args: [`--${operation}-cache`, file, ...rest] };
  }
  return { args };
}
module.exports = { routeArguments, COMMAND_HELP };
