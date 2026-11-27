#!/usr/bin/env node
'use strict';
// The server repository loads CLI modules by path (`require('vigievuln/lib/<name>')`, through
// its lib/fad.js). Those paths are a contract: this check fails when one of them no longer
// resolves, so a module is not moved, renamed or removed as "unused" by mistake.
// Usage: node scripts/check-server-modules.js [server checkout, default ../server]
const fs = require('node:fs'), path = require('node:path');
const cli = path.resolve(__dirname, '..');
const server = path.resolve(process.argv[2] || path.join(cli, '..', 'server'));
if (!fs.existsSync(path.join(server, 'lib'))) { console.log(`No server checkout at ${server}: nothing to check.`); process.exit(0); }
const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry =>
	entry.name === 'node_modules' ? [] : entry.isDirectory() ? walk(path.join(dir, entry.name)) : /\.[cm]?js$/.test(entry.name) ? [path.join(dir, entry.name)] : []);
const used = new Map();
for (const file of ['lib', 'bin', 'test'].flatMap(d => fs.existsSync(path.join(server, d)) ? walk(path.join(server, d)) : [])) {
	const text = fs.readFileSync(file, 'utf8');
	for (const m of text.matchAll(/\bfad\(\s*['"]([\w./-]+)['"]\s*\)|require\(\s*['"]vigievuln\/lib\/([\w./-]+)['"]\s*\)/g)) {
		const name = (m[1] || m[2]).replace(/\.js$/, '');
		if (!used.has(name)) used.set(name, path.relative(server, file));
	}
}
const missing = [...used].filter(([name]) => !fs.existsSync(path.join(cli, 'lib', name + '.js')) && !fs.existsSync(path.join(cli, 'lib', name, 'index.js')));
console.log(`${used.size} CLI module(s) loaded by ${server}`);
for (const [name, file] of missing) console.error(`missing: lib/${name}.js (loaded by ${file})`);
process.exit(missing.length ? 1 : 0);
