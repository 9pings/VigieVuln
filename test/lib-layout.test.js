'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const lib = path.join(__dirname, '..', 'lib');

// lib/README.md is the guide to the layout. Only what a reader needs to find first lives
// at the root of lib/: command entry points, option resolution, configuration.
const ROOT = ['cli-collect.js', 'cli-command-routing.js', 'cli-groups.js', 'cli-image.js', 'cli-project-commands.js',
	'cli-setup.js', 'cli-watch.js', 'config.js', 'options-env.js', 'source-input.js', 'ui.js'];

test('only entry points and configuration live at the root of lib/', () => {
	const files = fs.readdirSync(lib, { withFileTypes: true }).filter(e => e.isFile()).map(e => e.name).sort();
	assert.deepEqual(files, [...ROOT, 'README.md'].sort(), 'a new module belongs in the folder of its theme (see lib/README.md)');
	const guide = fs.readFileSync(path.join(lib, 'README.md'), 'utf8');
	for (const name of ROOT) assert.ok(guide.includes('`' + name + '`'), `${name} is described in lib/README.md`);
	for (const entry of fs.readdirSync(lib, { withFileTypes: true }).filter(e => e.isDirectory()))
		assert.ok(guide.includes('`' + entry.name + '/`'), `lib/${entry.name}/ is described in lib/README.md`);
});

test('a data source keeps its request descriptor and its own code in one folder', () => {
	const providers = path.join(lib, 'providers');
	const shared = fs.readdirSync(providers, { withFileTypes: true }).filter(e => e.isFile()).map(e => e.name).sort();
	assert.deepEqual(shared, ['common.js', 'index.js', 'proxy-throttle.js', 'registries.js', 'request-failure.js'], 'files at the root of providers/ serve every source');
});

test('every path the package exports resolves to a file', () => {
	const pkg = require('../package.json');
	for (const [key, target] of Object.entries(pkg.exports)) {
		if (key.includes('*')) continue;
		assert.ok(fs.statSync(path.join(__dirname, '..', target)).isFile(), `${key} → ${target}`);
		if (key.startsWith('./lib/')) assert.equal(require.resolve('vigievuln/' + key.slice(2)), path.join(__dirname, '..', target));
	}
	assert.equal(require('vigievuln/package.json').name, 'vigievuln');
	assert.equal(typeof require('vigievuln/lib/providers/nvd/index').build, 'function', 'a real path resolves without an entry');
});
