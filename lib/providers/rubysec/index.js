'use strict';
// The Ruby advisory database (rubysec/ruby-advisory-db): the data `bundler-audit` reads.
// One archive holds every advisory; no package name or version leaves the machine.
const ARCHIVE = 'https://codeload.github.com/rubysec/ruby-advisory-db/tar.gz/refs/heads/master';

module.exports = { id: 'rubysec', ttlMs: 4 * 3600 * 1000, build(type) {
	if (type !== 'advisory-db') throw Error('invalid Ruby advisory database request');
	return { url: ARCHIVE, init: { headers: { accept: 'application/gzip' } } };
} };
