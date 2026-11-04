'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');

test('Bun closes every prepared SQLite statement, including evicted statements', t => {
  const script = `
    const assert = require('node:assert/strict');
    const {openSqlite} = require(${JSON.stringify(path.resolve(__dirname, '../lib/sqlite-driver'))});
    const db = openSqlite(':memory:');
    const held = db.prepare('SELECT 1 AS value');
    for (let i = 0; i < 140; i++) db.prepare('SELECT ' + (i + 2) + ' AS value').get();
    assert.equal(held.get().value, 1);
    db.close();
    assert.throws(() => held.get());
  `;
  const result = spawnSync('bun', ['-e', script], {encoding:'utf8'});
  if (result.error?.code === 'ENOENT') return t.skip('Bun is not installed');
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
