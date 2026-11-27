'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

module.exports = function assertCancelled(result, paths = []) {
 const log = [result.stderr,result.stdout,result.output].filter(Boolean).join('\n');
 assert.equal(result.status,2,log);
 assert.match(log,/Scan cancelled|Scan annulé/);
 for (const path of paths) assert.equal(fs.existsSync(path),false,path);
 return log;
};
