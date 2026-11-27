'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

// A scan with a non-fatal coverage gap publishes its report marked incomplete.
// `status` is the expected exit code: 0, or the gate's code when a gate also fails.
module.exports = function assertIncomplete(result, findingsPath, { status = 0 } = {}) {
 const log = [result.stderr,result.stdout,result.output].filter(Boolean).join('\n');
 assert.equal(result.status,status,log);
 assert.match(log,/Coverage incomplete|Couverture incomplète/);
 assert.doesNotMatch(log,/Scan cancelled|Scan annulé/);
 const doc = findingsPath ? JSON.parse(fs.readFileSync(findingsPath,'utf8')) : null;
 if (doc) assert.equal(doc.summary.scanReliable,false,'summary.scanReliable');
 return { log, doc };
};
