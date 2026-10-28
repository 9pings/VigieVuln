const { test } = require('node:test');
const assert = require('node:assert/strict');
const { releaseNotes } = require('../scripts/release-notes');

test('release notes include only the exact tagged section including subsections', () => {
  const history = '# Changelog\r\n\r\n## [1.1.0] — Unreleased\r\n\r\n### Added\r\n- New\r\n\r\n## [1.0.1] — old\r\n- Old\r\n\r\n# Predecessor\r\n- Legacy';
  assert.equal(releaseNotes(history, '1.1.0'), '### Added\n- New\n');
});

test('release notes fail closed for missing, duplicate, empty or invalid versions', () => {
  for (const [history, version] of [['## [1.0.0]\n- old', '1.1.0'], ['## [1.1.0]\n- a\n## [1.1.0]\n- b', '1.1.0'], ['## [1.1.0]\n\n## [1.0.0]', '1.1.0'], ['## [1.1.0]', '1.1.0.*']])
    assert.throws(() => releaseNotes(history, version));
});
