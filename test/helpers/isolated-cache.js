const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after } = require('node:test');

// Install before loading product modules: resolving a default cache path can
// migrate a legacy home directory even when the scan later passes cacheDir.
module.exports = function isolatedCache(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `vv-${prefix}-root-`));
  const previous = os.homedir;
  os.homedir = () => root;
  require('../../lib/cache-directory').setActiveCacheDir(root);
  after(() => { os.homedir = previous; require('../../lib/cache-db').closeCacheDbs(); fs.rmSync(root, { recursive: true, force: true }); });
  return root;
};
