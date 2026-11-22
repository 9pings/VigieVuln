'use strict';

const fs = require('node:fs');
const path = require('node:path').posix;
const { safeFile } = require('../system-inventory/collect');

// Read installed build configuration as data, never as a script. Both the
// expected layout and linker identity must agree with the observed launcher.
function installedVersion(root, location, metadata, product) {
  const needed = metadata.needed || [];
  if (!product || !location || path.basename(path.dirname(location)) !== 'bin') return null;
  const prefix = path.dirname(path.dirname(location));
  function text(relative) {
    const file = safeFile(root, path.join(prefix, relative));
    if (!file) return '';
    const stat = fs.statSync(file);
    return stat.isFile() && stat.size <= 128 * 1024 ? fs.readFileSync(file, 'utf8') : '';
  }
  if (product.id === 'java' && needed.includes('libjli.so')) {
    const release = text('release');
    const version = /^JAVA_VERSION="(\d[\w.+-]{0,50})"\r?$/m.exec(release)?.[1];
    if (version && /^IMPLEMENTOR="[^"\r\n]+"\r?$/m.test(release))
      return { id: 'java', version, source: 'jdk-release', path: path.join(prefix, 'release') };
  }
  if (product.id === 'tcl') {
    for (const soname of needed) {
      const match = /^libtcl(\d+\.\d+)\.so(?:\.\d+)*$/.exec(soname);
      if (!match) continue;
      const config = path.join('lib', 'tcl' + match[1], 'tclConfig.sh');
      const doc = text(config);
      const minor = /^TCL_VERSION='(\d+\.\d+)'\r?$/m.exec(doc)?.[1];
      const patch = /^TCL_PATCH_LEVEL='(\.\d+)'\r?$/m.exec(doc)?.[1];
      if (match[1] === minor && patch && /^TCL_LIB_FILE='([^'\r\n]+)'\r?$/m.exec(doc)?.[1] === soname)
        return {
          id: 'tcl',
          version: minor + patch,
          source: 'tcl-build-config',
          path: path.join(prefix, config)
        };
    }
  }
  return null;
}
module.exports = { installedVersion };
