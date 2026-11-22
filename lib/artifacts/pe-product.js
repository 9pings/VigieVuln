'use strict';

const { catalog } = require('./product-catalog');
const normalize = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');
const listed = (values, value) => !!value && values?.some((v) => normalize(v) === normalize(value));

// Read one PE's own StringFileInfo tables. Exact product and publisher/original
// filename must agree within a table. Never borrow the enclosing EXE's version.
function versionResource(tables) {
  const identities = new Set(),
    versions = new Set();
  for (const table of tables || []) {
    const product = [...catalog.values()].find(
      (p) =>
        listed(p.peVersionInfo?.names, table.ProductName) &&
        (listed(p.peVersionInfo?.originals, table.OriginalFilename) ||
          listed(p.peVersionInfo?.vendors, table.CompanyName))
    );
    if (!product) return null;
    identities.add(product.id);
    const version = String(table.ProductVersion || '').trim();
    versions.add(/^\d+(?:\.\d+){1,3}$/.test(version) && version.length <= 40 ? version : null);
  }
  if (identities.size !== 1) return null;
  const [id] = identities;
  return { id, version: versions.size === 1 ? [...versions][0] : null, source: 'pe-version-info' };
}
module.exports = { versionResource };
