'use strict';

const { catalog, binaryProduct } = require('./product-catalog');
const codecs = new Map(
  [...catalog.values()].filter((product) => product.elfCodec).map((product) => [product.elfCodec, product])
);
const libraries = [...catalog.values()].filter((product) => product.library);
function libraryProduct(name) {
  return libraries.find((product) => product.library.test(name));
}

function sectionsOf({ read, header, bits, word, u16, u32, max }) {
  const wide = bits === 64,
    stride = u16(header, wide ? 58 : 46),
    count = u16(header, wide ? 60 : 48);
  if (!count || count > 4096 || stride < (wide ? 64 : 40) || stride * count > max) return [];
  const table = read(word(header, wide ? 40 : 32), stride * count);
  return Array.from({ length: count }, (_, i) => {
    const p = i * stride;
    return {
      name: u32(table, p),
      type: u32(table, p + 4),
      offset: word(table, p + (wide ? 24 : 16)),
      size: word(table, p + (wide ? 32 : 20)),
      link: u32(table, p + (wide ? 40 : 24)),
      entry: word(table, p + (wide ? 56 : 36))
    };
  });
}

function bunGraph(elf, sections) {
  const trailer = Buffer.from('\n---- Bun! ----\n');
  if (elf.size >= 24) {
    const end = elf.read(elf.size - 24, 24);
    if (end.subarray(0, 16).equals(trailer) && end.readBigUInt64LE(16) === BigInt(elf.size)) return true;
  }
  const names = sections[elf.u16(elf.header, elf.bits === 64 ? 62 : 50)];
  if (!names || names.size > 65536) return false;
  const strings = elf.read(names.offset, names.size);
  for (const section of sections) {
    if (
      section.type !== 1 ||
      strings.toString('latin1', section.name, section.name + 5) !== '.bun\0' ||
      section.size < 32
    )
      continue;
    const len = elf.read(section.offset, 8).readBigUInt64LE();
    if (
      len >= 24n &&
      len <= BigInt(section.size - 8) &&
      elf.read(section.offset + 8 + Number(len) - 16, 16).equals(trailer)
    )
      return true;
  }
  return false;
}

function symbolBytes(elf, sections, wanted) {
  const wide = elf.bits === 64,
    result = new Map();
  for (const section of sections) {
    if (section.type !== 11) continue;
    const strings = sections[section.link];
    if (
      strings?.type !== 3 ||
      section.entry !== (wide ? 24 : 16) ||
      section.size % section.entry ||
      Math.max(section.size, strings.size) > elf.max
    )
      continue;
    const names = elf.read(strings.offset, strings.size);
    if (!wanted.every((name) => names.includes(name + '\0'))) continue;
    const symbols = elf.read(section.offset, section.size);
    for (let j = 0; j < symbols.length; j += section.entry) {
      const start = elf.u32(symbols, j);
      const end = names.subarray(start, start + 49).indexOf(0) + start;
      if (end < start || end - start > 48) continue;
      const name = names.toString('latin1', start, end);
      if (!wanted.includes(name) || !elf.u16(symbols, j + (wide ? 6 : 14))) continue;
      const type = symbols[j + (wide ? 4 : 12)];
      if (!(type >> 4) || (type & 15) !== (name === 'Py_Version' ? 1 : 2)) continue;
      const length = elf.word(symbols, j + (wide ? 16 : 8));
      if (length < 1 || length > 32) continue;
      result.set(name, elf.read(elf.mapped(elf.word(symbols, j + (wide ? 8 : 4)), length), length));
    }
  }
  return result;
}

function constantReturn(bytes, machine) {
  if (!bytes) return;
  // Entire leaf function must be a literal return. No machine code is run.
  if (machine === 62 || machine === 3) {
    if (bytes.subarray(0, 4).equals(Buffer.from([0xf3, 0x0f, 0x1e, machine === 62 ? 0xfa : 0xfb])))
      bytes = bytes.subarray(4);
    if (bytes.equals(Buffer.from([0x31, 0xc0, 0xc3]))) return 0;
    if (bytes.length === 6 && bytes[0] === 0xb8 && bytes[5] === 0xc3) return bytes.readUInt32LE(1);
  }
  if (machine === 183 && bytes.length === 8 && bytes.readUInt32LE(4) === 0xd65f03c0) {
    const mov = bytes.readUInt32LE(0);
    if ((mov & 0xffe0001f) >>> 0 === 0x52800000) return (mov >>> 5) & 0xffff;
  }
}

function exportedVersion(product, elf, sections) {
  if (product.elfCodec === 'py-version') {
    const bytes = symbolBytes(elf, sections, ['Py_Version']).get('Py_Version');
    if (!bytes || ![4, 8].includes(bytes.length)) return;
    const hex = bytes.length === 4 ? elf.u32(bytes, 0) : elf.word(bytes, 0);
    if (hex <= 0xffffffff && hex >>> 24 === 3 && (hex & 255) === 0xf0)
      return {
        id: product.id,
        version: [hex >>> 24, (hex >>> 16) & 255, (hex >>> 8) & 255].join('.'),
        source: 'Py_Version'
      };
  }
  if (['webkit-version', 'jsc-version'].includes(product.elfCodec)) {
    const prefix = product.elfCodec === 'jsc-version' ? 'jsc' : 'webkit';
    const names = ['major', 'minor', 'micro'].map((part) => prefix + '_get_' + part + '_version');
    const symbols = symbolBytes(elf, sections, names);
    const parts = names.map((name) => constantReturn(symbols.get(name), elf.machine));
    if (parts.every((n) => Number.isInteger(n) && n <= 65535) && parts[0] > 0)
      return { id: product.id, version: parts.join('.'), source: prefix + ' version API' };
  }
}

// For renamed/embedded Node, bind the inspector version to the release archive
// compiled into Node. Compatibility strings in another JS engine do not suffice.
function embeddedEngines(elf, product) {
  const tags = new Set(),
    releases = new Set();
  const jsc = codecs.get('jsc-build');
  const markers = new Set(jsc.elfBuildMarkers);
  const checkNode = !['node-release', 'bun-standalone'].includes(product?.elfCodec);
  const checkJsc = !['jsc-version', 'webkit-version'].includes(product?.elfCodec);
  let registered = false;
  if (!checkNode && !checkJsc) return [];
  for (const chunk of readonlyChunks(elf)) {
    if (checkJsc) for (const marker of markers) if (chunk.includes(marker)) markers.delete(marker);
    if (!checkNode) {
      if (!markers.size) break;
      continue;
    }
    if (chunk.includes('node_module_register\0')) registered = true;
    if (tags.size <= 1 && chunk.includes('node.js/v'))
      for (const m of chunk.matchAll(/\0node\.js\/v(\d+\.\d+\.\d+)(?=\0)/g)) {
        tags.add(m[1]);
        if (tags.size > 1) break;
      }
    if (releases.size <= 1 && chunk.includes('nodejs.org/download/release/'))
      for (const m of chunk.matchAll(
        /https:\/\/nodejs\.org\/download\/release\/v(\d+\.\d+\.\d+)\/node-v\1\.tar\.gz\0/g
      )) {
        releases.add(m[1]);
        if (releases.size > 1) break;
      }
  }
  const products = [],
    [version] = tags;
  if (registered && tags.size === 1 && releases.size === 1 && releases.has(version))
    products.push({ id: codecs.get('node-release').id, version, source: 'node-release-and-inspector' });
  if (checkJsc && !markers.size) products.push({ id: jsc.id, version: null, source: 'jsc-build-markers' });
  return products;
}

function* readonlyChunks(elf) {
  let remaining = elf.size;
  for (const segment of elf.segments.filter((s) => s.type === 1 && !(s.flags & 2))) {
    if (segment.filesz > remaining) throw Error('overlapping ELF load segments');
    remaining -= segment.filesz;
    let tail = '';
    const step = Math.min(256 * 1024, elf.max);
    for (let pos = 0; pos < segment.filesz; pos += step) {
      const data =
        tail + elf.read(segment.offset + pos, Math.min(step, segment.filesz - pos)).toString('latin1');
      yield data;
      tail = data.slice(-160);
    }
  }
}

function embeddedProducts(name, elf) {
  const sections = sectionsOf(elf);
  const bundled = bunGraph(elf, sections);
  const product = bundled
    ? codecs.get('bun-standalone')
    : binaryProduct(name) ||
      libraryProduct(name) ||
      binaryProduct(elf.soname) ||
      libraryProduct(elf.soname || '');
  const products = elf.size >= 1024 * 1024 ? embeddedEngines(elf, product) : [];
  if (!product) return products;
  const exported = exportedVersion(product, elf, sections);
  if (exported) products.push(exported);
  if (!product.banner) return products;
  // Read only mapped, read-only data. Small overlapping chunks also handle
  // signatures spanning a read boundary without loading an entire executable.
  const versions = new Set();
  for (const data of readonlyChunks(elf)) {
    for (const match of data.matchAll(product.banner)) {
      const version = match.slice(1).join('.');
      if (version.length <= 40) versions.add(version);
      if (versions.size > 1) return products;
    }
  }
  if (versions.size)
    products.push({
      id: product.id,
      version: [...versions][0],
      source: bundled ? 'bun-module-graph' : 'embedded-version-banner'
    });
  else if (bundled) products.push({ id: 'bun', version: null, source: 'bun-module-graph' });
  return products;
}
module.exports = { embeddedProducts, libraryProduct };
