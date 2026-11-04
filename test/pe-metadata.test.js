const test = require('node:test');
const assert = require('node:assert/strict');
const { extractPeMetadata } = require('../lib/codecs/binary/pe-metadata');
const { buildInventory } = require('../lib/unmanaged');

function block(key, value, children = [], type = 1) {
	const head = Buffer.alloc(6), name = Buffer.from(key + '\0', 'utf16le');
	const align = b => Buffer.concat([b, Buffer.alloc((4 - b.length % 4) % 4)]);
	let data = align(Buffer.concat([head, name]));
	const bytes = value ? Buffer.from(value + '\0', 'utf16le') : Buffer.alloc(0);
	data = align(Buffer.concat([data, bytes]));
	for (const child of children) data = align(Buffer.concat([data, child]));
	data.writeUInt16LE(data.length, 0);
	data.writeUInt16LE(bytes.length / 2, 2);
	data.writeUInt16LE(type, 4);
	return data;
}
function fixture() {
	const version = block('VS_VERSION_INFO', '', [block('StringFileInfo', '', [block('040904b0', '', [
		block('ProductName', 'Example'), block('ProductVersion', '1.2.3'), block('CompanyName', 'Example Corp'),
	])])], 0);
	const b = Buffer.alloc(2048);
	b.write('MZ'); b.writeUInt32LE(0x80, 0x3c); b.write('PE\0\0', 0x80, 'binary');
	b.writeUInt16LE(1, 0x86); b.writeUInt16LE(224, 0x94); b.writeUInt16LE(0x10b, 0x98);
	b.writeUInt32LE(0x1000, 0x98 + 112); b.writeUInt32LE(1024, 0x98 + 116);
	const sec = 0x98 + 224; b.writeUInt32LE(0x1000, sec + 12); b.writeUInt32LE(1024, sec + 16); b.writeUInt32LE(512, sec + 20);
	const r = 512;
	b.writeUInt16LE(1, r + 14); b.writeUInt32LE(16, r + 16); b.writeUInt32LE(0x80000018, r + 20);
	b.writeUInt16LE(1, r + 24 + 14); b.writeUInt32LE(1, r + 40); b.writeUInt32LE(0x80000030, r + 44);
	b.writeUInt16LE(1, r + 48 + 14); b.writeUInt32LE(1033, r + 64); b.writeUInt32LE(72, r + 68);
	b.writeUInt32LE(0x1100, r + 72); b.writeUInt32LE(version.length, r + 76); version.copy(b, r + 256);
	return b;
}
test('extracts version metadata and preserves it in the binary inventory', () => {
	const metadata = extractPeMetadata(fixture());
	assert.deepEqual(metadata.versionStrings[0], {ProductName: 'Example', ProductVersion: '1.2.3', CompanyName: 'Example Corp'});
	const inventory = buildInventory(new Map([['x', { provenance:'binary', hashes:{sha256:'a'}, binaryMetadata:metadata }]]));
	assert.deepEqual(inventory[0].binaryMetadata, metadata);
});
test('malformed and truncated PE files do not produce metadata or throw', () => {
	const b = fixture();
	for (let n = 0; n < b.length; n += 23) assert.doesNotThrow(() => extractPeMetadata(b.subarray(0, n)));
	b.writeUInt32LE(0xffffffff, 0x3c);
	assert.equal(extractPeMetadata(b), null);
	assert.equal(extractPeMetadata(Buffer.from('MZ\0\0')), null);
});

test('file-backed metadata reader preserves VERSIONINFO in a distant resource without full-file allocation', t => {
	const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vv-pe-resource-'));
	t.after(() => fs.rmSync(dir, {recursive:true,force:true}));
	const original = fixture(), moved = Buffer.from(original);
	const offset = 16 * 1024 * 1024;
	moved.writeUInt32LE(offset, 0x98 + 224 + 20);
	const fp = path.join(dir, 'distant.dll'), fd = fs.openSync(fp, 'w+');
	try {
		fs.writeSync(fd, moved.subarray(0, 512), 0, 512, 0);
		fs.writeSync(fd, original.subarray(512), 0, original.length - 512, offset);
		const { extractPeMetadataFile } = require('../lib/codecs/binary/pe-metadata');
		assert.deepEqual(extractPeMetadataFile(fd, fs.fstatSync(fd).size), extractPeMetadata(original));
	} finally { fs.closeSync(fd); }
});
