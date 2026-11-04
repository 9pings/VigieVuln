// Extract untrusted PE VERSIONINFO strings without loading or executing the image.
// Every offset and length is checked against the file/resource bounds. Malformed
// resources are treated as absent; no identity or vulnerability is inferred here.
const MAX_RESOURCE = 64 * 1024 * 1024;
const MAX_VERSION_INFO = 1024 * 1024;

function extractPeMetadata(buf) {
	try {
		const ok = (p, n, end = buf.length) => Number.isSafeInteger(p) && p >= 0 && n >= 0 && p + n <= end;
		const u16 = p => { if (!ok(p, 2)) throw Error('bounds'); return buf.readUInt16LE(p); };
		const u32 = p => { if (!ok(p, 4)) throw Error('bounds'); return buf.readUInt32LE(p); };
		if (!ok(0, 64) || buf.toString('ascii', 0, 2) !== 'MZ') return null;
		const pe = u32(0x3c);
		if (!ok(pe, 24) || buf.toString('binary', pe, pe + 4) !== 'PE\0\0') return null;
		const sections = u16(pe + 6), optSize = u16(pe + 20), opt = pe + 24;
		if (sections > 96 || !ok(opt, optSize)) return null;
		const magic = u16(opt), dir = opt + (magic === 0x10b ? 96 : magic === 0x20b ? 112 : optSize);
		if (dir + 24 > opt + optSize) return null;
		const resourceRva = u32(dir + 16), resourceSize = u32(dir + 20);
		if (!resourceRva || !resourceSize || resourceSize > MAX_RESOURCE) return null;
		const sec = opt + optSize;
		if (!ok(sec, sections * 40)) return null;
		function rvaOffset(rva, length) {
			for (let i = 0; i < sections; i++) {
				const p = sec + i * 40, va = u32(p + 12), rawSize = u32(p + 16), raw = u32(p + 20);
				const delta = rva - va;
				if (delta >= 0 && delta + length <= rawSize && ok(raw + delta, length)) return raw + delta;
			}
			return null;
		}
		const root = rvaOffset(resourceRva, resourceSize);
		if (root === null) return null;
		const end = root + resourceSize;
		let directoryCount = 0;
		function directory(offset) {
			if (++directoryCount > 256) throw Error('too many directories');
			const p = root + offset;
			if (!ok(p, 16, end)) throw Error('directory');
			const count = u16(p + 12) + u16(p + 14);
			if (count > 1024 || !ok(p + 16, count * 8, end)) throw Error('entries');
			return Array.from({length: count}, (_, i) => [u32(p + 16 + i * 8), u32(p + 20 + i * 8)]);
		}
		const version = directory(0).find(([id, ref]) => id === 16 && (ref & 0x80000000));
		if (!version) return null;
		const values = [];
		for (const [, nameRef] of directory(version[1] & 0x7fffffff)) {
			if (!(nameRef & 0x80000000)) continue;
			for (const [, langRef] of directory(nameRef & 0x7fffffff)) {
				if (langRef & 0x80000000) continue;
				const entry = root + langRef;
				if (!ok(entry, 16, end)) continue;
				const size = u32(entry + 4), data = rvaOffset(u32(entry), size);
				if (data === null || size > MAX_VERSION_INFO || size < 6) continue;
				const strings = {};
				const align = n => Math.ceil(n / 4) * 4;
				function block(p, limit, depth) {
					if (depth > 5 || !ok(p, 6, limit)) return;
					const length = u16(p), valueLength = u16(p + 2), type = u16(p + 4), stop = p + length;
					if (length < 6 || stop > limit) return;
					let q = p + 6;
					while (ok(q, 2, stop) && u16(q) !== 0) q += 2;
					if (!ok(q, 2, stop)) return;
					const key = buf.toString('utf16le', p + 6, q); q = align(q + 2);
					const bytes = type === 1 ? valueLength * 2 : valueLength;
					if (!ok(q, bytes, stop)) return;
					if (type === 1 && key.length <= 256 && bytes > 0 && bytes <= 8192)
						Object.defineProperty(strings, key, { value: buf.toString('utf16le', q, q + bytes).replace(/\0+$/, ''), enumerable: true, configurable: true, writable: true });
					q = align(q + bytes);
					while (ok(q, 6, stop)) { const n = u16(q); if (!n || q + n > stop) break; block(q, stop, depth + 1); q = align(q + n); }
				}
				block(data, data + size, 0);
				if (Object.keys(strings).length) values.push(strings);
			}
		}
		return values.length ? { versionStrings: values } : null;
	} catch { return null; }
}

// Adapt the bounded parser to a file descriptor. One 64 KiB cache serves the
// many small header/string reads; even a distant resource never loads the file.
function extractPeMetadataFile(fd, size) {
	const fs = require("node:fs");
	let start = -1, cache = Buffer.alloc(0);
	const read = (offset, length) => {
		if (!Number.isSafeInteger(offset) || offset < 0 || length < 0 || length > MAX_VERSION_INFO || offset + length > size) throw Error("bounds");
		if (offset < start || offset + length > start + cache.length) {
			start = offset;
			cache = Buffer.alloc(Math.min(size - offset, Math.max(64 * 1024, length)));
			let count = 0;
			while (count < cache.length) {
				const n = fs.readSync(fd, cache, count, cache.length - count, start + count);
				if (!n) throw Error("unexpected EOF reading PE metadata");
				count += n;
			}
		}
		return cache.subarray(offset - start, offset - start + length);
	};
	return extractPeMetadata({ length: size,
		readUInt16LE: offset => read(offset, 2).readUInt16LE(0),
		readUInt32LE: offset => read(offset, 4).readUInt32LE(0),
		toString: (encoding, begin, end) => read(begin, end - begin).toString(encoding),
	});
}

module.exports = { extractPeMetadata, extractPeMetadataFile };
