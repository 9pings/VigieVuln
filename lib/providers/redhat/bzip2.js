'use strict';
// bzip2 decompression. Red Hat publishes its OVAL definitions only as .bz2 and Node has no
// decoder for that format. Decoding is block by block (at most 900 kB of state), each block
// and each stream is checked against its CRC, and every length read from the input is
// bounded before use. Reference: the bzip2 1.0 format (Julian Seward).
const BLOCK_MAGIC_HI = 0x314159, BLOCK_MAGIC_LO = 0x265359, END_MAGIC_HI = 0x177245, END_MAGIC_LO = 0x385090;
const MAX_GROUPS = 6, GROUP_SIZE = 50, MAX_CODE_LENGTH = 20, RUN_A = 0, RUN_B = 1;
const CRC = (() => {
	const table = new Int32Array(256);
	for (let i = 0; i < 256; i++) { let c = i << 24; for (let k = 0; k < 8; k++) c = c < 0 ? (c << 1) ^ 0x04c11db7 : c << 1; table[i] = c; }
	return table;
})();
const corrupt = what => Error(`invalid bzip2 data: ${what}`);

class Bits {
	constructor(bytes) { this.bytes = bytes; this.offset = 0; this.held = 0; this.count = 0; }
	// Up to 24 bits, most significant first.
	read(n) {
		while (this.count < n) {
			if (this.offset >= this.bytes.length) throw corrupt('unexpected end of input');
			this.held = ((this.held << 8) | this.bytes[this.offset++]) >>> 0; this.count += 8;
		}
		this.count -= n;
		const value = (this.held >>> this.count) & ((1 << n) - 1);
		this.held &= (1 << this.count) - 1;
		return value;
	}
	align() { this.held = 0; this.count = 0; }
	get remaining() { return this.bytes.length - this.offset; }
}

function decodeTables(lengths, alphabet) {
	let min = MAX_CODE_LENGTH, max = 0;
	for (let i = 0; i < alphabet; i++) { if (lengths[i] > max) max = lengths[i]; if (lengths[i] < min) min = lengths[i]; }
	const perm = new Uint16Array(alphabet), base = new Int32Array(MAX_CODE_LENGTH + 2), limit = new Int32Array(MAX_CODE_LENGTH + 2);
	let next = 0;
	for (let length = min; length <= max; length++) for (let symbol = 0; symbol < alphabet; symbol++) if (lengths[symbol] === length) perm[next++] = symbol;
	const counts = new Int32Array(MAX_CODE_LENGTH + 2);
	for (let i = 0; i < alphabet; i++) counts[lengths[i] + 1]++;
	for (let i = 1; i < counts.length; i++) counts[i] += counts[i - 1];
	// counts[length] is now the number of symbols with a shorter code. limit[length] is the
	// largest code of that length; base[length] turns a code of that length into its rank in perm.
	let code = 0;
	for (let length = min; length <= max; length++) {
		code += counts[length + 1] - counts[length];
		limit[length] = code - 1;
		code <<= 1;
	}
	for (let length = min; length <= max; length++) base[length] = (length === min ? 0 : ((limit[length - 1] + 1) << 1)) - counts[length];
	return { perm, base, limit, min, max };
}

function readBlock(bits, blockSize, tt) {
	const storedCrc = (bits.read(16) << 16 | bits.read(16)) | 0;
	if (bits.read(1)) throw corrupt('randomised blocks are not supported');
	const origin = bits.read(24);
	// Symbols in use.
	const used = bits.read(16), symbols = [];
	for (let group = 0; group < 16; group++) if (used & (0x8000 >> group)) {
		const map = bits.read(16);
		for (let k = 0; k < 16; k++) if (map & (0x8000 >> k)) symbols.push(group * 16 + k);
	}
	if (!symbols.length) throw corrupt('block without symbols');
	const alphabet = symbols.length + 2, endOfBlock = symbols.length + 1;
	const groups = bits.read(3), selectorCount = bits.read(15);
	if (groups < 2 || groups > MAX_GROUPS || selectorCount < 1) throw corrupt('coding tables');
	const order = Array.from({ length: groups }, (_, i) => i), selectors = new Uint8Array(selectorCount);
	for (let i = 0; i < selectorCount; i++) {
		let j = 0;
		while (bits.read(1)) if (++j >= groups) throw corrupt('selector');
		const chosen = order[j]; order.splice(j, 1); order.unshift(chosen);
		selectors[i] = chosen;
	}
	const tables = [];
	for (let t = 0; t < groups; t++) {
		const lengths = new Uint8Array(alphabet);
		let length = bits.read(5);
		for (let i = 0; i < alphabet; i++) {
			for (;;) {
				if (length < 1 || length > MAX_CODE_LENGTH) throw corrupt('code length');
				if (!bits.read(1)) break;
				length += bits.read(1) ? -1 : 1;
			}
			lengths[i] = length;
		}
		tables.push(decodeTables(lengths, alphabet));
	}
	// Huffman → move-to-front and zero-run decoding, straight into the BWT vector.
	const mtf = Uint8Array.from({ length: 256 }, (_, i) => i), counts = new Int32Array(256);
	let length = 0, group = -1, left = 0, table = null;
	const symbol = () => {
		if (!left) { if (++group >= selectorCount) throw corrupt('selector overrun'); table = tables[selectors[group]]; left = GROUP_SIZE; }
		left--;
		let size = table.min, code = bits.read(size);
		while (code > table.limit[size]) { if (++size > table.max) throw corrupt('Huffman code'); code = (code << 1) | bits.read(1); }
		const index = code - table.base[size];
		if (index < 0 || index >= alphabet) throw corrupt('Huffman code');
		return table.perm[index];
	};
	let next = symbol();
	while (next !== endOfBlock) {
		if (next === RUN_A || next === RUN_B) {
			let run = 0, weight = 1;
			do { run += next === RUN_A ? weight : 2 * weight; weight *= 2; if (run > blockSize) throw corrupt('run length'); next = symbol(); } while (next === RUN_A || next === RUN_B);
			const byte = symbols[mtf[0]];
			if (length + run > blockSize) throw corrupt('block overflow');
			counts[byte] += run;
			tt.fill(byte, length, length + run); length += run;
			continue;
		}
		const position = next - 1, value = mtf[position];
		mtf.copyWithin(1, 0, position); mtf[0] = value;
		const byte = symbols[value];
		if (length >= blockSize) throw corrupt('block overflow');
		counts[byte]++; tt[length++] = byte;
		next = symbol();
	}
	if (origin >= length) throw corrupt('origin pointer');
	// Inverse Burrows–Wheeler transform.
	let sum = 0;
	for (let i = 0; i < 256; i++) { const count = counts[i]; counts[i] = sum; sum += count; }
	for (let i = 0; i < length; i++) { const byte = tt[i] & 0xff; tt[counts[byte]++] |= i << 8; }
	// Undo the initial run-length encoding (four equal bytes, then a count) and check the CRC.
	let out = Buffer.allocUnsafe(Math.max(1024, length + (length >> 2))), written = 0, crc = -1;
	const emit = (byte, times) => {
		if (written + times > out.length) { const larger = Buffer.allocUnsafe(Math.max(out.length * 2, written + times)); out.copy(larger, 0, 0, written); out = larger; }
		for (let k = 0; k < times; k++) { out[written++] = byte; crc = (crc << 8) ^ CRC[((crc >>> 24) ^ byte) & 0xff]; }
	};
	let position = tt[origin] >>> 8, previous = -1, repeat = 0;
	for (let i = 0; i < length; i++) {
		const entry = tt[position], byte = entry & 0xff;
		position = entry >>> 8;
		if (repeat === 4) { emit(previous, byte); repeat = 0; previous = -1; continue; }
		emit(byte, 1);
		if (byte === previous) repeat++; else { previous = byte; repeat = 1; }
	}
	if ((~crc | 0) !== storedCrc) throw corrupt('block checksum');
	return { data: out.subarray(0, written), crc: storedCrc };
}

/** Decompress a bzip2 buffer (one or several concatenated streams): yields decoded blocks. */
function* decompressBlocks(bytes) {
	const bits = new Bits(bytes);
	let streams = 0;
	while (bits.remaining > 0 || bits.count >= 8) {
		if (bits.read(8) !== 0x42 || bits.read(8) !== 0x5a || bits.read(8) !== 0x68) { if (streams) return; throw corrupt('not a bzip2 stream'); }
		const level = bits.read(8) - 0x30;
		if (level < 1 || level > 9) throw corrupt('block size');
		const blockSize = level * 100000, tt = new Uint32Array(blockSize);
		let combined = 0;
		for (;;) {
			const high = bits.read(24), low = bits.read(24);
			if (high === BLOCK_MAGIC_HI && low === BLOCK_MAGIC_LO) {
				const block = readBlock(bits, blockSize, tt);
				combined = ((combined << 1) | (combined >>> 31)) ^ block.crc;
				yield block.data;
			} else if (high === END_MAGIC_HI && low === END_MAGIC_LO) {
				const stored = (bits.read(16) << 16 | bits.read(16)) | 0;
				if (stored !== (combined | 0)) throw corrupt('stream checksum');
				break;
			} else throw corrupt('block header');
		}
		bits.align(); streams++;
	}
}

module.exports = { decompressBlocks };
