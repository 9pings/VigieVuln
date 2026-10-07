/**
 * Stream the JSON files out of a (possibly nested) zip without writing it to disk.
 *
 * CVEProject ships its daily baseline as a zip whose only member is another zip
 * (`…_all_CVEs_at_midnight.zip.zip`, ~620 MB): extracting it to disk takes several GB.
 * Here the download stream is decompressed on the fly — a member named *.zip is fed into
 * a nested reader — and each JSON member is handed to `onJson(name, value)` as soon as it
 * is complete. Memory stays at one member at a time.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { Unzip, UnzipInflate } = require("fflate");

const MAX_JSON_BYTES = 16 * 1024 * 1024;

function zipReader({ onJson, onError, depth = 0 }) {
	if (depth > 3) throw new Error("zip nesting too deep");
	const unzip = new Unzip(file => {
		if (/\.zip$/i.test(file.name)) {
			const inner = zipReader({ onJson, onError, depth: depth + 1 });
			file.ondata = (err, chunk, final) => {
				if (err) return onError(err);
				try { inner.push(chunk, final); } catch (e) { onError(e); }
			};
			file.start();
			return;
		}
		if (!/\.json$/i.test(file.name)) return;           // not started → skipped
		const chunks = [];
		let size = 0;
		file.ondata = (err, chunk, final) => {
			if (err) return onError(err);
			size += chunk.length;
			if (size > MAX_JSON_BYTES) return;               // oversized member: ignored
			chunks.push(chunk);
			if (!final) return;
			let value;
			try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
			catch { return; }                                // malformed member: skipped
			try { onJson(file.name, value); } catch (e) { onError(e); }
		};
		file.start();
	});
	unzip.register(UnzipInflate);
	return { push: (chunk, final) => unzip.push(chunk, final) };
}

/**
 * Feed an async-iterable of Uint8Array chunks (a fetch body, a file stream). `afterChunk`
 * is awaited after each chunk: the place for an async consumer to drain what onJson
 * collected (the database writes then pace the download).
 */
async function forEachJsonInZip(source, onJson, { afterChunk = null } = {}) {
	let failure = null;
	const reader = zipReader({ onJson, onError: e => { failure ||= e; } });
	for await (const chunk of source) {
		reader.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk), false);
		if (failure) throw failure;
		if (afterChunk) await afterChunk();
	}
	reader.push(new Uint8Array(0), true);
	if (failure) throw failure;
}

module.exports = { forEachJsonInZip };
