/**
 * Stream the items of one top-level JSON array without parsing the whole document.
 *
 * The NVD feed of a recent year is a single ~500 MB JSON document ({ …, "cve_items": [ … ] });
 * JSON.parse on it needs several GB. This scanner walks the text once, string- and
 * escape-aware, and hands each array item to `onItem(value)` as soon as it closes, so
 * memory stays at one item. Pure JS, no dependency.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { StringDecoder } = require("node:string_decoder");

/**
 * @param source async-iterable of Buffer/Uint8Array chunks
 * @param key    the name of the array property to stream ("cve_items")
 */
async function forEachArrayItem(source, key, onItem, { afterChunk = null } = {}) {
	const decoder = new StringDecoder("utf8");
	const marker = `"${key}"`;
	let phase = "seek";            // seek → open → items → done
	let head = "";                 // text kept while seeking the marker
	let depth = 0, inString = false, escape = false;
	let parts = [], start = -1, count = 0;

	const feed = text => {
		let i = 0;
		if (phase === "seek") {
			head += text;
			const at = head.indexOf(marker);
			if (at < 0) { head = head.slice(-marker.length); return; }
			text = head.slice(at + marker.length); head = ""; phase = "open"; i = 0;
		}
		if (phase === "open") {
			const b = text.indexOf("[");
			if (b < 0) return;
			text = text.slice(b + 1); phase = "items"; i = 0;
		}
		if (phase !== "items") return;
		start = depth > 0 ? 0 : -1;
		for (; i < text.length; i++) {
			const c = text.charCodeAt(i);
			if (inString) {
				if (escape) escape = false;
				else if (c === 92) escape = true;            // \
				else if (c === 34) inString = false;         // "
				continue;
			}
			if (c === 34) { inString = true; continue; }
			if (c === 123 || c === 91) {                     // { [
				if (depth === 0) { start = i; parts = []; }
				depth++;
			} else if (c === 125 || c === 93) {              // } ]
				if (depth === 0) { phase = "done"; return; } // the array itself closes
				depth--;
				if (depth === 0) {
					parts.push(text.slice(start, i + 1));
					const raw = parts.join(""); parts = []; start = -1;
					onItem(JSON.parse(raw));
					count++;
				}
			}
		}
		if (depth > 0) parts.push(text.slice(start));
	};

	for await (const chunk of source) {
		feed(decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
		if (afterChunk) await afterChunk();
		if (phase === "done") break;
	}
	feed(decoder.end());
	if (phase === "seek") throw new Error(`no "${key}" array in the document`);
	return count;
}

module.exports = { forEachArrayItem };
