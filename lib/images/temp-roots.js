'use strict';
// Extraction roots can hold a whole image. An interrupted scan (Ctrl-C, a caller's
// timeout) removes the ones still registered before the process ends; normal completion
// unregisters them through their own cleanup.
const fs = require('node:fs');
const roots = new Set();
let installed = false;

function removeAll() {
	for (const dir of roots) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort on the way out */ } }
	roots.clear();
}
function install() {
	if (installed) return;
	installed = true;
	for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
		process.once(signal, () => { removeAll(); process.exit(code); });
	}
}
function track(dir) { install(); roots.add(dir); return dir; }
function untrack(dir) { roots.delete(dir); }

module.exports = { track, untrack, removeAll };
