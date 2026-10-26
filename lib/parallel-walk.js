/**
 * lib/parallel-walk.js — bounded-concurrency recursive directory walk.
 *
 * A serial readdirSync walk is fine on a fast local disk, but on a high-latency
 * filesystem (WSL/9p, network mounts, the air-gapped VM in the field) each readdir
 * pays a round-trip, so a big tree takes tens of seconds per walk — and vigievuln
 * walks the tree several times (detection, pom discovery, jar discovery, JS manifest
 * discovery). Issuing many readdirs concurrently turns that latency-bound serial walk
 * into something close to a single round-trip deep, which is dramatically faster.
 *
 * `onDir(absDir, entries)` is called once per visited directory with its Dirent[].
 * `skipDir(absChildDir, name)` prunes a child directory (caller's own skip policy);
 * it receives the child's absolute path (for path-relative globs) plus its basename.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");

const DEFAULT_CONCURRENCY = 48;

async function walkDirs(root, { skipDir = () => false, concurrency = DEFAULT_CONCURRENCY, onDir } = {}) {
	const queue = [root];
	let active = 0;
	await new Promise(resolve => {
		let settled = false;
		const finish = () => { if (!settled) { settled = true; resolve(); } };
		const pump = () => {
			if (settled) return;
			if (queue.length === 0 && active === 0) return finish();
			while (active < concurrency && queue.length) {
				const cur = queue.pop();
				active++;
				fs.promises.readdir(cur, { withFileTypes: true }).then(entries => {
					if (onDir) onDir(cur, entries);
					for (const e of entries) {
						if (!e.isDirectory()) continue;
						const child = path.join(cur, e.name);
						if (!skipDir(child, e.name)) queue.push(child);
					}
				}).catch(() => { /* unreadable dir → skip, same as readdirSync catch */ })
					.finally(() => { active--; pump(); });
			}
		};
		pump();
	});
}

module.exports = { walkDirs };
