/**
 * lib/resource-cache/fs-store.js — the filesystem implementation of the resource store.
 *
 * The resource-cache engine (./engine.js) talks to its store through a small interface,
 * so the same engine runs on this directory store (serve-cache, the client-side local
 * cache) and on a database-backed store (vigievuln with SQLite or PostgreSQL):
 *
 *   get(key)                  → entry | null   (entry: { fetchedAt, ttlMs, contentType,
 *                                               responseHeaders, bytes, … })   may be async
 *   acquire(entry)            → release()      keep a body alive while it streams (sync)
 *   openBody(entry)           → Readable
 *   readBody(entry)           → Buffer         may be async
 *   createWriter()            → { account(n), sink(), bytes(), read(), commit(key, meta), detach(meta), abort() }
 *   put(key, buffer, meta)    store a body already in memory                   may be async
 *   purge(key)                → boolean
 *   claimOwner()              → release()      single-writer ownership (no-op for a shared DB)
 *   size(), clear()           optional: configureLimits, bodyBytes, diskBytes (quota accounting)
 *
 * This file keeps the original directory API (commit(key, tmpFile, meta), reserve,
 * retire, entriesDir, metaPath, …) used by --import-cache and the tests.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const DEFAULT_CACHE_DIR = () => path.join(os.homedir(), ".fad-checker-proxy-cache");
const TRANSIENT_KEEP_MS = 30 * 1000;

/**
 * Persistent resource-keyed store. The metadata is the commit marker and points to an
 * immutable, generation-specific body. A crash before the metadata rename leaves
 * the previous entry intact; a crash afterward leaves the new entry intact.
 * Older <hash>.body entries remain readable for compatibility.
 */
function createCacheStore(dir = DEFAULT_CACHE_DIR()) {
	const entriesDir = path.join(dir, "entries");
	fs.mkdirSync(entriesDir, { recursive: true });
	const hash = url => crypto.createHash("sha256").update(String(url)).digest("hex");
	const metaPath = h => path.join(entriesDir, h + ".json");
	const bodyPath = h => path.join(entriesDir, h + ".body");
	const readers = new Map();
	const retired = new Set();
	const bodySizes = new Map();
	let usedBytes = 0, maxStoreBytes = Infinity, maxEntries = Infinity;
	const forget = file => { usedBytes -= bodySizes.get(file) || 0; bodySizes.delete(file); };
	const retire = file => {
		if ((readers.get(file) || 0) > 0) { retired.add(file); return; }
		try { fs.rmSync(file, { force: true }); forget(file); } catch { /* keep an orphan, never harm the active entry */ }
	};

	return {
		dir, entriesDir, hash, metaPath, bodyPath,
		// Called only by a server with exclusive ownership of this directory.
		configureLimits(bytes, entries) {
			maxStoreBytes = bytes; maxEntries = entries;
			const referenced = new Set();
			for (const f of fs.readdirSync(entriesDir).filter(f => /^[a-f0-9]{64}\.json$/.test(f))) {
				try {
					const meta = JSON.parse(fs.readFileSync(path.join(entriesDir, f), "utf8"));
					const entry = this.get(meta.url);
					if (entry) { referenced.add(entry.bodyPath); referenced.add(path.join(entriesDir, f)); }
					else retire(path.join(entriesDir, f));
				} catch { retire(path.join(entriesDir, f)); }
			}
			for (const f of fs.readdirSync(entriesDir)) {
				const file = path.join(entriesDir, f);
				if (/^\.tmp-|\.json\.tmp/.test(f) || (/\.body(?:-[a-f0-9]+)?$/.test(f) && !referenced.has(file))) retire(file);
			}
			bodySizes.clear(); usedBytes = 0;
			for (const file of referenced) { const n = fs.statSync(file).size; bodySizes.set(file, n); usedBytes += n; }
			this.makeRoom(0);
		},
		makeRoom(extra, keepUrl = null, addingEntry = false) {
			if (maxStoreBytes === Infinity) return;
			if (usedBytes + extra <= maxStoreBytes && this.size() + (addingEntry ? 1 : 0) <= maxEntries) return;
			if (extra > maxStoreBytes) throw new Error("proxy store quota exceeded");
			const rows = [];
			for (const f of fs.readdirSync(entriesDir).filter(f => /^[a-f0-9]{64}\.json$/.test(f))) {
				try {
					const meta = JSON.parse(fs.readFileSync(path.join(entriesDir, f), "utf8"));
					const entry = this.get(meta.url);
					if (entry) rows.push(entry);
				} catch { /* corrupt metadata is not an eviction candidate */ }
			}
			let count = rows.length + (addingEntry ? 1 : 0);
			for (const entry of rows.sort((a, b) => a.fetchedAt - b.fetchedAt)) {
				if (usedBytes + extra <= maxStoreBytes && count <= maxEntries) break;
				if (entry.url === keepUrl || readers.has(entry.bodyPath)) continue;
				retire(metaPath(hash(entry.url)));
				retire(entry.bodyPath); count--;
			}
			if (usedBytes + extra > maxStoreBytes || count > maxEntries) throw new Error("proxy store quota exceeded (active readers are pinned)");
		},
		reserve(file, bytes) {
			if (maxStoreBytes === Infinity) return;
			if (usedBytes + bytes > maxStoreBytes) this.makeRoom(bytes);
			bodySizes.set(file, (bodySizes.get(file) || 0) + bytes); usedBytes += bytes;
		},
		diskBytes() { return usedBytes; },
		bodyBytes() { return [...bodySizes].reduce((n, [file, bytes]) => n + (path.basename(file).includes(".json") ? 0 : bytes), 0); },
		get(url) {
			const h = hash(url);
			try {
				const meta = JSON.parse(fs.readFileSync(metaPath(h), "utf8"));
				if (meta.url !== url) return null;
				if (meta.bodyFile && !new RegExp(`^${h}\\.body-[0-9a-f]+$`).test(meta.bodyFile)) return null;
				const file = meta.bodyFile ? path.join(entriesDir, meta.bodyFile) : bodyPath(h);
				if (fs.statSync(file).size !== meta.bytes) return null;
				return { ...meta, bodyPath: file };
			} catch { return null; }
		},
		/** Keep a body alive while an HTTP response streams it. */
		acquire(entry) {
			const file = entry.bodyPath;
			readers.set(file, (readers.get(file) || 0) + 1);
			let released = false;
			return () => {
				if (released) return;
				released = true;
				const remaining = (readers.get(file) || 1) - 1;
				if (remaining) readers.set(file, remaining);
				else {
					readers.delete(file);
					if (retired.delete(file)) retire(file);
				}
			};
		},
		/** Publish a fully-written body without replacing the previous one first. */
		commit(url, tmpBodyFile, meta) {
			const h = hash(url);
			const previous = this.get(url);
			this.makeRoom(0, url, !previous);
			const bodyFile = h + ".body-" + crypto.randomBytes(8).toString("hex");
			const nextBody = path.join(entriesDir, bodyFile);
			const tmpMeta = metaPath(h) + ".tmp" + crypto.randomBytes(4).toString("hex");
			let published = false;
			try {
				const metadata = JSON.stringify({ ...meta, url, bodyFile });
				this.reserve(tmpMeta, Buffer.byteLength(metadata));
				fs.writeFileSync(tmpMeta, metadata);
				fs.renameSync(tmpBodyFile, nextBody);
				if (bodySizes.has(tmpBodyFile)) { const size = bodySizes.get(tmpBodyFile); bodySizes.delete(tmpBodyFile); bodySizes.set(nextBody, size); }
				fs.renameSync(tmpMeta, metaPath(h));
				if (bodySizes.has(tmpMeta)) {
					const size = bodySizes.get(tmpMeta); forget(metaPath(h));
					bodySizes.delete(tmpMeta); bodySizes.set(metaPath(h), size);
				}
				published = true;
			} finally {
				if (!published) {
					retire(tmpMeta);
					retire(nextBody);
				}
			}
			if (previous && previous.bodyPath !== nextBody) retire(previous.bodyPath);
		},
		clear() {
			let n = 0;
			for (const f of fs.readdirSync(entriesDir)) {
				if (f.endsWith(".json") || /\.body(?:-[0-9a-f]+)?$/.test(f)) {
					retire(path.join(entriesDir, f));
					n++;
				}
			}
			return n;
		},
		retire,
		kind: "fs",
		openBody(entry) { return fs.createReadStream(entry.bodyPath); },
		readBody(entry) { return fs.readFileSync(entry.bodyPath); },
		/** A body being written: spooled to a temp file, then committed or detached. */
		createWriter() {
			const store = this;
			const tmp = path.join(entriesDir, ".tmp-" + crypto.randomBytes(6).toString("hex"));
			return {
				account(n) { store.reserve(tmp, n); },
				sink() { return fs.createWriteStream(tmp); },
				bytes() { return fs.statSync(tmp).size; },
				read() { return fs.readFileSync(tmp); },
				commit(key, meta) { store.commit(key, tmp, meta); },
				/** Serve once without keeping it (too big to cache); removed shortly after. */
				detach(meta) {
					const timer = setTimeout(() => store.retire(tmp), TRANSIENT_KEEP_MS);
					timer.unref?.();
					return { ...meta, bodyPath: tmp };
				},
				abort() { store.retire(tmp); },
			};
		},
		put(key, buffer, meta) {
			const tmp = path.join(entriesDir, ".tmp-" + crypto.randomBytes(6).toString("hex"));
			try {
				this.reserve(tmp, buffer.length);
				fs.writeFileSync(tmp, buffer);
				this.commit(key, tmp, meta);
			} finally { this.retire(tmp); }
		},
		purge(key) {
			const entry = this.get(key);
			if (!entry) return false;
			retire(metaPath(hash(key)));
			retire(entry.bodyPath);
			return true;
		},
		/** One writer owns cleanup and quota accounting. A dead owner's PID is recoverable. */
		claimOwner() {
			const lockFile = path.join(dir, "server.lock");
			try { fs.writeFileSync(lockFile, String(process.pid), { flag: "wx" }); }
			catch (error) {
				if (error.code !== "EEXIST") throw error;
				const pid = Number(fs.readFileSync(lockFile, "utf8"));
				let dead = false;
				if (Number.isSafeInteger(pid) && pid > 0) {
					try { process.kill(pid, 0); } catch (e) { if (e.code === "ESRCH") dead = true; }
				}
				if (!dead) throw new Error("proxy store is already owned by a server (server.lock)");
				fs.unlinkSync(lockFile);
				fs.writeFileSync(lockFile, String(process.pid), { flag: "wx" });
			}
			return () => fs.rmSync(lockFile, { force: true });
		},
		size() {
			try { return fs.readdirSync(entriesDir).filter(f => f.endsWith(".json")).length; }
			catch { return 0; }
		},
	};
}

module.exports = { createCacheStore, DEFAULT_CACHE_DIR };
