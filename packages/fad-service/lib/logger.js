/**
 * Logging: one line per event, text or JSON, to stdout or to a file with size-based
 * rotation (file → file.1 → … → file.<keep>, oldest dropped) and reopen on SIGHUP, so
 * an external logrotate (copytruncate not needed) works too.
 *
 * Under `--workers N` only the PRIMARY process writes the file: workers send their lines
 * over the cluster IPC channel (createWorkerLogger), so rotation is never raced by
 * several writers.
 *
 * Privacy (spec §6): callers never pass requested coordinates; the access log carries a
 * route family, a status, a latency, a request id and a salted client tag.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("node:fs");
const path = require("node:path");

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function formatLine(format, level, msg, fields = {}) {
	const ts = new Date().toISOString();
	if (format === "json") return JSON.stringify({ ts, level, msg, ...fields });
	const kv = Object.entries(fields).filter(([, v]) => v !== undefined && v !== null && v !== "")
		.map(([k, v]) => `${k}=${/[\s"=]/.test(String(v)) ? JSON.stringify(String(v)) : v}`).join(" ");
	return `${ts} ${level.toUpperCase().padEnd(5)} ${msg}${kv ? " " + kv : ""}`;
}

/** A sink that writes whole lines to a file, rotating by size. */
function createFileSink({ file, maxBytes = 50 * 1024 * 1024, keep = 10 }) {
	fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
	let fd = null, size = 0;
	const open = () => {
		fd = fs.openSync(file, "a", 0o640);
		size = fs.fstatSync(fd).size;
	};
	const close = () => { if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } fd = null; } };
	const rotate = () => {
		close();
		for (let i = keep - 1; i >= 1; i--) {
			try { fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`); } catch { /* gap in the series */ }
		}
		if (keep >= 1) { try { fs.renameSync(file, `${file}.1`); } catch { /* nothing to rotate */ } }
		else fs.rmSync(file, { force: true });
		try { fs.rmSync(`${file}.${keep + 1}`, { force: true }); } catch { /* none */ }
		open();
	};
	open();
	return {
		write(line) {
			const buf = Buffer.from(line + "\n");
			if (size > 0 && size + buf.length > maxBytes) rotate();
			fs.writeSync(fd, buf);
			size += buf.length;
		},
		reopen() { close(); open(); },
		close,
	};
}

const stdoutSink = { write: line => process.stdout.write(line + "\n"), reopen() {}, close() {} };

/**
 * opts: { file, format: "text"|"json", level, maxBytes, keep, sink }
 * → { debug, info, warn, error, line(raw), reopen, close }
 */
function createLogger(opts = {}) {
	const format = opts.format || "text";
	const min = LEVELS[opts.level || "info"] ?? LEVELS.info;
	const sink = opts.sink || (opts.file ? createFileSink({ file: opts.file, maxBytes: opts.maxBytes, keep: opts.keep ?? 10 }) : stdoutSink);
	const emit = level => (msg, fields) => { if (LEVELS[level] >= min) sink.write(formatLine(format, level, msg, fields)); };
	return {
		format,
		debug: emit("debug"), info: emit("info"), warn: emit("warn"), error: emit("error"),
		/** An already formatted line (forwarded from a cluster worker). */
		line: raw => sink.write(String(raw).replace(/\n+$/, "")),
		reopen: () => sink.reopen(),
		close: () => sink.close(),
	};
}

/** In a cluster worker: format locally, write through the primary. */
function createWorkerLogger(opts = {}) {
	return createLogger({ ...opts, file: null, sink: {
		write: line => { if (process.send) process.send({ fadLog: line }); else process.stdout.write(line + "\n"); },
		reopen() {}, close() {},
	} });
}

module.exports = { createLogger, createWorkerLogger, createFileSink, formatLine, LEVELS };
