/**
 * Decompress an xz stream through the system `xz` binary (xz-utils): Node has no
 * built-in xz codec, and the NVD mirror ships xz only. The child is fed the download
 * stream and its stdout is returned as an async-iterable; a non-zero exit rejects.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { spawn } = require("node:child_process");
const { pipeline } = require("node:stream/promises");

function xzDecompress(input, { bin = process.env.FAD_SERVICE_XZ || "xz" } = {}) {
	const child = spawn(bin, ["-dc"], { stdio: ["pipe", "pipe", "pipe"] });
	let stderr = "";
	child.stderr.on("data", d => { stderr += d; });
	const exited = new Promise((resolve, reject) => {
		child.once("error", e => reject(e.code === "ENOENT" ? new Error(`"${bin}" not found — install xz-utils`) : e));
		child.once("close", code => code === 0 ? resolve() : reject(new Error(`xz exited ${code}: ${stderr.trim().slice(0, 200)}`)));
	});
	const feeding = pipeline(input, child.stdin).catch(() => {});   // EPIPE when xz dies is reported by `exited`
	return {
		async *[Symbol.asyncIterator]() {
			for await (const chunk of child.stdout) yield chunk;
			await feeding;
			await exited;
		},
		kill: () => child.kill(),
	};
}

module.exports = { xzDecompress };
