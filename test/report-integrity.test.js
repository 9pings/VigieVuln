const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const { sha256OfFile, buildChecksumManifest, writeChecksums } = require("../lib/report-integrity");

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-int-")); }

test("sha256OfFile matches a reference SHA-256", () => {
	const dir = tmp();
	try {
		const f = path.join(dir, "a.txt");
		fs.writeFileSync(f, "hello fad\n");
		const expected = crypto.createHash("sha256").update("hello fad\n").digest("hex");
		assert.strictEqual(sha256OfFile(f), expected);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("buildChecksumManifest emits sorted sha256sum-format lines with relative paths", () => {
	const dir = tmp();
	try {
		fs.writeFileSync(path.join(dir, "b.html"), "B");
		fs.writeFileSync(path.join(dir, "a.json"), "A");
		const manifest = buildChecksumManifest([path.join(dir, "b.html"), path.join(dir, "a.json")], { baseDir: dir });
		const lines = manifest.trimEnd().split("\n");
		assert.match(lines[0], /^[0-9a-f]{64} {2}a\.json$/, "sorted, two-space separator, relative path");
		assert.match(lines[1], /^[0-9a-f]{64} {2}b\.html$/);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("writeChecksums writes a file that `sha256sum -c` accepts", () => {
	const dir = tmp();
	try {
		fs.writeFileSync(path.join(dir, "report.html"), "<html></html>");
		fs.writeFileSync(path.join(dir, "findings.json"), "{}");
		const manifestPath = path.join(dir, "SHA256SUMS");
		const written = writeChecksums([path.join(dir, "report.html"), path.join(dir, "findings.json")], manifestPath, { baseDir: dir });
		assert.ok(fs.existsSync(manifestPath));
		assert.ok(written.includes("report.html"));
		// Verify with the system tool when available; the format must round-trip.
		try {
			const out = execFileSync("sha256sum", ["-c", "SHA256SUMS"], { cwd: dir, encoding: "utf8", env: { ...process.env, LC_ALL: "C" } });
			assert.match(out, /report\.html: OK/);
			assert.match(out, /findings\.json: OK/);
		} catch (e) {
			if (e.code === "ENOENT") return; // sha256sum not on PATH — format already asserted above
			throw e;
		}
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("writeChecksums skips files that do not exist", () => {
	const dir = tmp();
	try {
		fs.writeFileSync(path.join(dir, "exists.txt"), "x");
		const written = writeChecksums([path.join(dir, "exists.txt"), path.join(dir, "missing.txt")], path.join(dir, "SHA256SUMS"), { baseDir: dir });
		assert.ok(written.includes("exists.txt"));
		assert.ok(!written.includes("missing.txt"));
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
