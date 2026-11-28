/**
 * WordPress core file-integrity reference (api.wordpress.org/core/checksums/1.0/ —
 * the md5 map of the exact official distribution, pinned per version and locale).
 * « Modified », « missing from the tree » and « extra inside the controlled perimeter »
 * are three different results, and none of them is a CVE: divergences surface as
 * diagnostics with a coverage record, never as findings.
 * The controlled perimeter for extra files is wp-admin/ + wp-includes/ — the
 * distribution's code directories. wp-content/ is user land by design; flagging every
 * upload and custom plugin as "extra" would be noise, not integrity.
 */
const crypto = require("node:crypto");

const WP_CHECKSUMS_API = "https://api.wordpress.org/core/checksums/1.0/";
const EXTRA_DIRS = ["wp-admin", "wp-includes"];
const DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_DIAGNOSTICS_PER_CODE = 100;

function validateChecksums(snapshot) {
	if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot))
		throw new Error("WordPress checksums snapshot must be a JSON object");
	if (!snapshot.checksums || typeof snapshot.checksums !== "object" || Array.isArray(snapshot.checksums))
		throw new Error("WordPress checksums snapshot needs a checksums object");
	for (const [file, hash] of Object.entries(snapshot.checksums)) {
		if (typeof file !== "string" || file.startsWith("/") || file.split("/").includes(".."))
			throw new Error(`checksum path must stay relative to the WordPress root: ${file}`);
		if (!/^[0-9a-f]{32}$/i.test(String(hash)))
			throw new Error(`checksum for ${file} is not an md5 hex digest`);
	}
	return { checksums: new Map(Object.entries(snapshot.checksums)),
		version: typeof snapshot.version === "string" ? snapshot.version : null,
		locale: typeof snapshot.locale === "string" ? snapshot.locale : null };
}

/** Compares a validated reference against a tree through the injected file access
 *  ({ has, read → Buffer|null, filesIn, directories }), all relative to the WordPress root. */
function evaluateChecksums(reference, fileAccess, { maxDiagnosticsPerCode = DEFAULT_MAX_DIAGNOSTICS_PER_CODE } = {}) {
	const modified = [], missing = [], extra = [], uncertain = [], diagnostics = [];
	for (const [file, expected] of reference.checksums) {
		if (!fileAccess.has(file)) { missing.push(file); continue; }
		const bytes = fileAccess.read(file);
		if (bytes == null) { uncertain.push(file); continue; }
		if (crypto.createHash("md5").update(bytes).digest("hex") !== String(expected).toLowerCase()) modified.push(file);
	}
	const referenceSet = new Set(reference.checksums.keys());
	for (const dir of fileAccess.directories || []) {
		if (!EXTRA_DIRS.some(base => dir === base || dir.startsWith(`${base}/`))) continue;
		for (const name of fileAccess.filesIn(dir)) {
			const relative = dir === "." ? name : `${dir}/${name}`;
			if (!referenceSet.has(relative)) extra.push(relative);
		}
	}
	const referenceLabel = `the official WordPress ${reference.version || ""} distribution reference`.replace(/ +/g, " ").trim();
	const emit = (code, files, describe, summary) => {
		for (const file of files.slice(0, maxDiagnosticsPerCode))
			diagnostics.push({ code, path: file,
				message: describe(file) });
		if (files.length > maxDiagnosticsPerCode)
			diagnostics.push({ code: "CMS_INTEGRITY_LIST_TRUNCATED",
				message: `${files.length} file(s) ${summary}; the report lists the first ${maxDiagnosticsPerCode}` });
	};
	emit("CMS_FILE_MODIFIED", modified, file => `${file} differs from ${referenceLabel}`,
		`differ from ${referenceLabel}`);
	emit("CMS_FILE_MISSING", missing, file => `${file} is listed in ${referenceLabel} but absent from the scanned tree`,
		`are listed in ${referenceLabel} but absent from the scanned tree`);
	emit("CMS_FILE_EXTRA", extra, file => `${file} is not listed in ${referenceLabel}`,
		`are not listed in ${referenceLabel}`);
	for (const file of uncertain.slice(0, maxDiagnosticsPerCode))
		diagnostics.push({ code: "CMS_FILE_UNREADABLE", path: file,
			message: `${file} could not be hashed (unreadable or above the size limit); its integrity is unverified` });
	if (uncertain.length > maxDiagnosticsPerCode)
		diagnostics.push({ code: "CMS_INTEGRITY_LIST_TRUNCATED",
			message: `${uncertain.length} file(s) could not be hashed; the report lists the first ${maxDiagnosticsPerCode}` });
	return { modified, missing, extra, uncertain, diagnostics,
		checked: reference.checksums.size - uncertain.length, expected: reference.checksums.size };
}

module.exports = { WP_CHECKSUMS_API, EXTRA_DIRS, DEFAULT_MAX_FILE_BYTES, validateChecksums, evaluateChecksums };
