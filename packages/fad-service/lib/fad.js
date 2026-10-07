/**
 * Resolve a fad-checker module: the installed package when fad-service is installed on
 * its own, the repository's lib/ when it runs from the monorepo.
 */
const path = require("node:path");

function fad(rel) {
	try { return require(`fad-checker/lib/${rel}`); }
	catch (error) {
		if (error.code !== "MODULE_NOT_FOUND" || !String(error.message).includes("fad-checker")) throw error;
		return require(path.join(__dirname, "..", "..", "..", "lib", rel));
	}
}

/** The same for fad-checker's data/ files (CWE names…). */
function fadData(file) {
	try { return require(`fad-checker/data/${file}`); }
	catch (error) {
		if (error.code !== "MODULE_NOT_FOUND" || !String(error.message).includes("fad-checker")) throw error;
		return require(path.join(__dirname, "..", "..", "..", "data", file));
	}
}

module.exports = { fad, fadData };
