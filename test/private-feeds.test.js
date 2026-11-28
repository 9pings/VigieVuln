const { test } = require("node:test");
const assert = require("node:assert");

// ---- registries.js: nuget + composer are now first-class ecosystems ----
test("registries SUPPORTED + PUBLIC_BASES include nuget and composer", () => {
	const R = require("../lib/providers/registries");
	assert.ok(R.SUPPORTED.includes("nuget"), "nuget supported");
	assert.ok(R.SUPPORTED.includes("composer"), "composer supported");
	assert.ok(R.PUBLIC_BASES.nuget, "nuget public base defined");
	assert.ok(R.PUBLIC_BASES.composer, "composer public base defined");
});

// ---- NuGet private feed ----
test("nuget fetchRegistration tries custom registry first, sends auth, falls back to public", async () => {
	const { fetchRegistration } = require("../lib/codecs/nuget/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => {
		seen.push({ url, auth: headers.Authorization || null });
		if (url.startsWith("https://nexus/")) return { ok: false, status: 404 };
		return { ok: true, json: async () => ({ items: [] }) };
	};
	const out = await fetchRegistration("Newtonsoft.Json", {
		registries: [{ url: "https://nexus/nuget/", token: "T" }],
		fetcher,
	});
	assert.ok(out && !out.error, "got a registration object");
	assert.strictEqual(seen[0].url, "https://nexus/nuget/newtonsoft.json/index.json");
	assert.strictEqual(seen[0].auth, "Bearer T");
	assert.ok(seen[1].url.startsWith("https://api.nuget.org/"), "public base tried second");
});

test("nuget service-index URL is resolved to its RegistrationsBaseUrl", async () => {
	const { fetchRegistration } = require("../lib/codecs/nuget/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => {
		seen.push({ url, auth: headers.Authorization || null });
		if (url === "https://feed/v3/index.json") {
			return { ok: true, json: async () => ({ resources: [
				{ "@id": "https://feed/query/", "@type": "SearchQueryService" },
				{ "@id": "https://feed/reg/", "@type": "RegistrationsBaseUrl/3.6.0" },
			] }) };
		}
		if (url === "https://feed/reg/serilog/index.json") return { ok: true, json: async () => ({ items: [{}] }) };
		return { ok: false, status: 404 };
	};
	const out = await fetchRegistration("Serilog", {
		registries: [{ url: "https://feed/v3/index.json", auth: "u:p" }],
		fetcher,
	});
	assert.ok(out && !out.error, "resolved + fetched registration");
	const reg = seen.find(s => s.url === "https://feed/reg/serilog/index.json");
	assert.ok(reg, "fetched the resolved registration URL");
	assert.strictEqual(reg.auth, "Basic " + Buffer.from("u:p").toString("base64"));
});

test("nuget fetchRegistration with no custom registries hits api.nuget.org only", async () => {
	const { fetchRegistration } = require("../lib/codecs/nuget/registry");
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: true, json: async () => ({ items: [] }) }; };
	await fetchRegistration("System.Text.Json", { fetcher });
	assert.strictEqual(seen.length, 1);
	assert.ok(seen[0].startsWith("https://api.nuget.org/"));
});

// ---- Composer private feed ----
test("composerV2ToPackageObject converts /p2/ metadata to a packagist-like object", () => {
	const { composerV2ToPackageObject } = require("../lib/codecs/composer/registry");
	const p2 = { packages: { "monolog/monolog": [
		{ version: "3.5.0", license: ["MIT"] },
		{ version: "2.9.1", license: ["MIT"] },
		{ version: "dev-main", license: ["MIT"] },
	] } };
	const pkg = composerV2ToPackageObject(p2, "monolog/monolog");
	assert.ok(pkg.versions["3.5.0"], "version present");
	assert.deepStrictEqual(pkg.versions["3.5.0"].license, ["MIT"]);
	assert.strictEqual(pkg.abandoned, null);
});

test("composerV2ToPackageObject surfaces an abandoned flag from version metadata", () => {
	const { composerV2ToPackageObject } = require("../lib/codecs/composer/registry");
	const p2 = { packages: { "vendor/old": [
		{ version: "1.0.0", abandoned: "vendor/new" },
	] } };
	const pkg = composerV2ToPackageObject(p2, "vendor/old");
	assert.strictEqual(pkg.abandoned, "vendor/new");
});

test("composer fetchPackage tries custom /p2/ first with auth, then public packagist", async () => {
	const { fetchPackage } = require("../lib/codecs/composer/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => {
		seen.push({ url, auth: headers.Authorization || null });
		if (url.startsWith("https://satis/")) return { ok: false, status: 404 };
		return { ok: true, json: async () => ({ package: { versions: { "1.2.3": { license: ["MIT"] } } } }) };
	};
	const out = await fetchPackage("guzzlehttp/guzzle", { registries: [{ url: "https://satis/", token: "T" }], fetcher });
	assert.ok(out && !out.error, "got a package object");
	assert.strictEqual(seen[0].url, "https://satis/p2/guzzlehttp/guzzle.json");
	assert.strictEqual(seen[0].auth, "Bearer T");
	assert.ok(seen[1].url.startsWith("https://packagist.org/"), "public packagist tried second");
});

test("composer fetchPackage returns custom v2 result without hitting public", async () => {
	const { fetchPackage } = require("../lib/codecs/composer/registry");
	const seen = [];
	const fetcher = async (url) => {
		seen.push(url);
		return { ok: true, json: async () => ({ packages: { "acme/lib": [{ version: "2.0.0", license: ["Apache-2.0"] }] } }) };
	};
	const out = await fetchPackage("acme/lib", { registries: [{ url: "https://repo.acme/" }], fetcher });
	assert.ok(out.versions["2.0.0"], "converted v2 version present");
	assert.strictEqual(seen.length, 1, "stopped at the custom feed");
});
