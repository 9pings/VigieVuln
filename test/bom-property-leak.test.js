/**
 * An imported BOM's <properties> must NOT leak into the importing project.
 *
 * Maven's `<scope>import</scope>` imports a BOM's **<dependencyManagement>**, and nothing
 * else. The BOM resolves its own managed versions in its own property context; its
 * `<properties>` never become the importing project's properties. fad merged them, and worse,
 * merged them so the BOM WON (`{...merged.properties, ...imported.properties}`), so a BOM
 * silently redefined the importer's own property values.
 *
 * Real-world shape, from Apache Dubbo 2.7.8: the reactor root sets
 * `<hibernate_validator_version>5.2.4.Final</hibernate_validator_version>`, and
 * `dubbo-dependencies-bom` — imported into the root's <dependencyManagement> — redefines it to
 * `5.4.1.Final`. `dubbo-filter-validation` declares
 * `<version>${hibernate_validator_version}</version>`, so it resolved to 5.4.1.Final instead
 * of the 5.2.4.Final Maven gives it. Verified against `mvn dependency:tree`, which reports
 * `org.hibernate:hibernate-validator:jar:5.2.4.Final:test` for that module.
 *
 * The wrong version means the wrong CVE set: it was the last remaining gap in
 * docs/BENCHMARK.md (4 findings of 657).
 *
 * The fixture is that shape, minimised, and it guards BOTH directions — the leak must stop,
 * and importing a BOM must still work.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const core = require("../lib/core");
const { collectResolvedDeps } = require("../lib/cve-match");

const FIXTURE = path.join(__dirname, "fixtures", "maven-bom-property-leak");

async function collect() {
	const store = core.newMetadataStore();
	for (const pom of core.findPomFiles(FIXTURE)) await core.parsePom(pom, store);
	const propsByPom = {};
	for (const pom of Object.keys(store.byPath)) await core.getAllInheritedProps(pom, store, propsByPom);
	return { store, propsByPom, resolved: collectResolvedDeps(store, propsByPom, {}) };
}

test("an imported BOM does not overwrite the importing project's own property", async () => {
	const { propsByPom } = await collect();
	const rootKey = Object.keys(propsByPom).find(p => p.endsWith(`maven-bom-property-leak${path.sep}pom.xml`));
	assert.ok(rootKey, "the reactor root must be parsed");
	// xml2js hands property values back as single-element arrays.
	const raw = propsByPom[rootKey].properties["lib.version"];
	assert.equal(Array.isArray(raw) ? raw[0] : raw, "1.0.0",
		"the reactor declares lib.version=1.0.0; the imported BOM's 2.0.0 must not win");
});

test("a module resolves ${property} from its own inheritance, not from the BOM", async () => {
	const { resolved } = await collect();
	const lib = resolved.get("com.acme:lib");
	assert.ok(lib, "com.acme:lib must be collected");
	assert.ok(lib.versions.includes("1.0.0"),
		`module-a declares <version>\${lib.version}</version> and inherits 1.0.0 from the reactor; got ${JSON.stringify(lib.versions)}`);
});

test("the BOM's managed version still works, resolved in the BOM's own context", async () => {
	const { resolved } = await collect();
	const lib = resolved.get("com.acme:lib");
	assert.ok(lib.versions.includes("2.0.0"),
		`module-b declares no version, so the imported BOM supplies it — and the BOM resolved \${lib.version} against its OWN 2.0.0; got ${JSON.stringify(lib.versions)}`);
});

test("a versionless managed coord is never left as a literal ${...}", async () => {
	const { resolved } = await collect();
	for (const [key, dep] of resolved) {
		for (const v of dep.versions || []) {
			assert.ok(!/\$\{/.test(String(v)), `${key} kept an unresolved version ${v}`);
		}
	}
});

// Symmetric to the masked-version rule in lib/attribution.js: a DECLARED version is dev
// only when every manifest declaring it does so at test/provided scope. The record is
// coord-wide, so without per-version scope a test-only version inherits the coordinate's
// production flag. Real case, Dubbo 2.7.8: hibernate-validator:5.2.4.Final is declared once,
// `<scope>test</scope>`, in dubbo-filter-validation (confirmed by `mvn dependency:tree`), while
// the coordinate is production at 5.4.1.Final via dubbo-dependencies-bom — so its 4 findings
// were counted as production and would trip `--fail-on`.
test("a version declared ONLY at test scope is reported as dev", async () => {
	const { resolved } = await collect();
	const { matchDepsAgainstCves } = require("../lib/cve-match");
	const { attributeMatchOrigins } = require("../lib/attribution");
	const idx = {
		byPackageName: { "com.acme:lib": [{ id: "CVE-BOM-0001", coordinateEvidence: "explicit-coordinate", exactPackageName: "com.acme:lib", severity: "HIGH", ranges: [{ version: "0", status: "affected", versionType: "maven", lessThan: "9.9.9" }] }] },
		byProduct: {},
	};
	const matches = matchDepsAgainstCves(resolved, idx);
	attributeMatchOrigins(matches);
	const byVersion = new Map(matches.filter(m => m.cve.id === "CVE-BOM-0001").map(m => [m.dep.version, m.dep]));

	assert.ok(byVersion.has("3.0.0"), "the test-scoped 3.0.0 must be scanned");
	assert.equal(byVersion.get("3.0.0").isDev, true,
		"3.0.0 is declared only at test scope — counting it as production inflates the production total and the CI gate");
	assert.notEqual(byVersion.get("1.0.0")?.isDev, true,
		"1.0.0 is declared at compile scope by module-a and must stay production");
});
