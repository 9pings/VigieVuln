/**
 * One EOL finding per (product, cycle), not one per artifact.
 *
 * Measured on a 105-module Spring reactor: 16 EOL rows carrying 5 distinct verdicts, because
 * 9 org.springframework:* artifacts and 4 spring-boot ones share a release train. "This app
 * runs Spring 4.3" is one fact with one fix — bump the BOM — and printing it nine times
 * inflates the chapter and buries Jetty, Tomcat and Hibernate, which ARE separate findings.
 */
const test = require("node:test");
const assert = require("node:assert");
const { groupEolByProduct } = require("../lib/maintenance/outdated");

const hit = (groupId, artifactId, version, product, cycle, extra = {}) => ({
	product, cycle, productSlug: product.toLowerCase().replace(/ /g, "-"),
	dep: { ecosystem: "maven", groupId, artifactId, version, manifestPaths: ["pom.xml"], ...extra },
});

test("nine Spring artifacts on one cycle collapse to a single finding", () => {
	const hits = ["spring-core", "spring-web", "spring-beans", "spring-aop", "spring-tx"]
		.map(a => hit("org.springframework", a, "4.3.16.RELEASE", "Spring Framework", "4.3"));
	const out = groupEolByProduct(hits);
	assert.strictEqual(out.length, 1);
	assert.strictEqual(out[0].components.length, 5);
	assert.ok(out[0].components.every(c => c.version === "4.3.16.RELEASE"));
});

test("different products stay separate findings", () => {
	const out = groupEolByProduct([
		hit("org.springframework", "spring-core", "4.3.16.RELEASE", "Spring Framework", "4.3"),
		hit("org.apache.tomcat.embed", "tomcat-embed-core", "8.5.31", "Apache Tomcat", "8.5"),
	]);
	assert.strictEqual(out.length, 2);
});

test("the same product at two cycles stays two findings — never a merged, possibly wrong one", () => {
	const out = groupEolByProduct([
		hit("org.springframework", "spring-core", "4.3.16.RELEASE", "Spring Framework", "4.3"),
		hit("org.springframework", "spring-web", "5.2.0.RELEASE", "Spring Framework", "5.2"),
	]);
	assert.strictEqual(out.length, 2);
	assert.deepStrictEqual(out.map(o => o.cycle).sort(), ["4.3", "5.2"]);
});

test("the anchor is the artifact you would actually bump — the BOM wins", () => {
	const out = groupEolByProduct([
		hit("org.springframework", "spring-web", "4.3.16.RELEASE", "Spring Framework", "4.3"),
		hit("org.springframework", "spring-framework-bom", "4.3.16.RELEASE", "Spring Framework", "4.3"),
		hit("org.springframework", "spring-aop", "4.3.16.RELEASE", "Spring Framework", "4.3"),
	]);
	assert.strictEqual(out[0].dep.artifactId, "spring-framework-bom");
});

test("with no BOM, a direct dependency is preferred over a transitive one", () => {
	const out = groupEolByProduct([
		hit("org.springframework", "spring-aop", "4.3.16.RELEASE", "Spring Framework", "4.3", { scope: "transitive" }),
		hit("org.springframework", "spring-web", "4.3.16.RELEASE", "Spring Framework", "4.3"),
	]);
	assert.strictEqual(out[0].dep.artifactId, "spring-web");
});

test("grouping is deterministic — a re-run must produce the same anchor and order", () => {
	const hits = ["spring-web", "spring-aop", "spring-core"]
		.map(a => hit("org.springframework", a, "4.3.16.RELEASE", "Spring Framework", "4.3"));
	const a = groupEolByProduct(hits), b = groupEolByProduct([...hits].reverse());
	assert.strictEqual(a[0].dep.artifactId, b[0].dep.artifactId);
	assert.deepStrictEqual(a[0].components.map(c => c.name), b[0].components.map(c => c.name));
});

test("a lone artifact is untouched — same record, no anchor, no component list", () => {
	// A group of one is not a group: the finding must pass through byte-for-byte, keeping the
	// record's identity because other findings hold the same object.
	const one = hit("org.apache.tomcat.embed", "tomcat-embed-core", "8.5.31", "Apache Tomcat", "8.5");
	const out = groupEolByProduct([one]);
	assert.strictEqual(out.length, 1);
	assert.strictEqual(out[0].dep, one.dep, "the original record is passed through");
	assert.strictEqual(out[0].components, undefined);
	assert.strictEqual(out[0].anchor, undefined);
});

test("components keep every artifact, so the JSON export stays exhaustive", () => {
	const out = groupEolByProduct(["spring-core", "spring-web", "spring-beans"]
		.map(a => hit("org.springframework", a, "4.3.16.RELEASE", "Spring Framework", "4.3")));
	assert.deepStrictEqual(out[0].components.map(c => c.name).sort(),
		["org.springframework:spring-beans", "org.springframework:spring-core", "org.springframework:spring-web"]);
});

test("empty in, empty out", () => {
	assert.deepStrictEqual(groupEolByProduct([]), []);
});
