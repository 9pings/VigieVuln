const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseIgnoreFile, parseVex, applySuppressions } = require("../lib/suppress");
const { makeDepRecord } = require("../lib/dep-record");

const log4j = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "pom.xml" });
const lodash = makeDepRecord({ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "package.json" });

test("parseIgnoreFile parses cve / coord / reason and comments", () => {
	const rules = parseIgnoreFile(`
# a comment line
CVE-2021-44228               # accepted: not reachable
CVE-1111-2222 org.apache.*   # only this coord
* npm:lodash
`);
	assert.equal(rules.length, 3);
	assert.equal(rules[0].cve, "CVE-2021-44228");
	assert.equal(rules[0].coord, null);
	assert.equal(rules[0].reason, "accepted: not reachable");
	assert.equal(rules[1].coord, "org.apache.*");
	assert.equal(rules[2].cve, "*");
});

test("applySuppressions marks a global CVE rule across deps", () => {
	const matches = [
		{ dep: log4j, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-OTHER" } },
	];
	const n = applySuppressions(matches, parseIgnoreFile("CVE-2021-44228 # accepted"));
	assert.equal(n, 2);
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[0].suppressedReason, "accepted");
	assert.equal(matches[2].suppressed, undefined);
});

test("coord-scoped rule only suppresses the matching dependency", () => {
	const matches = [
		{ dep: log4j, cve: { id: "CVE-X" } },
		{ dep: lodash, cve: { id: "CVE-X" } },
	];
	applySuppressions(matches, parseIgnoreFile("CVE-X org.apache.logging.log4j:log4j-core"));
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[1].suppressed, undefined);
});

test("glob on coord matches a family", () => {
	const matches = [{ dep: log4j, cve: { id: "CVE-Y" } }];
	applySuppressions(matches, parseIgnoreFile("* org.apache.*"));
	assert.equal(matches[0].suppressed, true);
});

test("parseVex suppresses CVEs marked not_affected/fixed, mapped by purl", () => {
	const csaf = {
		product_tree: { full_product_names: [
			{ product_id: "PROD-0", name: "log4j", product_identification_helper: { purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" } },
		] },
		vulnerabilities: [
			{ cve: "CVE-2021-44228", product_status: { known_not_affected: ["PROD-0"] } },
			{ cve: "CVE-GLOBAL", product_status: { fixed: [] } },
		],
	};
	const rules = parseVex(csaf);
	const matches = [
		{ dep: log4j, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-2021-44228" } }, // different coord → not suppressed
		{ dep: lodash, cve: { id: "CVE-GLOBAL" } },     // empty clearance → not suppressed
	];
	applySuppressions(matches, rules);
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[1].suppressed, undefined);
	assert.equal(matches[2].suppressed, undefined);
});

// Regression: a VEX product_id with no purl in the product_tree must NOT become a
// global (coordRe:null) rule that suppresses the CVE for every dependency. (#4)
test("VEX with an unmappable product_id does not suppress unrelated deps", () => {
	const csaf = { product_tree: { full_product_names: [] }, vulnerabilities: [
		{ cve: "CVE-2021-44228", product_status: { known_not_affected: ["CSAFPID-1"] } },
	] };
	const rules = parseVex(csaf);
	assert.equal(rules.length, 0);
	const unrelated = makeDepRecord({ ecosystem: "maven", namespace: "org.unrelated", name: "thing", version: "1.0.0", manifestPath: "pom.xml" });
	const matches = [{ cve: { id: "CVE-2021-44228" }, dep: unrelated }];
	assert.equal(applySuppressions(matches, rules), 0);
});

test("affected, investigating, absent or empty VEX statuses never grant global clearance", () => {
	for (const product_status of [{ known_affected: ['P'] }, { under_investigation: ['P'] }, {}, { fixed: [] }, undefined]) {
		assert.deepEqual(parseVex({ vulnerabilities: [{ cve: 'CVE-1', product_status }] }), []);
	}
});

test("own CSAF affected export remains blocking when reimported as VEX", () => {
	const { buildCsaf } = require('../lib/csaf-export');
	const { evaluateGate } = require('../lib/gate');
	const matches = [{ dep: log4j, cve: { id: 'CVE-2021-44228', severity: 'CRITICAL' } }];
	const vex = buildCsaf(new Map([[log4j.coordKey, log4j]]), matches);
	assert.equal(applySuppressions(matches, parseVex(vex)), 0);
	assert.equal(evaluateGate(matches, 'critical').failed, true);
});

test("explicit VEX exemptions preserve status and scope; contradictions do not clear", () => {
	const { purlFor } = require('../lib/purl');
	for (const status of ['fixed', 'known_not_affected']) {
		const vex = { product_tree: { full_product_names: [{ product_id: 'P', product_identification_helper: { purl: purlFor(log4j) } }] },
			vulnerabilities: [{ cve: 'CVE-1', product_status: { [status]: ['P'] } }] };
		const matches = [{ dep: log4j, cve: { id: 'CVE-1' } }, { dep: lodash, cve: { id: 'CVE-1' } }];
		assert.equal(applySuppressions(matches, parseVex(vex)), 1);
		assert.equal(matches[0].suppressionStatus, status);
		assert.equal(matches[1].suppressed, undefined);
		vex.vulnerabilities[0].product_status.known_affected = ['P'];
		assert.deepEqual(parseVex(vex), []);
	}
});

test('VEX clearance never extends to affected, investigating or unknown copies sharing one PURL', () => {
	const { purlFor } = require('../lib/purl');
	const { evaluateGate } = require('../lib/gate');
	for (const siblingStatus of ['known_affected', 'under_investigation', null]) {
		for (const order of [['A', 'B'], ['B', 'A']]) {
			const vex = { product_tree: { full_product_names: order.map(product_id => ({ product_id,
				product_identification_helper: { purl: purlFor(log4j) } })) }, vulnerabilities: [{
				cve: 'CVE-2021-44228', product_status: { known_not_affected: ['A'], ...(siblingStatus ? { [siblingStatus]: ['B'] } : {}) },
			}] };
			const matches = ['site-a/pom.xml', 'site-b/pom.xml'].map(file => ({ dep: { ...log4j, manifestPaths: [file] },
				cve: { id: 'CVE-2021-44228', severity: 'HIGH' } }));
			assert.deepEqual(parseVex(vex), []);
			assert.equal(applySuppressions(matches, parseVex(vex)), 0);
			assert.equal(evaluateGate(matches, 'high').failed, true);
		}
	}
});

test('VEX PURLs are exact identities, not ignore-file globs', () => {
	const vex = { product_tree: { full_product_names: [{ product_id: 'P',
		product_identification_helper: { purl: 'pkg:npm/*@*' } }] },
		vulnerabilities: [{ cve: 'CVE-1', product_status: { fixed: ['P'] } }] };
	assert.equal(applySuppressions([{ dep: lodash, cve: { id: 'CVE-1' } }], parseVex(vex)), 0);
});

test('VEX contradictory assertions in separate vulnerability entries do not clear the same PURL', () => {
	const { purlFor } = require('../lib/purl');
	const clear = { cve: 'CVE-1', product_status: { fixed: ['P'] } };
	const affected = { cve: 'CVE-1', product_status: { known_affected: ['P'] } };
	for (const vulnerabilities of [[clear, affected], [affected, clear]]) {
		const vex = { product_tree: { full_product_names: [{ product_id: 'P', product_identification_helper: { purl: purlFor(log4j) } }] }, vulnerabilities };
		assert.deepEqual(parseVex(vex), []);
	}
});

test('ignore rules match merged aliases and GHSA while preserving coordinate scopes', () => {
 const matches=[
  {dep:log4j,cve:{id:'CVE-2024-1234',aliases:['GHSA-aaaa-bbbb-cccc']}},
  {dep:lodash,cve:{id:'CVE-2024-1234',aliases:['GHSA-aaaa-bbbb-cccc']}},
  {dep:lodash,cve:{id:'CVE-2024-5678',ghsa:'GHSA-dddd-eeee-ffff'}},
 ];
 assert.equal(applySuppressions(matches,parseIgnoreFile('GHSA-aaaa-bbbb-cccc org.apache.*')),1);
 assert.equal(matches[1].suppressed,undefined);
 assert.equal(applySuppressions([matches[2]],parseIgnoreFile('GHSA-dddd-eeee-ffff')),1);
 assert.equal(applySuppressions([{dep:lodash,cve:{id:'GHSA-test',aliases:['CVE-2024-9999']}}],parseIgnoreFile('CVE-2024-9999')),1);
 assert.equal(applySuppressions([{dep:lodash,cve:{id:'CVE-2024-1',aliases:'GHSA-aaaa-bbbb-cccc'}}],parseIgnoreFile('GHSA-aaaa-bbbb-cccc')),0);
});

test('VEX alias clearance cannot bypass affected primary-id assertions or exact product scope', () => {
 const {purlFor}=require('../lib/purl');
 const vex={product_tree:{full_product_names:[{product_id:'P',product_identification_helper:{purl:purlFor(log4j)}}]},vulnerabilities:[
  {cve:'GHSA-aaaa-bbbb-cccc',product_status:{fixed:['P']}},
  {cve:'CVE-2024-1234',product_status:{known_affected:['P']}},
 ]};
 const matches=[{dep:log4j,cve:{id:'CVE-2024-1234',aliases:['GHSA-aaaa-bbbb-cccc']}},{dep:lodash,cve:{id:'GHSA-aaaa-bbbb-cccc'}}];
 assert.equal(applySuppressions(matches,parseVex(vex)),0);
});

test('global ignore detection flags unrestricted stars but preserves scoped policies', () => {
 const {hasGlobalIgnoreRule}=require('../lib/suppress');
 for(const text of ['*','* # accepted deliberately','* *','* **'])assert.equal(hasGlobalIgnoreRule(parseIgnoreFile(text)),true);
 for(const text of ['','CVE-2024-1234','* org.apache.*','* pkg:npm/*'])assert.equal(hasGlobalIgnoreRule(parseIgnoreFile(text)),false);
});
