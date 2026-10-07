/**
 * test/fixtures/report-payload/full.js — one payload that lights up EVERY chapter of the
 * report: production / dev / embedded / CPE-filtered CVE, retire.js findings and the
 * vendored-JS inventory, native binaries, certificates and keys, end-of-life (both bands),
 * obsolete, outdated, licenses, excluded directories, scan warnings, a baseline diff and a
 * provenance manifest.
 *
 * It exists so the i18n suite can assert against a WHOLE report rather than a fragment: a
 * chapter that no fixture reaches is a chapter whose translations nothing checks. Every
 * string that comes from a data source is written as EVIDENCE_… so a test can tell the
 * report's own chrome from the evidence it quotes.
 *
 * `build(locale)` → the payload; the caller renders it.
 */
const { makeDepRecord } = require("../../../lib/dep-record");
const SRC = "/proj";
const mk = (o) => makeDepRecord(o);
const direct = mk({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: `${SRC}/pom.xml` });
const trans  = { ...mk({ ecosystem: "maven", namespace: "com.fasterxml.jackson.core", name: "jackson-databind", version: "2.9.0", manifestPath: `${SRC}/pom.xml` }), scope: "transitive", depth: 2, via: ["org.acme:svc"], viaPaths: [["org.acme:svc", "x:y"], ["org.acme:web"], ["a:b"], ["c:d"]] };
const trans2 = { ...mk({ ecosystem: "maven", namespace: "org.apache.commons", name: "commons-compress", version: "1.24.0", manifestPath: `${SRC}/pom.xml` }), scope: "transitive", depth: 1, via: ["org.acme:svc"], viaPaths: [["org.acme:svc"]] };
const npmDep = mk({ ecosystem: "npm", name: "lodash", version: "4.17.11", manifestPath: `${SRC}/web/package.json` });
const devDep = { ...mk({ ecosystem: "npm", name: "mocha", version: "3.0.0", manifestPath: `${SRC}/web/package.json` }), isDev: true, scope: "dev" };
const embDep = { ...mk({ ecosystem: "maven", namespace: "org.x", name: "embedded-lib", version: "1.0.0", manifestPath: `${SRC}/libs/app.jar!/BOOT-INF/lib/embedded-lib-1.0.0.jar` }), provenance: "embedded" };
const binDep = { ...mk({ ecosystem: "binary", name: "libfoo.so", version: null, manifestPath: `${SRC}/native/libfoo.so` }), provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "libfoo.so", identity: { ecosystem: "npm", name: "foo", version: "1.2.3", source: "deps.dev" }, integrity: "pristine", shouldBeManaged: true, path: `${SRC}/native/libfoo.so` };
const bomDep = { ...mk({ ecosystem: "maven", namespace: "org.springframework.boot", name: "spring-boot-starter-web", version: "2.7.18", manifestPath: `${SRC}/svc/pom.xml` }), versionSource: { via: "parent", bom: "org.springframework.boot:spring-boot-starter-parent:2.7.18" } };
const parentDep = { ...mk({ ecosystem: "maven", namespace: "org.acme", name: "inherited", version: "1.0", manifestPath: `${SRC}/pom.xml` }), scope: "parent" };

const cve = (id, o = {}) => ({
  id, severity: "CRITICAL", score: 9.8, description: "EVIDENCE_ADVISORY_TEXT stays in English.",
  fixVersion: "2.17.1", published: "2021-12-10", modified: "2022-01-02", cwes: ["CWE-502", "CWE-79"],
  cvssVector: "CVSS:3.1/AV:N", cvssVersion: "CVSS 3.1", epssScore: 0.97, epssPercentile: 0.999,
  kev: true, kevDateAdded: "2021-12-10", kevDueDate: "2021-12-24", kevRansomware: true, ghsa: "GHSA-jfh8-c2jp-5v3q",
  gcve: "GCVE-0-2021-44228", euvd: { id: "EUVD-2021-34768", exploitedSince: "2021-12-10" },
  certfr: [{ ref: "CERTFR-2021-ALE-022", kind: "alerte", title: "EVIDENCE_certfr_title" }],
  aliases: ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-45046"], cpes: ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
  nvdRefs: [{ url: "https://github.com/x/y/commit/abc", tags: ["Patch"] }, { url: "https://lists.apache.org/x", tags: ["Mailing List"] }],
  osvRefs: [{ url: "https://osv.dev/x", type: "ADVISORY" }],
  ...o,
});
const m = (dep, id, o) => ({ dep, cve: cve(id, o), confidence: "exact", source: "fad+osv" });

const resolved = new Map([
  ["org.apache.logging.log4j:log4j-core", direct],
  ["com.fasterxml.jackson.core:jackson-databind", trans],
  ["org.apache.commons:commons-compress", trans2],
  ["org.acme:svc", mk({ ecosystem: "maven", namespace: "org.acme", name: "svc", version: "1.0.0", manifestPath: `${SRC}/pom.xml` })],
  ["npm:lodash", npmDep], ["npm:mocha", devDep],
  ["org.springframework.boot:spring-boot-starter-web", bomDep],
  ["org.acme:inherited", parentDep],
  [`embedded:${SRC}/libs/app.jar!/BOOT-INF/lib/embedded-lib-1.0.0.jar`, embDep],
  [`embedded:${SRC}/libs/app.jar!/BOOT-INF/lib/clean-lib-2.0.0.jar`, { ...mk({ ecosystem: "maven", namespace: "org.x", name: "clean-lib", version: "2.0.0", manifestPath: `${SRC}/libs/app.jar!/BOOT-INF/lib/clean-lib-2.0.0.jar` }), provenance: "embedded" }],
  [`binary:${SRC}/native/libfoo.so`, binDep],
]);

module.exports = (locale) => ({
  locale,
  cveMatches: [m(direct, "CVE-2021-44228"), m(trans, "CVE-2020-36518", { severity: "HIGH", score: 7.5, fixVersion: null, kev: false, epssPercentile: 0.4 }), m(trans2, "CVE-2024-25710", { severity: "HIGH", score: 7.5, fixVersion: "1.26.0", kev: false, epssPercentile: 0.2 }), m(npmDep, "CVE-2019-10744", { severity: "MEDIUM", score: 5.3, kev: false }), { ...m(bomDep, "CVE-2016-1000027", { severity: "LOW", score: 3.1, kev: false }), cpeFiltered: true }],
  devCveMatches: [m(devDep, "CVE-2018-0001", { severity: "LOW", kev: false })],
  embeddedMatches: [m(embDep, "CVE-2017-0001", { severity: "HIGH", kev: false })],
  retireMatches: [
    { dep: { artifactId: "jquery", version: "1.8.3", vendoredFile: `${SRC}/web/js/jquery.js`, scope: "vendored" }, cve: { id: "CVE-2015-9251", severity: "MEDIUM", description: "EVIDENCE_RETIRE_TEXT", fixVersion: "3.0.0" }, source: "retire" },
    // Same physical file, second advisory: the vendored-JS chapter groups the two behind
    // one library row (the inventory already declared vulnCount: 2 for this file).
    { dep: { artifactId: "jquery", version: "1.8.3", vendoredFile: `${SRC}/web/js/jquery.js`, scope: "vendored" }, cve: { id: "CVE-2019-11358", severity: "LOW", description: "jQuery.extend prototype pollution", fixVersion: "3.4.0", cwes: ["CWE-1321"] }, source: "retire" },
  ],
  vendoredJsInventory: [{ component: "jquery", version: "1.8.3", file: "web/js/jquery.js", detection: "filecontent", vulnerable: true, vulnCount: 2, maxSeverity: "MEDIUM" }, { component: "bootstrap", version: "3.4.1", file: "web/js/bootstrap.js", detection: "filename", vulnerable: false, vulnCount: 0 }],
  certFindings: [
    { path: `${SRC}/certs/server.pem`, kind: "certificate", algorithm: "RSA", bits: 1024, subject: "CN=srv", issuer: "CN=ca", notAfter: "2020-01-01T00:00:00Z", daysUntilExpiry: -900, sha256: "c".repeat(64), issues: [{ type: "cert-expired", severity: "high" }, { type: "cert-weak-key", severity: "medium" }, { type: "cert-self-signed", severity: "low" }] },
    { path: `${SRC}/certs/id_rsa`, kind: "private-key", algorithm: "RSA", format: "PKCS#8", encrypted: false, count: 2, sha256: "d".repeat(64), issues: [{ type: "private-key-committed", severity: "critical" }] },
    { path: `${SRC}/certs/edge.crt`, kind: "certificate", algorithm: "RSA", bits: 2048, subject: "CN=edge", issuer: "CN=ca", notAfter: "2026-11-01T00:00:00Z", daysUntilExpiry: 43, sha256: "9".repeat(64), issues: [{ type: "cert-expiring", severity: "medium" }, { type: "cert-weak-signature", severity: "medium" }] },
    { path: `${SRC}/certs/ks.jks`, kind: "keystore", algorithm: "JKS", sha256: "e".repeat(64), issues: [{ type: "keystore-committed", severity: "low" }] },
    { path: `${SRC}/certs/id_rsa.pub`, kind: "public-key", algorithm: "ssh-rsa", format: "OpenSSH", sha256: "f".repeat(64), issues: [{ type: "public-key-committed", severity: "low" }] },
  ],
  eolResults: [
    { dep: direct, product: "Log4j", productSlug: "log4j", cycle: "2.14", status: "eol", eol: "2021-12-01", latest: "2.24.1", via: "group-artifact", viaKey: "org.apache.logging.log4j:log4j-core", notes: "EVIDENCE_EOL_NOTE", components: [{ name: "a" }, { name: "b" }, { name: "c" }] },
    { dep: trans, product: "Jackson", productSlug: "jackson", cycle: "2.9", status: "eol", eol: "2020-01-01", latest: "2.18.0", via: "group-prefix", viaKey: "com.fasterxml.jackson" },
    { dep: npmDep, product: "Node.js", productSlug: "nodejs", cycle: "14", status: "unsupported", support: "2022-10-18", eol: "2023-04-30", latest: "22.9.0", via: "npm-name", viaKey: "lodash" },
  ],
  obsoleteResults: [{ dep: npmDep, severity: "HIGH", replacement: "lodash-es", reason: "EVIDENCE_DEPRECATION_REASON" }],
  outdatedResults: [
    { dep: direct, latest: "2.24.1", releaseDate: "2024-11-07" },
    { dep: npmDep, latest: "4.17.21", releaseDate: "2021-02-20" },
  ],
  licenseResults: { assessed: [1, 2], flagged: [1], byCategory: { "strong-copyleft": [{ dep: direct, ids: ["GPL-3.0"], raw: [], source: "pom" }], permissive: [{ dep: npmDep, ids: ["MIT"], raw: [], source: "registry" }] } },
  excludedDirs: [{ dir: "node_modules", type: "default", reason: "package store" }, { dir: "vendor/x", type: "exclude-path", reason: "--exclude-path vendor/**" }],
  resolvedDeps: resolved,
  parsedManifests: [{ path: `${SRC}/pom.xml`, ecosystemType: "maven" }, { path: `${SRC}/web/package.json`, ecosystemType: "npm" }, { path: `${SRC}/svc/pom.xml`, ecosystemType: "maven" }, { path: `${SRC}/tools/package.json`, ecosystemType: "npm" }],
  warnings: [
    { type: "no-lockfile", message: "EVIDENCE_WARNING_MSG", count: 1, manifestPath: `${SRC}/web/package.json`, items: ["a", "b"] },
    { type: "private-libs", message: "EVIDENCE_WARNING_MSG2", count: 2, items: [{ id: "com.acme:secret", manifestPaths: [`${SRC}/pom.xml`, `${SRC}/svc/pom.xml`] }] },
    { type: "unresolved-versions", message: "EVIDENCE_WARNING_MSG3", count: 1, items: ["x:y"] },
  ],
  diff: { summary: { cve: { addedProduction: 2, added: 3, removed: 1, unchanged: 8, addedBySeverity: { CRITICAL: 1, HIGH: 1 } }, eol: { added: 1, removed: 0, unchanged: 2 }, obsolete: { added: 0, removed: 1, unchanged: 0 }, outdated: { added: 1, removed: 0, unchanged: 3 }, licenses: { added: 0, removed: 0, unchanged: 2 } }, cve: { added: [{ id: "CVE-2021-44228", severity: "CRITICAL", dep: { coord: "org.apache.logging.log4j:log4j-core", version: "2.14.1" } }] } },
  projectInfo: {
    name: "demo", src: SRC, generatedAt: "2026-09-19", toolVersion: "2.5.3", cveDataDate: "2026-09-18",
    provenance: {
      mode: "online", runtime: { node: "v22", platform: "linux", arch: "x64" },
      configuration: { ecosystems: "auto", transitive: true, transitiveDepth: 4, osv: true, nvd: true, epss: true, kev: false, licenses: true, typosquat: false, failOn: "high" },
      dataSources: [{ label: "NIST NVD", status: "cached", asOf: "2026-09-18", detail: "EVIDENCE_SOURCE_DETAIL" }, { label: "CISA KEV", status: "missing", asOf: null, detail: "" }, { label: "EPSS", status: "disabled", asOf: null, detail: "" }],
    },
  },
});
