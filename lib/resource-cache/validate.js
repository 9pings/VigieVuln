/**
 * Strict typing of everything a client can send. Whitelists only: a field, a header, a
 * query parameter or a (provider, type) pair that is not listed here is refused with a 400
 * BEFORE any lookup, any database access or any upstream request — never coerced, never
 * defaulted silently.
 *
 *   validateResource(body)     the POST /v1/resource (and /admin/purge) document
 *   validateQuery(url, spec)   the query string of a public or admin route
 *
 * The (provider, type) table is exactly what vigievuln sends (lib/providers/*); the
 * providers re-check the same values when they build a URL — two independent locks.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

class ValidationError extends Error {
	constructor(message, field = null) { super(message); this.status = 400; this.field = field; }
}

const isPlain = v => v !== null && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype;
const PRINTABLE = /^[\x20-\x7e]*$/;

// ---------------------------------------------------------------- field types ----
const T = {
	str: (re, max = 200) => (v, at) => {
		if (typeof v !== "string" || !v.length || v.length > max || !re.test(v)) throw new ValidationError(`${at}: invalid value`, at);
		return v;
	},
	int: (min, max) => (v, at) => {
		if (!Number.isSafeInteger(v) || v < min || v > max) throw new ValidationError(`${at}: integer ${min}..${max} expected`, at);
		return v;
	},
	oneOf: list => (v, at) => { if (!list.includes(v)) throw new ValidationError(`${at}: one of ${list.join(", ")} expected`, at); return v; },
	arr: (item, min, max) => (v, at) => {
		if (!Array.isArray(v) || v.length < min || v.length > max) throw new ValidationError(`${at}: ${min}..${max} items expected`, at);
		return v.map((x, i) => item(x, `${at}[${i}]`));
	},
	/** shape: { field: validator }, optional: [names] — unknown keys are refused. */
	obj: (shape, optional = []) => (v, at) => {
		if (!isPlain(v)) throw new ValidationError(`${at}: object expected`, at);
		for (const k of Object.keys(v)) if (!(k in shape)) throw new ValidationError(`${at}.${k}: unexpected field`, `${at}.${k}`);
		const out = {};
		for (const [k, check] of Object.entries(shape)) {
			if (v[k] === undefined) { if (optional.includes(k)) continue; throw new ValidationError(`${at}.${k}: required`, `${at}.${k}`); }
			out[k] = check(v[k], `${at}.${k}`);
		}
		return out;
	},
};

const CVE = T.str(/^CVE-\d{4}-\d{4,7}$/i, 20);
const NAME = T.str(/^[A-Za-z0-9@][A-Za-z0-9._~\/@+-]*$/, 214);
// Separators are mandatory between runs: the old optional separator nested
// inside a repetition allowed exponentially many partitions of a long name.
const COMPOSER = T.str(/^[a-z0-9]+(?:[_.-][a-z0-9]+)*\/[a-z0-9]+(?:(?:[_.]|-{1,2})[a-z0-9]+)*$/i, 200);
const OSV_ECOS = ["Maven", "npm", "PyPI", "Packagist", "NuGet", "Go", "RubyGems", "crates.io", "Hex", "Pub", "CRAN", "Hackage", "SwiftURL", "GitHub Actions"];
const OSV_NAME = T.str(/^[\x21-\x7e]+$/, 300), OSV_VERSION = T.str(/^[\x21-\x7e]+$/, 100);
const OSV_PAGE_TOKEN = T.str(/^[\x21-\x7e]+$/, 2048);
const scopedOsvEcosystem = T.str(/^[A-Za-z][A-Za-z0-9 ._+-]*:[A-Za-z0-9][A-Za-z0-9 ._:+-]*$/, 160);
const OSV_ECOSYSTEM = (value, at) => OSV_ECOS.includes(value) ? value : scopedOsvEcosystem(value, at);
const OSV_FLAT = T.obj({ ecosystem: OSV_ECOSYSTEM, name: OSV_NAME, version: OSV_VERSION, page_token: OSV_PAGE_TOKEN }, ["page_token"]);
const OSV_NESTED = T.obj({ package: T.obj({ ecosystem: OSV_ECOSYSTEM, name: OSV_NAME }), version: OSV_VERSION, page_token: OSV_PAGE_TOKEN }, ["page_token"]);
/** fad sends the flat form; OSV's own querybatch form ({ package: {…}, version }) is accepted too — both end flat. */
const OSV_QUERY = (v, at) => {
	if (isPlain(v) && "package" in v) { const q = OSV_NESTED(v, at); return { ecosystem: q.package.ecosystem, name: q.package.name, version: q.version, ...(q.page_token ? { page_token: q.page_token } : {}) }; }
	return OSV_FLAT(v, at);
};
const NONE = T.obj({});

/** "<provider>/<type>" → the params schema. */
const releases = require('../providers/package-releases');
const archive = T.oneOf(Object.keys(releases.archives)), suite = T.str(releases.suite,40);
const RESOURCES = {
  "package-releases/release": T.obj({archive,suite}),
  "package-releases/index": T.obj({archive,suite,file:T.str(releases.index,80)}),
  "package-releases/apk": T.obj({series:T.str(releases.alpine,8),arch:T.str(releases.apkArch,16),section:T.oneOf(['main','community'])}),
  "package-releases/upstream": T.obj({project:T.int(1,1000000)}),
	"nvd/cve": T.obj({ id: CVE }),
	"nvd/cve-mirror": T.obj({ id: CVE }),
	"nvd/spip-advisories": NONE,
 "nvd/image-product": T.obj({product:T.oneOf([...require('../artifacts/product-catalog').upstreamProducts.values()].filter(p=>p.cpe).map(p=>p.id)),cpe:T.str(/^[a-z0-9_.-]+:[a-z0-9_.-]+$/,100),version:T.str(/^\d+(?:\.\d+){1,3}$/,40)}),
	"osv/vuln": T.obj({ id: T.str(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, 100) }),
	"osv/packages": T.obj({ queries: T.arr(OSV_QUERY, 1, 1000) }),
	"epss/scores": T.obj({ ids: T.arr(CVE, 1, 100) }),
	"epss/cve-score": T.obj({ id: CVE }),
	"kev/catalog": NONE,
	"kev/cves": T.obj({ ids: T.arr(CVE, 1, 100) }),
	"eol/product": T.obj({ product: T.str(/^[a-z0-9][a-z0-9._-]*$/, 100) }),
	"npm/package": T.obj({ name: T.str(/^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9._~-][a-z0-9._~-]*$/i, 214) }),
	"pypi/package": T.obj({ name: T.str(/^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/, 100) }),
	"ruby/gem": T.obj({ name: T.str(/^[A-Za-z0-9_.-]+$/, 100) }),
	"go/module-latest": T.obj({ module: T.str(/^[a-z0-9.!_~-]+(\/[A-Za-z0-9.!_~+-]+)*$/, 300) }),
	"go/module-info": T.obj({ module: T.str(/^[a-z0-9.!_~-]+(\/[A-Za-z0-9.!_~+-]+)*$/, 300), version: T.str(/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$/, 150) }),
	"alpine/package": T.obj({ name: T.str(/^[a-z0-9][a-z0-9+_.-]*$/, 200) }),
	"nginx/advisories": NONE,
	"freexian/index": T.obj({page:T.int(1,10000)}),
	"freexian/advisory": T.obj({slug:T.str(/^ela-\d+-\d+-[a-z0-9][a-z0-9.+-]*$/,250)}),
	"freexian/tracker": T.obj({packages:T.arr(T.str(/^[a-z0-9][a-z0-9+.-]*$/,200),1,1000)}),
	"freexian/vulnerability": T.obj({id:CVE}),
	"alpine/vulnerability": T.obj({ id: CVE }),
	"mit-kerberos/announcement": T.obj({quarter:T.str(/^\d{4}q[1-4]$/,6),message:T.str(/^\d{6}$/,6)}),
	"debian/history": T.obj({ until: T.str(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 20) }),
	"debian/source-version": T.obj({ name:T.str(/^[a-z0-9][a-z0-9+.-]*$/,200),version:T.str(/^[0-9][A-Za-z0-9.+:~\-]*$/,150) }),
	"debian/list": T.obj({ commit: T.str(/^[a-f0-9]{40}$/, 40), list: T.oneOf(['CVE','DSA','DLA']), packages: T.arr(T.str(/^[a-z0-9][a-z0-9+.-]*$/, 200), 1, 1000) }),
	"nuget/service-index": NONE,
	"nuget/registration": T.obj({ name: T.str(/^[A-Za-z0-9_.-]+$/, 100) }),
	"nuget/registration-page": T.obj({ path: T.str(/^\/[A-Za-z0-9_.\/-]+\.json$/, 300) }),
	"packagist/advisories": T.obj({ packages: T.arr(COMPOSER, 1, 100) }),
	"packagist/advisory-package": T.obj({ name: COMPOSER }),
	"packagist/package": T.obj({ name: COMPOSER }),
	"packagist/p2": T.obj({ name: COMPOSER }),
	"maven/artifact": T.obj({ path: T.str(/^(?!.*\.\.)[A-Za-z0-9._+-]+(\/[A-Za-z0-9._+-]+)*$/, 500), method: T.oneOf(["GET", "HEAD"]), repository:T.oneOf(['google']) }, ["method","repository"]),
	"maven/latest": T.obj({ group: T.str(/^[A-Za-z0-9._-]+$/, 200), artifact: T.str(/^[A-Za-z0-9._-]+$/, 200) }),
	"maven/preflight": T.obj({repository:T.oneOf(['google'])},['repository']),
	"github/cve-release": NONE,
	"github/theme-release": T.obj({repo:T.oneOf(["TryGhost/Casper","TryGhost/Source"])}),
	"github/cve-maven": T.obj({ keys: T.arr(T.str(/^[pa]:[a-z0-9][a-z0-9._:+-]*$/, 220), 1, 200) }),
	"github/cve-npm": T.obj({ names: T.arr(T.str(/^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9._~-][a-z0-9._~-]*$/, 214), 1, 200) }),
	"github/cve-packages": T.obj({ packages: T.arr(T.obj({ecosystem:T.str(/^(?:[A-Za-z0-9][A-Za-z0-9:._+-]*|system:deb:debian:\*)$/,150),name:OSV_NAME}),1,200) }),
	"vigievuln/advisories": T.obj({ packages: T.arr(T.obj({ecosystem:T.oneOf(['Maven','npm']),name:OSV_NAME}),1,200) }),
	"github/cve-archive": T.obj({ tag: T.str(/^[A-Za-z0-9._-]+$/, 100), name: T.str(/^[A-Za-z0-9._-]+\.zip$/i, 200) }),
	"github/publisher-advisories": T.obj({ repo: T.str(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, 200), page: T.int(1, 1000), perPage: T.int(1, 100) }, ["page", "perPage"]),
	"hashid/depsdev-sha1": T.obj({ base64: T.str(/^[A-Za-z0-9+/]{27}=$/, 28) }),
	"hashid/circl-sha256": T.obj({ sha256: T.str(/^[0-9a-fA-F]{64}$/, 64) }),
	"wordfence/production-feed": NONE,
	"wpvulnerability/advisories": T.obj({kind:T.oneOf(["core","plugin","theme"]),subject:T.str(/^[a-z0-9][a-z0-9._-]*$/,200)}),
	"wordfence/software": T.obj({ software: T.arr(T.obj({ type: T.oneOf(["core", "plugin", "theme"]),
		slug: T.str(/^[a-z0-9][a-z0-9._-]*$/, 200) }), 1, 100) }),
	"wordpress/extension": T.obj({kind:T.oneOf(["plugin","theme"]),slug:T.str(/^[a-z0-9][a-z0-9._-]*$/,200)}),
	"drupal/extension": T.obj({name:T.str(/^drupal\/[a-z0-9][a-z0-9_-]*$/,206)}),
	"wordpress/checksums": T.obj({ version: T.str(/^\d+(\.\d+){1,3}$/, 20), locale: T.str(/^[a-z]{2,3}(_[A-Z]{2})?$/, 10) }),
	"drupal/advisories": T.obj({ packages: T.arr(T.str(/^drupal\/[a-z0-9_]+$/, 100), 1, 100) }),
	"osvdb/ecosystem-archive": T.obj({ ecosystem: T.oneOf([...OSV_ECOS, "Debian", "Ubuntu", "Alpine", "AlmaLinux", "Rocky Linux", "Red Hat", "SUSE", "openSUSE"]) }),
	"retire/signatures": NONE,
	"euvd/cve-mapping": NONE,
	"euvd/cves": T.obj({ ids: T.arr(CVE, 1, 100) }),
	"euvd/vulnerability": T.obj({ id: T.str(/^EUVD-\d{4}-\d{1,12}$/, 24) }),
	"euvd/exploited": T.obj({ page: T.int(0, 1000) }),
	"certfr/cves": T.obj({ ids: T.arr(CVE, 1, 100) }),
	"certfr/index": T.obj({ kind: T.oneOf(["avis", "alerte"]) }),
	"certfr/advisory": T.obj({ kind: T.oneOf(["avis", "alerte"]), ref: T.str(/^CERT(?:FR|A)-\d{4}-(?:AVI|ALE)-\d{1,5}$/, 30),
		rev: (v, at) => { if (typeof v !== "string" || v.length > 40 || !/^[0-9T:.+-]*$/.test(v)) throw new ValidationError(`${at}: invalid value`, at); return v; } }, ["rev"]),
	"gcve/directory": NONE,
	"gcve/signature": NONE,
	"gcve/gna-dump": T.obj({ gna: T.int(1,1000000) }),
};

/** Request headers a client may forward upstream (lower-case names), each strictly typed. */
const HEADERS = {
	"user-agent": T.str(PRINTABLE, 200),
	"accept": T.str(/^[\w.+\/*;=, -]+$/, 200),
	"content-type": T.oneOf(["application/json"]),
	"authorization": T.str(/^(Bearer|Basic) [A-Za-z0-9._~+\/=-]+$/, 600),
	"apikey": T.str(/^[A-Za-z0-9-]+$/, 100),
	"x-github-api-version": T.str(/^\d{4}-\d{2}-\d{2}$/, 10),
};

/** The /v1/resource document → { provider, type, params, headers } or ValidationError. */
function validateResource(body) {
	if (!isPlain(body)) throw new ValidationError("a JSON object is expected");
	for (const k of Object.keys(body)) if (!["provider", "type", "params", "headers", "revalidate"].includes(k)) throw new ValidationError(`${k}: unexpected field`, k);
	if (typeof body.provider !== "string" || typeof body.type !== "string") throw new ValidationError("provider and type are required strings");
	const schema = RESOURCES[`${body.provider}/${body.type}`];
	if (!schema) throw new ValidationError(`unknown resource ${String(body.provider).slice(0, 40)}/${String(body.type).slice(0, 40)}`, "type");
	if (body.revalidate !== undefined && typeof body.revalidate !== 'boolean') throw new ValidationError('revalidate: boolean expected', 'revalidate');
	if (body.revalidate && !require('../providers').getProvider(body.provider).revalidateTypes?.includes(body.type)) throw new ValidationError('revalidate: unsupported resource', 'revalidate');
	const params = schema(body.params === undefined ? {} : body.params, "params");
	let headers = {};
	if (body.headers !== undefined) {
		if (!isPlain(body.headers) || Object.keys(body.headers).length > 10) throw new ValidationError("headers: object expected", "headers");
		for (const [name, value] of Object.entries(body.headers)) {
			const k = name.toLowerCase();
			if (!HEADERS[k]) throw new ValidationError(`headers.${name.slice(0, 40)}: not allowed`, "headers");
			headers[k] = HEADERS[k](value, `headers.${k}`);
		}
	}
	return { provider: body.provider, type: body.type, params, headers, ...(body.revalidate ? {revalidate:true} : {}) };
}

/** Query parameters of one route: spec = { name: validatorFromString }. Unknown → 400. */
function validateQuery(url, spec = {}) {
	const out = {};
	for (const name of new Set(url.searchParams.keys())) {
		if (!(name in spec)) throw new ValidationError(`unexpected query parameter "${name.slice(0, 40)}"`, name);
		const all = url.searchParams.getAll(name);
		if (all.length > 1) throw new ValidationError(`${name}: given twice`, name);
		out[name] = spec[name](all[0], name);
	}
	return out;
}

/** Validators for query-string values (they arrive as strings). */
const Q = {
	lang: v => T.oneOf(["en", "fr"])(v, "lang"),
	text: max => (v, at) => { if (typeof v !== "string" || v.length > max || /[\u0000-\u001f\u007f]/.test(v)) throw new ValidationError(`${at}: invalid text`, at); return v; },
	int: (min, max) => (v, at) => { if (!/^\d{1,6}$/.test(v)) throw new ValidationError(`${at}: integer expected`, at); return T.int(min, max)(Number(v), at); },
	oneOf: list => (v, at) => T.oneOf(list)(v, at),
	hex: len => (v, at) => T.str(new RegExp(`^[0-9a-f]{${len}}$`), len)(v, at),
	/** A package version as registries write them (SemVer, Maven, PEP 440 incl. "1!2.0", Go pseudo-versions, NuGet). */
	version: (v, at) => T.str(/^[A-Za-z0-9][A-Za-z0-9.+_~!-]*$/, 128)(v, at),
};

module.exports = { validateResource, validateQuery, ValidationError, RESOURCES, HEADERS, Q };
