// CERT-FR (ANSSI) advisories: the per-kind listing, then one JSON per advisory. The
// revision date rides in the params so a revised advisory is a new resource while an
// unchanged one is never fetched twice.
const KINDS = new Set(["avis", "alerte"]);
const REF = /^CERT(?:FR|A)-\d{4}-(?:AVI|ALE)-\d{1,5}$/;
module.exports = {
	id: "certfr", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		const base = "https://www.cert.ssi.gouv.fr";
		if (!KINDS.has(params?.kind)) throw new Error("invalid CERT-FR request");
		if (type === "index") return { url: `${base}/${params.kind}/json/` };
		if (type === "advisory" && REF.test(String(params?.ref || ""))) return { url: `${base}/${params.kind}/${params.ref}/json/` };
		throw new Error("invalid CERT-FR request");
	},
};
