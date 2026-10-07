/**
 * The key of a product as a CNA names it in a CVE record (affected[].vendor / product):
 * "vendor/product", each part lowercase with letters, digits and . _ + - only; "_" for an
 * unknown vendor; null when the product itself is n/a. Shared by the asset store (the
 * cve_product table) and the pages (links), so a link always finds its page.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const NA = /^(n\/?a|unknown|unspecified|-|\*)$/i;
function slugPart(v) {
	const s = String(v ?? "").normalize("NFKC").trim();
	if (!s || NA.test(s)) return null;
	const slug = s.toLowerCase().replace(/[^\p{L}\p{N}._+-]+/gu, "-").replace(/^-+|-+$/g, "").slice(0, 100);
	return slug && !/^\.+$/.test(slug) ? slug : null;     // never a "." / ".." path segment
}
function productKey(vendor, product) {
	const p = slugPart(product);
	return p ? `${slugPart(vendor) || "_"}/${p}` : null;
}

/** "/product/<vendor>/<product>" for a key, or null. */
const productPath = key => key ? `/product/${key.split("/").map(encodeURIComponent).join("/")}` : null;

module.exports = { productKey, slugPart, productPath };
