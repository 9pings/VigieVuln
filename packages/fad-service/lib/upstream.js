/**
 * The fetcher the service uses towards upstreams. Maven Central requests go to an
 * official Central mirror first — Google's EU bucket by default, listed by Maven itself
 * in repo.maven.apache.org/maven2/.meta/repository-metadata.xml — and fall back to
 * repo1.maven.org when the mirror lacks the file (mirror lag) or does not answer. That
 * keeps the bulk of the traffic in the EU and off Sonatype's own servers.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const CENTRAL = "https://repo1.maven.org/maven2/";
const DEFAULT_MAVEN_MIRRORS = ["https://maven-central-eu.storage-download.googleapis.com/maven2/"];

function createUpstreamFetcher(base = globalThis.fetch, { mavenMirrors = DEFAULT_MAVEN_MIRRORS } = {}) {
	const mirrors = (mavenMirrors || []).map(u => u.endsWith("/") ? u : u + "/").filter(u => /^https:\/\//.test(u));
	return async function upstreamFetch(url, init = {}) {
		const target = String(url);
		if (!mirrors.length || !target.startsWith(CENTRAL)) return base(url, init);
		const rest = target.slice(CENTRAL.length);
		for (const m of mirrors) {
			try {
				const r = await base(m + rest, init);
				if (r.ok) return r;
				await r.body?.cancel?.();
				if (r.status !== 404 && r.status !== 403 && r.status < 500) return base(url, init);
			} catch (e) { if (init.signal?.aborted) throw e; }
		}
		return base(url, init);
	};
}

module.exports = { createUpstreamFetcher, DEFAULT_MAVEN_MIRRORS, CENTRAL };
