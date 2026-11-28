'use strict';
// Reads the unpatched-vulnerability definitions of a Red Hat OVAL file: for each CVE, the
// packages Red Hat states are affected and why no fix is available. Only that is kept; the
// patch definitions (errata) come from another source and the OVAL tests are not evaluated.
const { StringDecoder } = require('node:string_decoder');
const { decompressBlocks } = require('./bzip2');

const MAX_DEFINITION_CHARS = 4 * 1024 * 1024, MAX_ADVISORIES = 200000;
const STATES = ['Affected', 'Fix deferred', 'Will not fix', 'Out of support scope', 'Under investigation'];
const SEVERITY = { low: 'LOW', moderate: 'MEDIUM', important: 'HIGH', critical: 'CRITICAL' };
const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'" };
const unescape = text => text.replace(/&(?:amp|lt|gt|quot|apos);/g, entity => ENTITIES[entity]);
const COMPONENT = /^(?:[A-Za-z0-9][A-Za-z0-9._+-]*:[A-Za-z0-9._+-]+\/)?[A-Za-z0-9][A-Za-z0-9._+-]*$/;

function parseDefinition(xml) {
	const cve = /<cve\b([^>]*)>\s*(CVE-\d{4}-\d{4,})\s*<\/cve>/.exec(xml);
	if (!cve) return null;
	const attribute = name => (new RegExp(`\\b${name}="([^"]*)"`).exec(cve[1]) || [])[1] || null;
	const cvss = /^(\d+(?:\.\d+)?)\/(CVSS:3\.[01]\/[A-Za-z:/]+)$/.exec(attribute('cvss3') || '');
	const title = (/<title>([^<]*)<\/title>/.exec(xml) || [])[1];
	const published = /^(\d{4})(\d{2})(\d{2})$/.exec(attribute('public') || '');
	const components = [];
	for (const resolution of xml.matchAll(/<resolution state="([^"]+)">([\s\S]*?)<\/resolution>/g)) {
		const state = STATES.indexOf(resolution[1]);
		if (state < 0) continue;
		for (const component of resolution[2].matchAll(/<component>([^<]+)<\/component>/g)) if (COMPONENT.test(component[1])) components.push([component[1], state]);
	}
	if (!components.length) return null;
	return { id: cve[2], components, advisory: {
		title: title ? unescape(title).replace(/\s*\((?:low|moderate|important|critical)\)\s*$/i, '').slice(0, 500) : null,
		severity: SEVERITY[String(attribute('impact') || (/<severity>([^<]+)<\/severity>/.exec(xml) || [])[1] || '').toLowerCase()] || 'UNKNOWN',
		score: cvss ? Number(cvss[1]) : null, vector: cvss ? cvss[2] : null,
		published: published ? `${published[1]}-${published[2]}-${published[3]}` : null,
		updated: (/<updated date="(\d{4}-\d{2}-\d{2})"/.exec(xml) || [])[1] || null } };
}

/**
 * Decompress and read an OVAL file. → { timestamp, advisories: { CVE: {...} },
 * components: { package or "module:stream/package": [[CVE, state index], …] }, states }
 */
function readUnpatched(compressed) {
	const decoder = new StringDecoder('utf8'), advisories = Object.create(null), components = Object.create(null);
	let pending = '', count = 0, timestamp = null, done = false;
	const take = definition => {
		// Unpatched vulnerabilities only: errata (rhsa, rhba, rhea) and "unaffected" are other classes.
		if (!/^<definition\b[^>]*\bid="oval:com\.redhat\.cve:def:/.test(definition)) return;
		const parsed = parseDefinition(definition);
		if (!parsed || advisories[parsed.id] || count >= MAX_ADVISORIES) return;
		advisories[parsed.id] = parsed.advisory; count++;
		for (const [name, state] of parsed.components) (components[name] ||= []).push([parsed.id, state]);
	};
	for (const block of decompressBlocks(compressed)) {
		pending += decoder.write(block);
		if (timestamp === null) { const stamp = /<oval:timestamp>([^<]+)<\/oval:timestamp>/.exec(pending); if (stamp) timestamp = stamp[1]; }
		for (;;) {
			const start = pending.indexOf('<definition ');
			if (start < 0) { if (pending.includes('</definitions>')) done = true; pending = pending.slice(-16); break; }
			const end = pending.indexOf('</definition>', start);
			if (end < 0) { pending = pending.slice(start); if (pending.length > MAX_DEFINITION_CHARS) throw Error('Red Hat OVAL definition exceeds its size limit'); break; }
			take(pending.slice(start, end));
			pending = pending.slice(end + 13);
		}
		// Tests, objects and states follow the definitions: nothing more to read.
		if (done) break;
	}
	if (!count) throw Error('Red Hat OVAL file holds no unpatched definition');
	return { timestamp, advisories, components, states: STATES, count };
}

module.exports = { readUnpatched, parseDefinition, STATES };
