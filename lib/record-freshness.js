'use strict';

// Versioned record metadata: dates describe the source record, never its cache fetch.
const METADATA_VERSION = 1;
const DAY_MS = 86400000;
const extractors = {
 nvd: record => ({published:record?.published, modified:record?.modified}),
 osv: record => ({published:record?.published, modified:record?.modified}),
 euvd: record => ({published:record?.published, modified:record?.modified}),
};
function stableRecord(source, record, options = {}) {
 if (options.reuseStableAdvisories === false || options.forceUpdate || require('./cache-policy').shouldForceUpdate()) return false;
 const days = options.stableAdvisoryAgeDays ?? 365;
 if (!Number.isFinite(days) || days <= 0 || days > Number.MAX_SAFE_INTEGER / DAY_MS) return false;
 const now = options.now ?? Date.now(), extract = (options.recordMetadataExtractors || extractors)[source];
 if (!Number.isFinite(now) || typeof extract !== 'function') return false;
 const metadata = extract(record);
 if (!metadata?.modified) return false;
 const dates = [metadata.modified, metadata.published].filter(x => x != null && x !== '').map(x => typeof x === 'string' ? Date.parse(x) : NaN);
 return dates.length > 0 && dates.every(x => Number.isFinite(x) && x <= now) && now - Math.max(...dates) >= days * DAY_MS;
}
module.exports = { METADATA_VERSION, extractors, stableRecord };
