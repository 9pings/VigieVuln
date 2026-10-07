// Direct rendering checks run without a database or a listening HTTP socket.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const web = require('../lib/web/render');
const { makeT } = require('../lib/web/i18n');

test('public layout: one labelled search, heading, skip target and no client scripts in either locale', () => {
 for (const locale of ['en', 'fr']) {
  const t = makeT(locale);
  for (const path of ['/', '/search']) {
   const body = path === '/' ? web.home({ t, counts: { cve: 400000 } }) : '';
   // No script unless a third-party analytics provider is configured (opt-in, see ops.test.js).
   const html = web.layout({ t, locale, path, body, title: 'test', site: {} });
   assert.equal((html.match(/<h1>/g) || []).length, 1);
   assert.equal((html.match(/role="search"/g) || []).length, 1);
   assert.match(html, /<label for="query">/);
   assert.match(html, /<main id="content" tabindex="-1">/);
   assert.match(html, /href="#content"/);
   assert.doesNotMatch(html, /<script\b|<style\b|\sstyle=/i);
   assert.ok(html.includes(t('Skip to content')));
  }
 }
});

test('CVE summary preserves unknown severity, zero EPSS and escaped evidence', () => {
 const t = makeT('fr');
 const html = web.cvePage({ t, locale: 'fr', asset: { data: {
  id: 'CVE-2026-1000', description: '<script>bad</script>', published: '2026-10-01T00:00:00Z',
  references: [{ url: 'javascript:alert(1)' }, { url: 'https://example.org/" onclick="bad' }],
 }, sources: [] }, signals: { epss_score: 0, epss_date: '2026-10-01' } });
 assert.match(html, /<h2>En bref<\/h2>/);
 assert.match(html, /Non disponible/);
 assert.match(html, /EPSS 0\.00 % · centile \?/);
 assert.match(html, /<time datetime="2026-10-01">2026-10-01<\/time>/);
 assert.match(html, /&lt;script&gt;bad&lt;\/script&gt;/);
 assert.doesNotMatch(html, /<script\b|href="javascript:|\sonclick="/i);
});

test('search cards and empty states escape titles and query text', () => {
 const ctx = { t: makeT('en'), locale: 'en', q: '<img src=x>' };
 const empty = web.results({ ...ctx, rows: [] });
 assert.match(empty, /&lt;img src=x&gt;/);
 assert.match(empty, /Try a broader keyword/);
 const html = web.results({ ...ctx, rows: [{ type: 'advisory', key: 'osv:GHSA-test', title: '<b>source title</b>' }] });
 assert.match(html, /<article class="result">/);
 assert.match(html, /OSV \/ GHSA · advisory/);
 assert.match(html, /href="\/advisory\/osv\/GHSA-test\?lang=en"/);
 assert.match(html, /&lt;b&gt;source title&lt;\/b&gt;/);
});
