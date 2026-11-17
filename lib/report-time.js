'use strict';

const esc = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// A calendar date is not an instant. Never shift it across days when changing
// time zones; likewise, do not invent a zone for a timestamp without an offset.
function renderTime(value, locale = 'en') {
  const epoch = typeof value === 'number' && Number.isFinite(value) ? new Date(value) : null;
  const raw = epoch && Number.isFinite(epoch.getTime()) ? epoch.toISOString() : String(value ?? '');
  const match = /^(\d{4}-\d{2}-\d{2})(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/.exec(raw);
  if (!match) return esc(raw);
  const day = new Date(match[1] + 'T00:00:00Z');
  if (!Number.isFinite(day.getTime()) || day.toISOString().slice(0, 10) !== match[1]) return esc(raw);
  const dateOnly = raw === match[1];
  const clock = /T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(raw);
  if (clock && (+clock[1] > 23 || +clock[2] > 59 || +(clock[3] || 0) > 59)) return esc(raw);
  if (dateOnly) return `<time datetime="${raw}">${raw}</time>`;
  if (!dateOnly && !match[2]) {
    if (!Number.isFinite(Date.parse(raw + 'Z'))) return esc(raw);
    return `<time datetime="${esc(raw)}">${esc(raw.replace('T', ' '))}</time>`;
  }
  const date = dateOnly ? day : new Date(raw);
  if (!Number.isFinite(date.getTime())) return esc(raw);
  const options = { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' };
  if (!dateOnly) Object.assign(options, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
  return `<time datetime="${esc(raw)}">${esc(new Intl.DateTimeFormat(locale, options).format(date))}</time>`;
}

// Serialized into standalone HTML, and exercised with actual Intl time zones.
function localizeReportTimes(root = document) {
  const locale = root.documentElement.lang || undefined;
  root.querySelectorAll('time[datetime]').forEach(function (el) {
    const raw = el.getAttribute('datetime');
    const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(raw);
    if (!dateOnly && !/(?:Z|[+-]\d{2}:\d{2})$/.test(raw)) return;
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return;
    const options = { year: 'numeric', month: '2-digit', day: '2-digit' };
    if (dateOnly) options.timeZone = 'UTC';
    else Object.assign(options, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
    el.textContent = new Intl.DateTimeFormat(locale, options).format(date);
  });
}

module.exports = { renderTime, localizeReportTimes };
