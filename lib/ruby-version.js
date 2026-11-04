'use strict';

// RubyGems version ordering, not SemVer: alphabetic segments precede numeric
// segments, numeric segments use arbitrary precision, and '-' denotes '.pre.'.
// Only nonempty, bounded, literal version strings are accepted; branches,
// constraints and platform suffixes outside Gem::Version's grammar are unknown.
// Reference: https://guides.rubygems.org/patterns/#semantic-versioning
const VERSION = /^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function segments(version) {
  if (typeof version !== 'string' || !version || version.length > 1024 || !VERSION.test(version)) return null;
  const tokens = version.replace(/-/g, '.pre.').match(/[0-9]+|[A-Za-z]+/g)
    .map(token => /^\d+$/.test(token) ? BigInt(token) : token);
  const firstLabel = tokens.findIndex(token => typeof token === 'string');
  const release = tokens.slice(0, firstLabel < 0 ? tokens.length : firstLabel);
  const prerelease = firstLabel < 0 ? [] : tokens.slice(firstLabel);
  // Zero padding is insignificant both before the first prerelease label and
  // at the end. Preserve zeros inside either section: 1.0.1 differs from 1.1.
  while (release.length && release.at(-1) === 0n) release.pop();
  while (prerelease.length && prerelease.at(-1) === 0n) prerelease.pop();
  return [...release, ...prerelease];
}

function compareRubyVersions(a, b) {
  const left = segments(a), right = segments(b);
  if (!left || !right) return null;
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i] ?? 0n, y = right[i] ?? 0n;
    if (x === y) continue;
    if (typeof x !== typeof y) return typeof x === 'string' ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

module.exports = { compareRubyVersions };
