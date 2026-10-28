#!/usr/bin/env node
// Extract exactly the tagged release; fail closed rather than publishing old history.
const fs = require('node:fs');

function releaseNotes(changelog, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid release version');
  const lines = changelog.replace(/\r\n/g, '\n').split('\n');
  const heading = new RegExp(`^##\\s+\\[${version.replace(/\./g, '\\.')}\\](?:\\s|$)`);
  const matches = lines.flatMap((line, i) => heading.test(line) ? [i] : []);
  if (matches.length !== 1) throw new Error('Expected exactly one changelog section for the release');
  const start = matches[0];
  let end = start + 1;
  while (end < lines.length && !/^#{1,2}\s/.test(lines[end])) end++;
  const notes = lines.slice(start + 1, end).join('\n').trim();
  if (!notes) throw new Error('Release changelog section is empty');
  return `${notes}\n`;
}

if (require.main === module) {
  try {
    const [, , version, source, output] = process.argv;
    if (!version || !source || !output) throw new Error('Usage: release-notes.js <version> <changelog> <output>');
    fs.writeFileSync(output, releaseNotes(fs.readFileSync(source, 'utf8'), version));
  } catch (err) { console.error(err.message); process.exitCode = 1; }
}
module.exports = { releaseNotes };
