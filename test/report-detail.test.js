'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { planDetail, beyondDetailLimit } = require('../lib/reports/detail');

const system = (name, sourceName = name) => ({ ecosystem: 'system', manager: 'dpkg', artifactTargetId: 'host', name, coordKey: `host:dpkg:${name}`, version: '1.0-1', sourceName, sourceVersion: '1.0-1' });
const match = (dep, n, score = 5) => ({ dep, cve: { id: `CVE-2024-${String(1000 + n)}`, severity: 'MEDIUM', score } });

test('an advisory of a source package is detailed once for all the packages built from it', () => {
	const packages = ['libavcodec61', 'libavformat61', 'libavutil59'].map(name => system(name, 'ffmpeg'));
	const matches = packages.flatMap(dep => [match(dep, 1, 9), match(dep, 2, 4)]).concat([match(system('zlib1g', 'zlib'), 1, 9)]);
	const plan = planDetail(matches);
	assert.equal(plan.detailed.length, 3, 'two ffmpeg advisories and the zlib one');
	const first = plan.detailed.find(m => m.dep.sourceName === 'ffmpeg' && m.cve.id === 'CVE-2024-1001');
	assert.deepEqual(plan.siblings.get(first).map(m => m.dep.name).sort(), packages.map(p => p.name).filter(n => n !== first.dep.name).sort());
	assert.equal(plan.compact.size, 4, 'the two other packages, for each ffmpeg advisory');
	const ffmpeg = plan.groups.find(g => g.dep.sourceName === 'ffmpeg');
	assert.deepEqual([ffmpeg.source, ffmpeg.packages, ffmpeg.detailed, ffmpeg.beyond.length], [true, 3, 2, 0]);
});

test('a group details its highest-priority advisories and counts each further advisory once', () => {
	const kernel = [system('linux-image-6.1', 'linux'), system('linux-headers-6.1', 'linux')];
	const matches = kernel.flatMap(dep => Array.from({ length: 130 }, (_, n) => match(dep, n, 9 - n / 100)));
	const plan = planDetail(matches);
	assert.equal(plan.detailed.length, 100);
	assert.deepEqual(plan.detailed.slice(0, 2).map(m => m.cve.id), ['CVE-2024-1000', 'CVE-2024-1001'], 'highest score first');
	assert.equal(plan.groups[0].beyond.length, 30, 'advisories, not occurrences');
	assert.equal(beyondDetailLimit(matches).size, 160);
	// The same advisory on two unrelated components is detailed on both.
	const npm = name => ({ ecosystem: 'npm', name, version: '1.0.0', coordKey: `npm:${name}@1.0.0` });
	assert.equal(planDetail([match(npm('a'), 1), match(npm('b'), 1)]).detailed.length, 2);
	// Two physical copies of one component (same coordinate, two manifests) keep their own entries.
	const copy = manifest => ({ dep: { ...npm('a'), manifestPath: manifest }, cve: { id: 'CVE-2024-1', severity: 'HIGH', score: 8 } });
	assert.equal(planDetail([copy('site/a/package-lock.json'), copy('site/b/package-lock.json')]).detailed.length, 2);
	// Same package name in two system targets: two groups.
	const other = { ...system('zlib1g', 'zlib'), artifactTargetId: 'image' };
	assert.equal(planDetail([match(system('zlib1g', 'zlib'), 1), match(other, 1)]).detailed.length, 2);
});
