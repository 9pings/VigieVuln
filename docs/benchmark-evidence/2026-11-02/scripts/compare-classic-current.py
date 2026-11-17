"""Compare exact Maven coordinates/versions and explicitly declared advisory IDs.

Usage: script.py OUTPUT_DIR PROJECT VV_REPORT DESTINATION
Inputs are the rerun reports from 2026-11-02. OSV queried the live API;
Trivy/Grype reused the pinned database snapshots. This comparison script does
not execute scanners or claim their package inventories are identical.
"""
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import unquote

base, project, vv_file, destination = sys.argv[1:]
base = Path(base)
names = {"vigievuln": vv_file}
names.update({name: f"{project}-{name}{'-online' if project == 'dubbo' else ''}.json"
              for name in ["osv", "trivy", "grype"]})
raw = {name: json.loads((base / file).read_text()) for name, file in names.items()}
rows = {name: [] for name in names}
unidentified = {name: 0 for name in names}

def add(scanner, package, version, ids):
    ids = sorted({i for i in ids if isinstance(i, str) and i.startswith(('CVE-', 'GHSA-', 'SNYK-', 'OSV-'))})
    if not package or not version or not ids:
        unidentified[scanner] += 1
        return
    if project == 'dubbo' and package.startswith('org.apache.dubbo:'):
        return
    rows[scanner].append({'package': package, 'version': str(version), 'ids': ids})

for item in raw['vigievuln'].get('cve', []):
    dep = item.get('dep') or {}
    if dep.get('ecosystem') in ['maven', 'gradle'] and not item.get('suppressed') and not item.get('cpeFiltered'):
        add('vigievuln', dep.get('coord'), dep.get('version'), [item.get('id')] + (item.get('aliases') or []))
for result in raw['osv'].get('results', []):
    for item in result.get('packages', []):
        package = item.get('package') or {}
        if package.get('ecosystem') == 'Maven':
            for vuln in item.get('vulnerabilities', []):
                add('osv', package.get('name'), package.get('version'), [vuln.get('id')] + (vuln.get('aliases') or []))
for result in raw['trivy'].get('Results', []):
    for vuln in result.get('Vulnerabilities') or []:
        add('trivy', vuln.get('PkgName'), vuln.get('InstalledVersion'), [vuln.get('VulnerabilityID')] + (vuln.get('VendorIDs') or []))
for item in raw['grype'].get('matches', []):
    artifact = item.get('artifact') or {}
    meta = artifact.get('metadata') or {}
    package = None
    if meta.get('pomGroupID'):
        package = meta['pomGroupID'] + ':' + (meta.get('pomArtifactID') or artifact['name'])
    elif artifact.get('purl', '').startswith('pkg:maven/'):
        parts = artifact['purl'][len('pkg:maven/'):].split('@')[0].split('/')
        if len(parts) == 2:
            package = ':'.join(map(unquote, parts))
    add('grype', package, artifact.get('version'), [item['vulnerability'].get('id')] + [v.get('id') for v in item.get('relatedVulnerabilities', [])])

def deduplicate(records):
    # Repeated occurrences with the same explicit identity are one observation.
    grouped = {}
    for r in records:
        identity = sorted(r['ids'], key=lambda i: (not i.startswith('CVE-'), not i.startswith('GHSA-'), i))[0]
        key = (r['package'], r['version'], identity)
        previous = grouped.setdefault(key, {**r, 'ids': []})
        previous['ids'] = sorted(set(previous['ids']) | set(r['ids']))
    return list(grouped.values())

def matches(a, b):
    return a['package'] == b['package'] and a['version'] == b['version'] and bool(set(a['ids']) & set(b['ids']))

rows = {name: deduplicate(values) for name, values in rows.items()}
result = {'project': project, 'unit': 'Exact case-sensitive Maven coordinate/version and declared common advisory ID',
          'comparisonInputs': 'Scanners rerun on 2026-11-02; OSV live API, Trivy/Grype pinned databases; see inventories and warnings in BENCHMARK.md',
          'vigievuln': len(rows['vigievuln']), 'scanners': {}, 'unidentifiedObservations': unidentified,
          'artifacts': {name: {'file': file, 'sha256': hashlib.sha256((base / file).read_bytes()).hexdigest()} for name, file in names.items()}}
for name in ['osv', 'trivy', 'grype']:
    missing = [r for r in rows[name] if not any(matches(r, v) for v in rows['vigievuln'])]
    result['scanners'][name] = {'observations': len(rows[name]), 'missingFromVigievuln': len(missing), 'missing': missing}
if project == 'dubbo':
    diagnosis = json.loads((Path(__file__).parent.parent / 'remaining-62-diagnosis.json').read_text())
    recovered = {'matcher_corrected', 'corrected_by_bound_nvd_range'}
    remaining = [r for r in diagnosis['rows'] if r['category'] not in recovered and not any(matches(r, v) for v in rows['vigievuln'])]
    result['remainingPreviouslyConfirmed'] = [{**{k: r[k] for k in ['package', 'version', 'snykId', 'ids', 'category']},
                              'alsoReportedBy': [name for name in ['osv', 'trivy', 'grype'] if any(matches(r, other) for other in rows[name])]}
                             for r in remaining]
Path(destination).write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k in ['project', 'vigievuln', 'scanners', 'unidentifiedObservations']}, indent=2))
