#!/usr/bin/env python3
"""Recompute the exclusive Dubbo Snyk adjudication from checked-in reviews.
No network, credentials, private scanner reports or product mutation.
Prints JSON to stdout; redirect it to the desired evidence file.
"""
import collections
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    'dubbo-snyk-primary-individual.json',
    'dubbo-snyk-version-adjudication.json',
    'dubbo-snyk-other-coordinates.json',
]
MAP = {
    'bug_vigievuln_projection_benchmark': 'corrected_verified',
    'confirmed_missing_advisory': 'confirmed_missing_package_advisory',
    'omission_corroboree_cna_code_version_exacte': 'confirmed_missing_package_advisory',
    'source_editeur_maven_non_integree': 'confirmed_missing_package_advisory',
    'omission_confirmee_code_editeur_type_custom': 'confirmed_missing_package_advisory',
    'omission_corroboree_avis_code_sans_cve': 'confirmed_missing_package_advisory',
    'affected artifact and version supported by CNA and upstream code': 'confirmed_missing_package_advisory',
    'false_alert_for_version': 'confirmed_snyk_error',
    'hors_module_et_plage_selon_cna': 'confirmed_snyk_error',
    'fausse_alerte_selon_avis_editeur': 'confirmed_snyk_error',
    'version not affected according to CNA': 'confirmed_snyk_error',
    'vulnerable feature absent in tested artifact version': 'confirmed_snyk_error',
    'already_reported_primary_equivalence': 'already_reported_proven_equivalence',
    'indeterminate': 'indeterminate',
    'indetermine': 'indeterminate',
    'source_non_integree': 'indeterminate',
    'desaccord_sources_primaires': 'indeterminate',
    'limitation_matcher_type_custom': 'indeterminate',
    'source_editeur_non_integree_version_indeterminee': 'indeterminate',
    'indeterminate_disputed': 'indeterminate',
    'indeterminate_source_disagreement': 'indeterminate',
}

def key(row):
    return row['package'], row['version'], row['snykId']

def read(name):
    return json.loads((ROOT / name).read_text())

def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()

override_name = 'dubbo-snyk-consolidation-overrides.json'
overrides = {key(row): row for row in read(override_name)['overrides']}
rows = []
groups = []
used_overrides = set()
for filename in FILES:
    source = read(filename)
    local = []
    for case in source['cases']:
        verdict = case['verdict']
        if verdict not in MAP:
            raise ValueError('Unmapped verdict: ' + verdict)
        result = MAP[verdict]
        override = overrides.get(key(case))
        if override:
            assert verdict == override['originalVerdict'], (key(case), verdict)
            result = override['finalCategory']
            used_overrides.add(key(case))
        if result == 'corrected_verified':
            assert case['onlineScan']['result'] == 'same_identity_reported'
            assert case['onlineScan']['findings']
        row = {'package': case['package'], 'version': case['version'], 'snykId': case['snykId'],
               'group': filename, 'sourceVerdict': verdict, 'category': result}
        if override:
            row['overrideEvidence'] = override
        local.append(row)
        rows.append(row)
    groups.append({'file': filename, 'sha256': digest(filename), 'occurrences': len(local),
                   'distinctSnykIds': len({r['snykId'] for r in local}),
                   'counts': dict(collections.Counter(r['category'] for r in local))})
assert used_overrides == set(overrides)
assert len(rows) == len({key(r) for r in rows}) == 167
assert {key(r) for r in rows} == {key(r) for r in read('dubbo-snyk-adjudication.json')['cases']}
by_id = collections.defaultdict(set)
for row in rows:
    by_id[row['snykId']].add(row['category'])
result = {'schema': 1, 'date': '2026-11-02',
          'unit': 'One unique package/version/Snyk-ID occurrence; not one independent vulnerability or code bug.',
          'occurrences': len(rows), 'distinctSnykIds': len(by_id),
          'counts': dict(collections.Counter(r['category'] for r in rows)), 'groups': groups,
          'overridesSha256': digest(override_name),
          'snykIdsWithDifferentVersionVerdicts': {k: sorted(v) for k, v in by_id.items() if len(v) > 1},
          'limits': [
              'The 12 recovered observations share a projection/index-reconstruction defect; they are not 12 independent bugs.',
              'The 68 missing observations are exact-package/version coverage gaps. A matching CVE can already be reported for a different package or version.',
              'The other-coordinate group documents 12 still-missing package attributions whose CVE is already elsewhere; this is not an exhaustive global count across all 68 gaps.',
              'Snyk database completeness is not a separate exclusive outcome proved by these reviews. Source omissions, source representation and conservative matcher limitations overlap.',
              'Confirmed Snyk errors are scoped to the named advisory/product/version; no claim of application safety follows.',
              'Distinct Snyk-ID category counts need not sum to 141: one ID spans confirmed-missing and indeterminate versions.',
          ], 'cases': rows}
print(json.dumps(result, ensure_ascii=False, indent=2))
