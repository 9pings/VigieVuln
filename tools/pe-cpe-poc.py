#!/usr/bin/env python3
"""Experimental PE metadata -> NVD CPE/CVE research; not a production scanner.

Requires Python 3 and pefile (python -m pip install pefile). Queries disclose the
file's product name and selected CPE to NVD. Never executes the inspected binary.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request

import pefile

BASE = "https://services.nvd.nist.gov/rest/json/"


def get(endpoint, params, key=None):
    req = urllib.request.Request(BASE + endpoint + "?" + urllib.parse.urlencode(params),
                                 headers={"User-Agent": "VigieVuln-PE-research/0.1", **({'apiKey': key} if key else {})})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def metadata(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    pe = pefile.PE(path, fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        strings = []
        for group in getattr(pe, 'FileInfo', []):
            for info in group:
                for table in getattr(info, 'StringTable', []):
                    strings.append({k.decode('utf-8', 'replace'): v.decode('utf-8', 'replace')
                                    for k, v in table.entries.items()})
        return {'path': path, 'sha256': digest.hexdigest(), 'version_strings': strings}
    finally:
        pe.close()


def norm(value):
    return re.sub(r'[^a-z0-9]+', '', value.lower())


def candidates(products, name, vendor):
    # CPE keyword search is only discovery: don't infer an identity from a partial match.
    found = {}
    for row in products:
        cpe = row.get('cpe', {})
        parts = cpe.get('cpeName', '').split(':')
        if len(parts) != 13 or cpe.get('deprecated') or '\\' in cpe['cpeName']:
            continue
        if norm(parts[4]) != norm(name):
            continue
        key = (parts[2], parts[3], parts[4])
        item = found.setdefault(key, {'part': parts[2], 'vendor': parts[3], 'product': parts[4],
                                      'vendor_in_metadata': bool(norm(parts[3]) and norm(parts[3]) in norm(vendor)),
                                      'sample_cpe': cpe['cpeName']})
        item['vendor_in_metadata'] |= bool(norm(parts[3]) and norm(parts[3]) in norm(vendor))
    return sorted(found.values(), key=lambda x: (not x['vendor_in_metadata'], x['vendor'], x['product']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--search', help='Explicit product name to search in the NVD CPE dictionary')
    parser.add_argument('--cpe', help='Explicit CPE 2.3 including version; query NVD for candidate CVEs')
    parser.add_argument('--api-key', help='Optional NVD API key')
    args = parser.parse_args()
    out = metadata(args.file)
    out['notice'] = 'Experimental: metadata and CPE candidates are unverified; NVD results require applicability and build review.'
    if args.search:
        data = get('cpes/2.0', {'keywordSearch': args.search, 'resultsPerPage': 2000}, args.api_key)
        vendor = ' '.join(x.get('CompanyName', '') for x in out['version_strings'])
        out['cpe_search'] = {'query': args.search, 'total_results': data['totalResults'],
                             'truncated': data['totalResults'] > len(data.get('products', [])),
                             'candidates': candidates(data.get('products', []), args.search, vendor)}
    if args.cpe:
        if not re.fullmatch(r'cpe:2\.3:(?:[^:]*:){10}[^:]*', args.cpe):
            parser.error('--cpe must be a complete CPE 2.3 name')
        if args.search:
            time.sleep(6 if not args.api_key else 1)
        data = get('cves/2.0', {'cpeName': args.cpe, 'resultsPerPage': 2000}, args.api_key)
        cpe_version = args.cpe.split(':')[5]
        product_versions = sorted({x.get('ProductVersion') for x in out['version_strings'] if x.get('ProductVersion')})
        out['cve_search'] = {'cpe': args.cpe, 'total_results': data['totalResults'],
                             'cpe_version': cpe_version, 'metadata_product_versions': product_versions,
                             'version_agrees_with_metadata': cpe_version in product_versions if product_versions else None,
                             'coverage_notice': 'No results do not prove safety: NVD may lack CPE applicability, and product/build context may differ.',
                             'truncated': data['totalResults'] > len(data.get('vulnerabilities', [])),
                             'candidate_cves': [{'id': v['cve']['id'], 'configurations': v['cve'].get('configurations', [])}
                                                for v in data.get('vulnerabilities', [])]}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, pefile.PEFormatError) as exc:
        print(f'PE research failed: {exc}', file=sys.stderr)
        sys.exit(1)
