import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pe_cpe_poc', pathlib.Path(__file__).with_name('pe-cpe-poc.py'))
poc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poc)


class CorrelationTests(unittest.TestCase):
    def test_distinct_vendors_are_not_silently_selected(self):
        products = [{'cpe': {'cpeName': f'cpe:2.3:a:{vendor}:curl:8.21.0:*:*:*:*:*:*:*'}}
                    for vendor in ('haxx', 'curl_project')]
        self.assertEqual({c['vendor'] for c in poc.candidates(products, 'curl', 'curl, https://curl.se/')},
                         {'haxx', 'curl_project'})

    def test_manual_cpe_version_mismatch_and_empty_coverage_are_visible(self):
        argv = ['pe-cpe-poc.py', 'example.exe', '--cpe', 'cpe:2.3:a:haxx:curl:8.22.0:*:*:*:*:*:*:*']
        fake_metadata = {'version_strings': [{'ProductVersion': '8.21.0'}]}
        fake_response = {'totalResults': 0, 'vulnerabilities': []}
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(poc, 'metadata', return_value=fake_metadata), \
             patch.object(poc, 'get', return_value=fake_response), contextlib.redirect_stdout(output):
            poc.main()
        result = json.loads(output.getvalue())['cve_search']
        self.assertFalse(result['version_agrees_with_metadata'])
        self.assertIn('do not prove safety', result['coverage_notice'])
        self.assertEqual(result['candidate_cves'], [])


if __name__ == '__main__':
    unittest.main()
