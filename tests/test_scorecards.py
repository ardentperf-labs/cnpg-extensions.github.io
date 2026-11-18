import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('scorecards', Path(__file__).resolve().parents[1]/'scripts/scan-scorecards.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ScorecardTests(unittest.TestCase):
    def test_preserves_scores_and_details(self):
        report = {'date': '2026-11-18', 'repo': {'commit': 'abc'},
                  'checks': [{'name': 'Maintained', 'score': 0, 'details': ['quiet']},
                             {'name': 'Branch-Protection', 'score': -1}]}
        raw = json.dumps(report)
        with tempfile.TemporaryDirectory() as tmp, patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw, '')):
            result = m.scan('https://github.com/example/repo', 'scorecard', Path(tmp), 10)
            self.assertEqual(result['status'], 'available')
            self.assertEqual(result['inconclusiveChecks'], 1)
            self.assertEqual((Path(tmp)/result['report']).read_text(), raw)

    def test_failure_does_not_become_zero(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'private diagnostics')):
            result = m.scan('https://github.com/example/repo', 'scorecard', Path(tmp), 10)
            self.assertEqual(result['status'], 'unavailable')
            self.assertNotIn('score', result)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_unsupported_host_is_not_executed(self):
        with patch.object(m.subprocess, 'run') as run:
            self.assertEqual(m.scan('https://salsa.debian.org/a/b', 'scorecard', Path('.'), 10)['status'], 'unsupported')
            run.assert_not_called()

    def test_catalog_deduplicates_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'catalog-test.yaml').write_text('spec:\n  images:\n  - extensions: [{name: pgvector}, {name: http}]\n  - extensions: [{name: pgvector}]\n')
            self.assertEqual(m.catalog_names(tmp), {'pgvector', 'http'})
