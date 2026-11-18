import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from osv_scan import findings, scan_osv_batch

class OSVTests(unittest.TestCase):
    def test_ids_deduplicate_per_package_version_not_across_versions(self):
        def entry(version):
            return {'package': {'name': 'crate', 'version': version}, 'vulnerabilities': [{'id': 'RUSTSEC-1'}, {'id': 'RUSTSEC-1'}]}
        self.assertEqual(len(findings({'results': [{'packages': [entry('1'), entry('2')]}]})), 2)

    def test_batch_keeps_findings_with_each_source_and_identifies_clean_sboms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            affected = root / 'static/a/image.spdx.json'
            clean = root / 'static/b/image.spdx.json'
            omitted = root / 'static/c/image.spdx.json'
            missing = root / 'static/d/image.spdx.json'
            for sbom in (affected, clean, omitted):
                sbom.parent.mkdir(parents=True)
                sbom.touch()
            pkg = {'package': {'name': 'crate', 'version': '1'}}
            vulnerable = {**pkg, 'vulnerabilities': [{'id': 'RUSTSEC-1'}]}
            affected_entry = {'source': {'type': 'sbom', 'path': str(affected)}, 'packages': [pkg, vulnerable]}
            clean_entry = {'source': {'type': 'sbom', 'path': str(clean)}, 'packages': [pkg]}
            raw = {'results': [clean_entry, affected_entry], 'experimental_config': None}
            response = SimpleNamespace(returncode=1, stdout=json.dumps(raw), stderr='')
            with patch('osv_scan.subprocess.run', return_value=response) as run:
                result = scan_osv_batch([affected, clean, omitted, missing], root, 'osv-scanner')
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], [
                'osv-scanner', 'scan', 'source', '--offline', '--all-packages',
                '--verbosity', 'error', '--format', 'json',
                '-L', str(affected), '-L', str(clean), '-L', str(omitted),
            ])
            self.assertEqual(result[affected]['findings'], [{'package': 'crate', 'version': '1', 'id': 'RUSTSEC-1'}])
            self.assertEqual(result[clean]['findings'], [])
            for sbom in (omitted, missing):
                self.assertEqual(result[sbom]['status'], 'unavailable')
                self.assertNotIn('findings', result[sbom])
            affected_report = json.loads((root / 'static' / result[affected]['report']).read_text())
            self.assertEqual(affected_report['results'], [{**affected_entry, 'packages': [vulnerable]}])
            clean_report = json.loads((root / 'static' / result[clean]['report']).read_text())
            self.assertEqual(clean_report, {'results': [], 'experimental_config': None})

    def test_failed_command_and_invalid_output_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sbom = root / 'image.spdx.json'
            sbom.touch()
            for code, output in [(2, '{}'), (0, 'invalid'), (0, '{}')]:
                response = SimpleNamespace(returncode=code, stdout=output, stderr='error')
                with self.subTest(code=code, output=output), patch('osv_scan.subprocess.run', return_value=response):
                    result = scan_osv_batch([sbom], root, 'osv-scanner')[sbom]
                    self.assertEqual(result['status'], 'unavailable')
                    self.assertNotIn('findings', result)

    def test_batch_isolates_an_input_that_aborts_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good, bad = (root / 'static' / name for name in ('good.spdx.json', 'bad.spdx.json'))
            good.parent.mkdir()
            good.touch()
            bad.touch()
            failed = SimpleNamespace(returncode=127, stdout='', stderr='extraction failed on specified lockfile')
            good_entry = {'source': {'type': 'sbom', 'path': str(good)},
                          'packages': [{'package': {'name': 'crate', 'version': '1'}}]}
            succeeded = SimpleNamespace(returncode=0, stdout=json.dumps({'results': [good_entry]}), stderr='')
            with patch('osv_scan.subprocess.run', side_effect=[failed, succeeded, failed]) as run:
                result = scan_osv_batch([good, bad], root, 'osv-scanner')
            self.assertEqual(run.call_count, 3)
            self.assertEqual(result[good]['status'], 'scanned')
            self.assertEqual(result[bad]['status'], 'unavailable')

    def test_ecosystem_errors_do_not_become_clean_results_in_mixed_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good, bad = (root / 'static' / name for name in ('good.spdx.json', 'bad.spdx.json'))
            good.parent.mkdir()
            good.touch()
            bad.touch()
            def entry(path, ecosystem):
                return {'source': {'type': 'sbom', 'path': str(path)}, 'packages': [
                    {'package': {'name': 'example', 'version': '1', 'ecosystem': ecosystem}}]}
            raw = {'results': [entry(good, 'Debian:12'), entry(bad, 'GitHub Actions')]}
            for code in (1, 127):
                response = SimpleNamespace(returncode=code, stdout=json.dumps(raw), stderr=
                    'Error during extraction: could not load db for GitHub Actions ecosystem: unavailable')
                with self.subTest(code=code), patch('osv_scan.subprocess.run', return_value=response):
                    result = scan_osv_batch([good, bad], root, 'osv-scanner')
                self.assertEqual(result[good]['status'], 'scanned')
                self.assertEqual(result[bad]['status'], 'unavailable')
                self.assertNotIn('findings', result[bad])
            response.stderr = 'Unexpected extraction failure'
            with patch('osv_scan.subprocess.run', return_value=response):
                result = scan_osv_batch([good, bad], root, 'osv-scanner')
            self.assertTrue(all(r['status'] == 'unavailable' for r in result.values()))

    def test_failed_refresh_prevents_scanning_stale_database(self):
        with patch('osv_scan.subprocess.run') as run:
            sbom = Path('unused')
            result = scan_osv_batch([sbom], Path('.'), 'osv-scanner', {'error': 'refresh failed'})[sbom]
        self.assertEqual(result['status'],'unavailable')
        self.assertNotIn('findings',result)
        run.assert_not_called()

    def test_database_refresh_records_both_archives_and_rejects_bad_downloads(self):
        import io
        import zipfile
        from osv_scan import refresh_database
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('example.json','{}')
        from unittest.mock import Mock
        response=Mock(content=archive.getvalue(),headers={'Last-Modified':'today'})
        with tempfile.TemporaryDirectory() as directory:
            with patch('osv_scan.requests.get',return_value=response) as get:
                result=refresh_database(Path(directory))
            self.assertEqual(get.call_count,2)
            self.assertEqual(set(result['databases']),{'crates.io','Debian'})
            self.assertNotIn('error',result)
            saved=Path(directory)/'.cache/osv-local-db/osv-scalibr/crates.io/all.zip'
            previous=saved.read_bytes()
            response.content=b'invalid archive'
            with patch('osv_scan.requests.get',return_value=response):
                failed=refresh_database(Path(directory))
            self.assertIn('error',failed)
            self.assertEqual(saved.read_bytes(),previous)
