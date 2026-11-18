from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import generate
from evidence_shards import merge_shards, shard_path


COMMITS = {'artifacts': 'catalog-commit', 'source': 'source-commit', 'upstream': 'upstream-commit'}
GRYPE = {'schemaVersion': 'v6.1.10', 'from': 'db.tar.zst?checksum=sha256%3Aabc', 'built': '2026-11-18T00:00:00Z',
         'valid': True, 'path': '/tmp/one/vulnerability.db'}
OSV = {'path': '/tmp/one', 'refreshedAt': '2026-11-18T00:01:00Z',
       'databases': {'crates.io': {'sha256': 'a' * 64}, 'Debian': {'sha256': 'b' * 64}}}


def job(name):
    return {'name': name, 'pg': 18, 'distro': 'trixie', 'reference': f'ghcr.io/org/{name}:18@sha256:abc',
            'catalog': 'catalog-trixie.yaml'}


class MergeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.static = self.root / 'static'
        self.jobs = [job(name) for name in ('one', 'two', 'three', 'four')]
        self.shards = [
            {'shardIndex': index, 'shardCount': 2, 'commits': COMMITS, 'database': deepcopy(GRYPE),
             'osvDatabase': deepcopy(OSV), 'images': [{**item, 'platforms': []} for item in self.jobs[index::2]]}
            for index in range(2)
        ]
        self.write_shards()

    def write_shards(self):
        for shard in self.shards:
            shard_path(self.root, shard['shardIndex']).write_text(json.dumps(shard))

    def merge(self):
        return merge_shards(self.root, self.jobs, COMMITS, self.static)

    def test_complete_partition_matches_catalog_order_and_ignores_local_database_paths_and_times(self):
        shard = self.shards[1]
        shard['images'].reverse()
        shard['database']['path'] = '/tmp/two/vulnerability.db'
        shard['osvDatabase'].update(path='/tmp/two', refreshedAt='2026-11-18T00:02:00Z')
        self.write_shards()
        images, database = self.merge()
        self.assertEqual([image['name'] for image in images], ['one', 'two', 'three', 'four'])
        self.assertEqual(database, GRYPE)

    def test_missing_shard_is_rejected(self):
        shard_path(self.root, 1).unlink()
        with self.assertRaisesRegex(RuntimeError, 'shard set is incomplete'):
            self.merge()

    def test_duplicate_shard_index_is_rejected(self):
        duplicate = {**self.shards[1], 'shardIndex': 0}
        shard_path(self.root, 1).write_text(json.dumps(duplicate))
        with self.assertRaisesRegex(RuntimeError, 'shard index is duplicate'):
            self.merge()

    def test_duplicate_image_within_shard_is_rejected(self):
        self.shards[0]['images'].append(self.shards[0]['images'][0])
        self.write_shards()
        with self.assertRaisesRegex(RuntimeError, 'catalog partition'):
            self.merge()

    def test_covered_catalog_with_images_in_wrong_partitions_is_rejected(self):
        self.shards[0]['images'], self.shards[1]['images'] = self.shards[1]['images'], self.shards[0]['images']
        self.write_shards()
        with self.assertRaisesRegex(RuntimeError, 'catalog partition'):
            self.merge()

    def test_image_reference_drift_and_extraneous_images_are_rejected(self):
        original = self.shards[0]['images']
        changed = [{**original[0], 'reference': 'ghcr.io/org/one:18@sha256:changed'}, original[1]]
        extras = [*original, {**job('extra'), 'platforms': []}]
        for images in (changed, extras, original[:1]):
            with self.subTest(images=images):
                self.shards[0]['images'] = images
                self.write_shards()
                with self.assertRaisesRegex(RuntimeError, 'catalog partition'):
                    self.merge()

    def test_drifted_source_commit_is_rejected(self):
        self.shards[1]['commits'] = {**COMMITS, 'source': 'different-commit'}
        self.write_shards()
        with self.assertRaisesRegex(RuntimeError, 'source commits differ'):
            self.merge()

    def test_different_grype_or_osv_database_is_rejected(self):
        different_grype = {**GRYPE, 'from': 'db.tar.zst?checksum=sha256%3Adef'}
        different_osv = deepcopy(OSV)
        different_osv['databases']['crates.io']['sha256'] = 'c' * 64
        for grype, osv in ((different_grype, OSV), (GRYPE, different_osv)):
            with self.subTest(grype=grype, osv=osv):
                self.shards[1].update(database=grype, osvDatabase=osv)
                self.write_shards()
                with self.assertRaisesRegex(RuntimeError, 'advisory databases differ'):
                    self.merge()

    def test_incomplete_database_refresh_is_rejected(self):
        self.shards[1]['osvDatabase'] = {'error': 'network error'}
        self.write_shards()
        with self.assertRaisesRegex(RuntimeError, 'verified OSV database'):
            self.merge()

    def test_scanned_report_artifacts_must_match_their_platform(self):
        sbom = Path('reports/one/trixie-pg18-amd64.spdx.json')
        grype = sbom.with_suffix('.grype.json')
        platform = {'architecture': 'amd64', 'status': 'available', 'sbom': sbom.as_posix(),
                    'containerNotices': {'status': 'unavailable'},
                    'scan': {'status': 'scanned', 'report': grype.as_posix()},
                    'osvScan': {'status': 'unavailable'}}
        self.shards[0]['images'][0]['platforms'] = [platform]
        self.write_shards()
        (self.static / sbom).parent.mkdir(parents=True)
        (self.static / sbom).write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'report is missing or mismatched.*grype'):
            self.merge()
        (self.static / grype).write_text('{}')
        images, _ = self.merge()
        self.assertEqual(images[0]['platforms'], [platform])
        del platform['containerNotices']
        self.write_shards()
        with self.assertRaisesRegex(RuntimeError, 'fresh container notice'):
            self.merge()


class EvidenceOnlyTests(unittest.TestCase):
    def test_evidence_only_scans_its_partition_refreshes_notices_and_stops_before_rendering(self):
        images = [job(name) for name in ('one', 'two', 'three', 'four')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / '.cache'
            catalog = cache / 'artifacts/image-catalogs-extensions/catalog-trixie.yaml'
            catalog.parent.mkdir(parents=True)
            catalog.write_text(yaml.safe_dump({
                'metadata': {'labels': {'images.cnpg.io/os': 'trixie'}},
                'spec': {'images': [{'major': 18, 'extensions': [
                    {'name': item['name'], 'image': {'reference': item['reference']}} for item in images
                ]}]},
            }))
            scanned = []

            def inspect(item, grype, database, refresh):
                scanned.append((item['name'], refresh))
                return {**item, 'status': 'available', 'platforms': [
                    {'status': 'unavailable', 'digest': item['reference'].split('@')[1], 'architecture': 'amd64'}
                ]}

            argv = ['generate.py', '--scan', '--refresh', '--evidence-only', '--shard-index', '1',
                    '--shard-count', '2', '--refresh-extension', 'two']
            with patch.object(sys, 'argv', argv), patch.multiple(generate, ROOT=root, CACHE=cache), \
                 patch.object(generate, 'checkout', side_effect=lambda name, refresh: COMMITS[name]), \
                 patch.object(generate.shutil, 'which', side_effect=lambda name: name), \
                 patch.object(generate.subprocess, 'run', return_value=Mock(returncode=0)), \
                 patch.object(generate, 'run', return_value=json.dumps(GRYPE)), \
                 patch.object(generate, 'refresh_database', return_value=OSV), \
                 patch.object(generate, 'scan_osv_batch', return_value={}) as scan_osv, \
                 patch.object(generate, 'inspect_image', side_effect=inspect), \
                 patch.object(generate, 'container_notices', return_value={'status': 'available'}) as notices:
                generate.main()
            self.assertCountEqual(scanned, [('two', True), ('four', False)])
            self.assertEqual(notices.call_count, 2)
            scan_osv.assert_called_once_with([], root, 'osv-scanner', OSV)
            shard = json.loads(shard_path(cache, 1).read_text())
            self.assertEqual((shard['shardIndex'], shard['shardCount']), (1, 2))
            self.assertEqual(shard['commits'], COMMITS)
            self.assertCountEqual([image['name'] for image in shard['images']], ['two', 'four'])
            self.assertFalse((cache / 'inspected.json').exists())
            self.assertFalse((root / 'content').exists())

    def test_incompatible_options_fail_before_checkout(self):
        for args in (['--merge-evidence', '--scan'], ['--merge-evidence', '--rebuild-cache'],
                     ['--evidence-only', '--scan', '--shard-index', '4', '--shard-count', '4'],
                     ['--shard-index', '0'], ['--evidence-only', '--shard-index', '0', '--shard-count', '4']):
            with self.subTest(args=args), patch.object(sys, 'argv', ['generate.py', *args]), \
                 patch.object(generate, 'checkout') as checkout, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    generate.main()
                checkout.assert_not_called()
