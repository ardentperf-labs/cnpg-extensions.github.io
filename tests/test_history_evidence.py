import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import call, patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import history_evidence as evidence


COMMITS = {name: name + '-commit' for name in evidence.REPOS}
HISTORY = {'some-extension': {'fetchedAt': '2026-11-18T00:00:00Z', 'builds': []}}


class HistoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.marker = self.root / '.cache/history-commits.json'
        self.destination = self.root / 'data/version_history.json'

    def write_catalog(self, filename, names):
        directory = self.root / '.cache/artifacts/image-catalogs-extensions'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / filename).write_text(yaml.safe_dump({'spec': {'images': [{'extensions': [
            {'name': name, 'image': {'reference': f'ghcr.io/org/{name}:{filename}@sha256:abc'}}
            for name in names
        ]}]}}))

    def test_capture_groups_variants_and_writes_source_commits_after_history(self):
        self.write_catalog('catalog-a.yaml', ['some-extension'])
        self.write_catalog('catalog-b.yaml', ['another', 'some-extension'])

        def retrieve(entries, refresh_extension):
            self.assertFalse(self.marker.exists())
            self.assertEqual(refresh_extension, 'some-extension')
            self.assertEqual([entry['name'] for entry in entries], ['another', 'some-extension'])
            self.assertEqual(entries[1]['variants'], [
                {'reference': 'ghcr.io/org/some-extension:catalog-a.yaml@sha256:abc'},
                {'reference': 'ghcr.io/org/some-extension:catalog-b.yaml@sha256:abc'},
            ])

        with patch.object(evidence, 'checkout', side_effect=lambda name, refresh: COMMITS[name]) as checkout, \
             patch.object(evidence, 'generate_history', side_effect=retrieve):
            evidence.capture(self.root, refresh_extension='some-extension')
        self.assertEqual(checkout.call_args_list, [call(name, refresh=True) for name in evidence.REPOS])
        self.assertEqual(json.loads(self.marker.read_text()), COMMITS)

    def test_capture_rejects_unknown_selection_and_unsafe_names(self):
        for names, message in ((['some-extension'], 'Unknown catalog extension'), (['../escape'], 'Unsafe extension name')):
            with self.subTest(names=names):
                self.write_catalog('catalog-a.yaml', names)
                with patch.object(evidence, 'checkout'), patch.object(evidence, 'generate_history') as generate:
                    with self.assertRaisesRegex(ValueError, message):
                        evidence.capture(self.root, refresh_extension='wrong')
                generate.assert_not_called()
                self.assertFalse(self.marker.exists())

    def test_capture_requires_nonempty_catalog(self):
        self.write_catalog('catalog-a.yaml', [])
        with patch.object(evidence, 'checkout'), patch.object(evidence, 'generate_history') as generate:
            with self.assertRaisesRegex(RuntimeError, 'Catalog contains no extensions'):
                evidence.capture(self.root)
        generate.assert_not_called()

    def test_capture_failure_removes_stale_success_marker(self):
        self.write_catalog('catalog-a.yaml', ['some-extension'])
        self.marker.write_text(json.dumps(COMMITS))
        with patch.object(evidence, 'checkout'), patch.object(evidence, 'generate_history', side_effect=RuntimeError('offline')):
            with self.assertRaisesRegex(RuntimeError, 'offline'):
                evidence.capture(self.root)
        self.assertFalse(self.marker.exists())

    def test_verify_requires_matching_commits_names_and_valid_data_without_rewriting(self):
        self.marker.parent.mkdir()
        self.marker.write_text(json.dumps(COMMITS))
        self.destination.parent.mkdir()
        self.destination.write_text(json.dumps(HISTORY, indent=2))
        original = self.destination.read_text()
        entries = [{'name': 'some-extension'}]
        evidence.verify(self.root, entries, COMMITS)
        with self.assertRaisesRegex(RuntimeError, 'source commits differ'):
            evidence.verify(self.root, entries, {**COMMITS, 'artifacts': 'different'})
        for wrong_entries in ([], [{'name': 'other'}], entries + [{'name': 'other'}]):
            with self.subTest(entries=wrong_entries):
                with self.assertRaisesRegex(RuntimeError, 'extension names do not match'):
                    evidence.verify(self.root, wrong_entries, COMMITS)
        self.assertEqual(self.destination.read_text(), original)

        self.destination.write_text('{"some-extension":{"fetchedAt":"bad timestamp","builds":[]}}')
        with self.assertRaises(ValueError):
            evidence.verify(self.root, entries, COMMITS)
